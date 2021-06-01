/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "libarp/util/defines.h"
#include "libarp/pack/pack.h"
#include "internal/defines/file.h"
#include "internal/defines/misc.h"
#include "internal/defines/package.h"
#include "internal/pack/pack_util.h"
#include "internal/generated/media_types.csv.h"
#include "internal/util/common.h"
#include "internal/util/compress.h"
#include "internal/util/crc32c.h"
#include "internal/util/csv.h"
#include "internal/util/error.h"
#include "internal/util/fs.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <shlwapi.h>
#else
#include <libgen.h>
#endif

#define CURRENT_MAJOR_VERSION 1

#define IO_BUFFER_LEN (128 * 1024) // 128 KB
#define DIR_LIST_BUFFER_LEN 1024 // 4 KB

ArpPackingOptions create_v1_packing_options(const char *pack_name, const char *pack_namespace, uint64_t max_part_len,
        const char *compression_type, const char *media_types_path) {
    size_t name_len_s = strlen(pack_name);
    size_t namespace_len_s = strlen(pack_namespace);
    size_t media_types_path_len_s = media_types_path != NULL ? strlen(media_types_path) : 0;

    if (name_len_s == 0) {
        libarp_set_error("Package name must not be empty");
        return NULL;
    }

    if (namespace_len_s == 0) {
        libarp_set_error("Namespace must not be empty");
        return NULL;
    } else if (namespace_len_s > PACKAGE_NAMESPACE_LEN) {
        libarp_set_error("Namespace length is too long");
        return NULL;
    } else if (validate_path_component(pack_namespace, (uint8_t) namespace_len_s) != 0) {
        return NULL;
    }

    if (max_part_len != 0 && max_part_len < PACKAGE_MIN_PART_LEN) {
        libarp_set_error("Max part length is too small");
        return NULL;
    }

    arp_packing_options_t *opts = calloc(1, sizeof(arp_packing_options_t));
    opts->pack_name = calloc(1, name_len_s + 1);
    opts->pack_namespace = calloc(1, PACKAGE_NAMESPACE_LEN + 1);
    opts->compression_type[0] = '\0';
    opts->media_types_path = media_types_path_len_s > 0 ? calloc(1, media_types_path_len_s + 1) : NULL;

    memcpy(opts->pack_name, pack_name, name_len_s + 1);
    memcpy(opts->pack_namespace, pack_namespace, namespace_len_s + 1);
    if (compression_type != NULL && strlen(compression_type) > 0) {
        char *compress_magic = NULL;
        if (strcmp(compression_type, ARP_COMPRESS_TYPE_DEFLATE) == 0) {
            compress_magic = ARP_COMPRESS_MAGIC_DEFLATE;
        } else {
            free(opts);

            libarp_set_error("Unrecognized compression type");
            return NULL;
        }
        memcpy(opts->compression_type, compress_magic, sizeof(opts->compression_type));
    }
    if (media_types_path != NULL && strlen(media_types_path) > 0) {
        memcpy(opts->media_types_path, media_types_path, media_types_path_len_s + 1);
    }

    opts->max_part_len = max_part_len;

    return opts;
}

void free_packing_options(ArpPackingOptions opts) {
    if (opts == NULL) {
        return;
    }

    arp_packing_options_t *real_opts = (arp_packing_options_t*) opts;

    if (real_opts->pack_name != NULL) {
        free(real_opts->pack_name);
    }

    if (real_opts->pack_namespace != NULL) {
        free(real_opts->pack_namespace);
    }

    if (real_opts->media_types_path != NULL) {
        free(real_opts->media_types_path);
    }

    free(real_opts);
}

static csv_file_t *_load_media_types(arp_packing_options_t *opts) {
    void *user_csv = NULL;
    size_t user_csv_len = 0;

    if (opts->media_types_path != NULL) {
        FILE *user_file = fopen(opts->media_types_path, "rb");
        if (user_file == NULL) {
            libarp_set_error("Failed to open user media types file");
            return NULL;
        }

        stat_t user_file_stat;
        if (fstat(fileno(user_file), &user_file_stat) != 0) {
            fclose(user_file);

            libarp_set_error("Failed to stat user media types file");
            return NULL;
        }

        user_csv_len = user_file_stat.st_size;
        if (user_csv_len > USER_MT_FILE_MAX_SIZE) {
            fclose(user_file);

            libarp_set_error("User media types file is too large");
            return NULL;
        }

        if ((user_csv = malloc(user_csv_len + 1)) == NULL) {
            fclose(user_file);

            libarp_set_error("malloc failed");
            return NULL;
        }
        if (fread(user_csv, user_csv_len, 1, user_file) != 1) {
            free(user_csv);

            libarp_set_error("Failed to read from user media types file");
            return NULL;
        }

        fclose(user_file);
    }

    csv_file_t *csv = parse_csv(MEDIA_TYPES_CSV_SRC, MEDIA_TYPES_CSV_LEN, user_csv, user_csv_len);

    if (user_csv != NULL) {
        free(user_csv);
    }

    return csv;
}

static void _free_fs_node(fs_node_ptr node) {
    if (node == NULL) {
        return;
    }

    if (node->file_stem != NULL) {
        free(node->file_stem);
    }

    if (node->file_ext != NULL) {
        free(node->file_ext);
    }

    if (node->media_type != NULL) {
        free(node->media_type);
    }

    if (node->target_path != NULL) {
        free(node->target_path);
    }

    if (node->type == FS_NODE_TYPE_DIR) {
        if (node->children != NULL) {
            for (size_t i = 0; i < node->children_count; i++) {
                fs_node_ptr child = node->children[i];
                if (child != NULL) {
                    _free_fs_node(child);
                }
            }
            free(node->children);
        }
    }

    free(node);
}

static int _create_fs_tree_impl(const char *root_path, const csv_file_t *media_types, fs_node_ptr *res,
        bool is_root) {
    static uint8_t recursion_count = 0;

    // we only need to do the nesting limit check in this function because once
    // the fs tree is constructed, it's guaranteed to be within the limit
    if (recursion_count > FILE_NESTING_LIMIT) {
        libarp_set_error("File nesting limit reached");
        return -1;
    }

    fs_node_ptr node = NULL;
    if ((node = calloc(1, sizeof(fs_node_t))) == NULL) {
        libarp_set_error("calloc failed");
        return ENOMEM;
    }

    node->is_root = is_root;

    stat_t root_stat;
    if (stat(root_path, &root_stat) != 0) {
        _free_fs_node(node);

        libarp_set_error("stat failed");
        return -1;
    }

    if (S_ISDIR(root_stat.st_mode)) {
        node->type = FS_NODE_TYPE_DIR;
        // calloc sets the name and ext to null - the caller will set these if necessary

        DirHandle root = NULL;
        if ((root = open_directory(root_path)) == NULL) {
            _free_fs_node(node);

            return errno;
        }

        const char *child_name = NULL;
        errno = 0;
        while ((child_name = read_directory(root)) != NULL) {
            char *child_full_path = NULL;
            if ((child_full_path = malloc(strlen(root_path) + 1 + strlen(child_name) + 1)) == NULL) {
                close_directory(root);

                _free_fs_node(node);

                libarp_set_error("malloc failed");
                return ENOMEM;
            }

            sprintf(child_full_path, "%s" PATH_SEPARATOR "%s", root_path, child_name);

            if (strcmp(child_name, ".") == 0 || strcmp(child_name, "..") == 0) {
                free(child_full_path);
                continue;
            }

            stat_t child_stat;
            if (stat(child_full_path, &child_stat) != 0) {
                close_directory(root);

                free(child_full_path);
                _free_fs_node(node);

                libarp_set_error("Failed to stat directory child while constructing fs tree (pass 1)");
                return errno;
            }

            free(child_full_path);

            // we don't check for links here because they should be transparently resolved
            if (S_ISDIR(child_stat.st_mode) || S_ISREG(child_stat.st_mode)) {
                if (node->children_count == SIZE_MAX) {
                    close_directory(root);
                    _free_fs_node(node);

                    libarp_set_error("Too many directory children to count");
                    return E2BIG;
                }

                node->children_count++;
            }
        }

        if (errno != 0) {
            close_directory(root);
            _free_fs_node(node);

            libarp_set_error("Encountered error while constructing fs tree (pass 1)");
            return errno;
        }

        rewind_directory(root);

        if (node->children_count > 0) {
            if ((node->children = calloc(node->children_count, sizeof(fs_node_ptr))) == NULL) {
                _free_fs_node(node);

                libarp_set_error("malloc failed");
                return ENOMEM;
            }

            size_t child_index = 0;
            errno = 0;
            while ((child_name = read_directory(root)) != NULL && child_index < node->children_count) {
                if (strcmp(child_name, ".") == 0 || strcmp(child_name, "..") == 0) {
                    continue;
                }

                if (child_index == SIZE_MAX) {
                    close_directory(root);
                    _free_fs_node(node);

                    libarp_set_error("Too many directory children to count");
                    return E2BIG;
                }

                char *child_full_path = NULL;
                if ((child_full_path = malloc(strlen(root_path) + 1 + strlen(child_name) + 1)) == NULL) {
                    close_directory(root);
                    _free_fs_node(node);

                    libarp_set_error("malloc failed");
                    return ENOMEM;
                }

                sprintf(child_full_path, "%s" PATH_SEPARATOR "%s", root_path, child_name);

                stat_t child_stat;
                if (stat(child_full_path, &child_stat) != 0) {
                    close_directory(root);

                    free(child_full_path);
                    _free_fs_node(node);

                    libarp_set_error("Failed to stat directory child while constructing fs tree (pass 2)");
                    return errno;
                }

                fs_node_ptr child_node = NULL;

                recursion_count++;
                {
                    int rc = _create_fs_tree_impl(child_full_path, media_types, &child_node, false);
                    free(child_full_path);
                    if (rc != 0) {
                        close_directory(root);

                        _free_fs_node(node);

                        *res = NULL;
                        return rc;
                    }
                }

                recursion_count--;

                node->children[child_index] = child_node;


                child_index++;

                errno = 0;
            }

            close_directory(root);

            if (errno != 0) {
                _free_fs_node(node);

                libarp_set_error("Encountered error while building fs tree (pass 2)");
                return errno;
            }

            // just in case
            node->children_count = child_index;
        } else {
            node->children = NULL;
        }
    } else if (S_ISREG(root_stat.st_mode)) {
        // symlinks should be transparently resolved
        node->type = FS_NODE_TYPE_FILE;

        node->size = root_stat.st_size;
    } else {
        free(node);

        *res = NULL;

        if (recursion_count == 0) {
            libarp_set_error("Root fs node type is not valid (must be regular file, directory, or link)");
            return -1;
        } else {
            return 0;
        }
    }

    #ifdef _WIN32
    char win32_path_buffer[MAX_PATH + 1];
    size_t win32_path_len = GetFullPathName(root_path, MAX_PATH + 1, win32_path_buffer, NULL);

    if (win32_path_len == 0 || win32_path_len > MAX_PATH) {
        _free_fs_node(node);

        libarp_set_error("Failed to get full file path");
        return -1;
    }

    if ((node->target_path = malloc(win32_path_len)) == NULL) {
        _free_fs_node(node);

        libarp_set_error("malloc failed");
        return ENOMEM;
    }

    memcpy(node->target_path, win32_path_buffer, win32_path_len);
    node->target_path[win32_path_len] = '\0';
    #else
    // realpath returns a malloc'd string, so assigning it directly is fine
    if ((node->target_path = realpath(root_path, NULL)) == NULL) {
        _free_fs_node(node);

        libarp_set_error("realpath failed");
        return errno;
    }

    // annoyingly, realpath sets errno on success sometimes
    errno = 0;
    #endif

    char *path_copy = NULL;
    if ((path_copy = strdup(root_path)) == NULL) {
        _free_fs_node(node);

        libarp_set_error("strdup failed");
        return ENOMEM;
    }

    char *file_name = NULL;
    #ifdef _WIN32
    file_name = path_copy;
    PathStripPath(file_name);
    #else
    if ((file_name = basename(path_copy)) == NULL) {
        free(path_copy);
        _free_fs_node(node);

        libarp_set_error("basename failed");
        return -1;
    }
    #endif

    size_t stem_len_s = 0;
    size_t ext_len_s = 0;
    const char *ext_delim = NULL;

    if (node->type == FS_NODE_TYPE_DIR) {
        stem_len_s = strlen(file_name);
        ext_len_s = 0;
    } else {
        ext_delim = strrchr(file_name, '.');

        // file is considered to have no extension if:
        //   there is no dot, or
        //   the name starts with a dot and has no other dots, or
        //   the name ends with a dot
        if (ext_delim == NULL
                || ext_delim == file_name
                || (size_t) (ext_delim - file_name) == strlen(file_name)) {
            // file has no extension (or starts with a dot and has no other dot)
            stem_len_s = strlen(file_name);
            ext_len_s = 0;
        } else {
            stem_len_s = (size_t) (ext_delim - file_name);
            ext_len_s = strlen(file_name) - stem_len_s - 1;
        }
    }

    size_t stem_len_b = stem_len_s + 1;
    size_t ext_len_b = ext_len_s + 1;

    if ((node->file_stem = malloc(stem_len_b)) == NULL) {
        free(path_copy);
        _free_fs_node(node);

        libarp_set_error("malloc failed");
        return ENOMEM;
    }

    memcpy(node->file_stem, file_name, stem_len_s);

    node->file_stem[stem_len_b - 1] = '\0';
    
    if (ext_len_s > 0) {
        if ((node->file_ext = malloc(ext_len_b)) == NULL) {
            free(path_copy);
            _free_fs_node(node);

            libarp_set_error("malloc failed");
            return ENOMEM;
        }

        memcpy(node->file_ext, (const void*) (file_name + stem_len_b), ext_len_s);
        node->file_ext[ext_len_b - 1] = '\0';
    }

    free(path_copy);

    if (node->type != FS_NODE_TYPE_DIR) {
        const char *media_type = ext_len_s > 0 ? search_csv(media_types, node->file_ext) : DEFAULT_MEDIA_TYPE;

        if (media_type == NULL) {
            media_type = DEFAULT_MEDIA_TYPE;
        }
        
        size_t media_type_len_s = strlen(media_type);
        size_t media_type_len_b = media_type_len_s + 1;

        if (media_type_len_s == 0 || media_type_len_s > NODE_MT_MAX_LEN) {
            media_type = DEFAULT_MEDIA_TYPE;
        }

        if ((node->media_type = malloc(media_type_len_b)) == NULL) {
            _free_fs_node(node);

            libarp_set_error("malloc failed");
            return ENOMEM;
        }

        memcpy(node->media_type, media_type, media_type_len_s);
        node->media_type[media_type_len_b - 1] = '\0';
    }

    *res = node;
    return 0;
}

static int _create_fs_tree(const char *root_path, const csv_file_t *media_types, fs_node_ptr *res) {
    return _create_fs_tree_impl(root_path, media_types, res, true);
}

// forward declaration required for recursive calls
static size_t _fs_node_count(fs_node_ptr root, bool dirs_only);

static size_t _fs_node_count(fs_node_ptr root, bool dirs_only) {
    if (root == NULL) {
        return 0;
    }

    if (root->type == FS_NODE_TYPE_DIR) {
        size_t count = 1;

        for (size_t i = 0; i < root->children_count; i++) {
            if (count == SIZE_MAX) {
                libarp_set_error("Too many fs nodes to count");
                return count;
            }

            count += _fs_node_count(root->children[i], dirs_only);
        }

        return count;
    } else {
        if (dirs_only) {
            return 0;
        } else {
            return 1;
        }
    }
}

// forward declaration required for recursive calls
static int _flatten_dir(fs_node_ptr root, fs_node_ptr_arr node_arr, size_t *dir_off, size_t *file_off,
        size_t *node_count);

static int _flatten_dir(fs_node_ptr root, fs_node_ptr_arr node_arr, size_t *dir_off, size_t *file_off,
        size_t *node_count) {
    if (root == NULL) {
        return 0;
    }

    // we have two separate offsets because the directories are listed first in a single block
    if (root->type == FS_NODE_TYPE_DIR) {
        root->index = *dir_off;
        node_arr[*dir_off] = root;
        *dir_off += 1;
        // We track the node count separately to prove to the static analyzer
        // that the array is being fully populated. We could just use the value
        // in file_off since that will effectively be identical, but LLVM isn't
        // clever enough to figure that out and will throw a warning when we try
        // to access the flattened node array.
        //
        // EDIT: This actually still doesn't seem to be enough to prove it. I
        // think it's because we're populating the array at two different
        // offsets concurrently. In any case, I think tracking the node count
        // separately is still probably a cleaner and less bug-prone way of
        // doing it.
        *node_count += 1;

        for (size_t i = 0; i < root->children_count; i++) {
            _flatten_dir(root->children[i], node_arr, dir_off, file_off, node_count);
        }
    } else {
        root->index = *file_off;
        node_arr[*file_off] = root;
        *file_off += 1;
        *node_count += 1;
    }

    return 0;
}

static int _flatten_fs(fs_node_ptr root, fs_node_ptr_arr *flattened, size_t *node_count) {
    size_t total_count = _fs_node_count(root, false);
    size_t dir_count = _fs_node_count(root, true);

    *node_count = 0;

    if (total_count == 0) {
        *flattened = NULL;
        *node_count = 0;
        return 0;
    }

    fs_node_ptr_arr node_arr = NULL;
    if ((node_arr = malloc(sizeof(void*) *total_count)) == NULL) {
        libarp_set_error("malloc failed");
        return ENOMEM;
    }

    int rc = UNINIT_U32;

    size_t dir_off = 0;
    size_t file_off = dir_count;
    if ((rc = _flatten_dir(root, node_arr, &dir_off, &file_off, node_count)) != 0) {
        free(node_arr);

        return rc;
    }

    *flattened = node_arr;

    return 0;
}

// forward declaration required for recursive calls
static int _compute_important_sizes(const_fs_node_ptr fs_root, uint64_t max_part_len, package_important_sizes_t *sizes);

static int _compute_important_sizes(const_fs_node_ptr fs_root, uint64_t max_part_len, package_important_sizes_t *sizes) {
    if (sizes->part_count == 0) {
        sizes->part_count = 1;
    }

    assert(fs_root != NULL);

    size_t stem_len_s = fs_root->is_root ? 0 : strlen(fs_root->file_stem);

    if (fs_root->type == FS_NODE_TYPE_FILE || fs_root->type == FS_NODE_TYPE_LINK) {
        if (sizes->node_count == UINT32_MAX) {
            libarp_set_error("Too many nodes to pack");
            return E2BIG;
        } else if (sizes->resource_count == UINT32_MAX) {
            libarp_set_error("Too many resources to pack");
            return E2BIG;
        }
        
        size_t ext_len_s = 0;
        if (fs_root->file_ext != NULL) {
            ext_len_s = strlen(fs_root->file_ext);
        }

        size_t media_type_len_s = strlen(fs_root->media_type);

        if (media_type_len_s == 0) {
            media_type_len_s = sizeof(DEFAULT_MEDIA_TYPE) - 1;
        }

        sizes->cat_len += NODE_DESC_BASE_LEN + stem_len_s + ext_len_s + media_type_len_s;

        if (max_part_len != 0 && fs_root->size > max_part_len) {
            libarp_set_error("Max part size is smaller than largest resource");
            return EINVAL;
        }

        size_t new_len = sizes->body_lens[sizes->part_count - 1] + fs_root->size;
        if (max_part_len != 0 && new_len > max_part_len) {
            if (sizes->part_count == PACKAGE_MAX_PARTS) {
                libarp_set_error("Part count would exceed maximum");
                return EINVAL;
            }

            sizes->part_count += 1;
        }

        sizes->body_lens[sizes->part_count - 1] += fs_root->size;

        sizes->node_count += 1;
        sizes->resource_count += 1;
    } else if (fs_root->type == FS_NODE_TYPE_DIR) {
        if (sizes->node_count == UINT32_MAX) {
            libarp_set_error("Too many nodes to pack");
            return E2BIG;
        } else if (sizes->directory_count == UINT32_MAX) {
            libarp_set_error("Too many directories to pack");
            return E2BIG;
        }

        sizes->cat_len += NODE_DESC_BASE_LEN + stem_len_s;

        size_t node_len = fs_root->children_count * NODE_DESC_INDEX_LEN;
        size_t new_len = sizes->body_lens[sizes->part_count - 1] + node_len;

        if (max_part_len != 0 && node_len > max_part_len) {
            libarp_set_error("Max part size is not large enough to store largest directory");
            return EINVAL;
        }

        if (max_part_len != 0 && new_len > max_part_len) {
            if (sizes->part_count == PACKAGE_MAX_PARTS) {
                libarp_set_error("Part count would exceed maximum");
                return -1;
            }
        }

        sizes->body_lens[sizes->part_count - 1] += node_len;
        sizes->node_count += 1;
        sizes->directory_count += 1;

        for (size_t i = 0; i < fs_root->children_count; i++) {
            fs_node_ptr child = fs_root->children[i];
            if (child == NULL) {
                continue;
            }

            int rc = _compute_important_sizes(fs_root->children[i], max_part_len, sizes);
            if (rc != 0) {
                return rc;
            }
        }
    } else {
        libarp_set_error("Unknown fs node type");
        return -1;
    }

    return 0;
}

static char *_get_part_path(const char *target_dir, const char *pack_name, uint16_t index, bool skip_suffix, char *buf) {
    const size_t part_name_base_len_b = strlen(".part") + 3 + strlen(".arp") + 1;

    if (buf == NULL) {
        buf = malloc(strlen(target_dir) + strlen(PATH_SEPARATOR) + strlen(pack_name) + part_name_base_len_b);
    }

    if (skip_suffix && index != 1) {
        libarp_set_error("Suffix cannot be skipped for part with index > 1");
        return NULL;
    }

    if (skip_suffix) {
        sprintf(buf, "%s%s%s.arp", target_dir, PATH_SEPARATOR, pack_name);
    } else {
        sprintf(buf, "%s%s%s.part%03d.arp", target_dir, PATH_SEPARATOR, pack_name, index);
    }

    return buf;
}

static int _unlink_part_files(const char *target_dir, const char *pack_name, size_t count, bool skip_suffix) {
    char *cur_path = NULL;

    for (size_t i = 1; i <= count; i++) {
        cur_path = _get_part_path(target_dir, pack_name, i, skip_suffix, cur_path);
        unlink(cur_path);
    }

    free(cur_path);

    return 0;
}

static void _populate_package_header(arp_packing_options_t *opts, package_important_sizes_t *sizes,
        unsigned char out_buf[PACKAGE_HEADER_LEN]) {
    memset(out_buf, 0, PACKAGE_HEADER_LEN);

    // magic number
    // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
    memcpy(offset_ptr(out_buf, PACKAGE_MAGIC_OFF), FORMAT_MAGIC, PACKAGE_MAGIC_LEN);
    // version
    uint16_t version = CURRENT_MAJOR_VERSION;
    copy_int_as_le(offset_ptr(out_buf, PACKAGE_VERSION_OFF), &version, PACKAGE_VERSION_LEN);
    // compression
    if (strlen(opts->compression_type) > 0) {
        memcpy(offset_ptr(out_buf, PACKAGE_COMPRESSION_OFF), opts->compression_type, PACKAGE_COMPRESSION_LEN);
    }
    // namespace
    memcpy(offset_ptr(out_buf, PACKAGE_NAMESPACE_OFF), opts->pack_namespace, PACKAGE_NAMESPACE_LEN);
    // parts
    copy_int_as_le(offset_ptr(out_buf, PACKAGE_PARTS_OFF), &sizes->part_count, PACKAGE_PARTS_LEN);
    // catalogue offset
    copy_int_as_le(offset_ptr(out_buf, PACKAGE_CAT_OFF_OFF), &sizes->cat_off, PACKAGE_CAT_OFF_LEN);
    // catalogue size
    copy_int_as_le(offset_ptr(out_buf, PACKAGE_CAT_LEN_OFF), &sizes->cat_len, PACKAGE_CAT_LEN_LEN);
    // node count
    copy_int_as_le(offset_ptr(out_buf, PACKAGE_CAT_CNT_OFF), &sizes->node_count, PACKAGE_CAT_CNT_LEN);
    // directory count
    copy_int_as_le(offset_ptr(out_buf, PACKAGE_DIR_CNT_OFF), &sizes->directory_count, PACKAGE_RES_CNT_LEN);
    // resource count
    copy_int_as_le(offset_ptr(out_buf, PACKAGE_RES_CNT_OFF), &sizes->resource_count, PACKAGE_RES_CNT_LEN);
    // body offset
    copy_int_as_le(offset_ptr(out_buf, PACKAGE_BODY_OFF_OFF), &sizes->first_body_off, PACKAGE_BODY_OFF_LEN);
    // body size
    copy_int_as_le(offset_ptr(out_buf, PACKAGE_BODY_LEN_OFF), &sizes->body_lens[0], PACKAGE_BODY_LEN_LEN);
    // reserved 1
    memset(offset_ptr(out_buf, PACKAGE_RESERVED_1_OFF), 0, PACKAGE_RESERVED_1_LEN);
}

static int _write_package_contents_to_disk(fs_node_ptr_arr fs_flat, const char *target_dir,
        arp_packing_options_t *opts, package_important_sizes_t *sizes) {
    FILE *cur_part_file = NULL;
    char *cur_part_path = NULL;

    bool skip_part_suffix = sizes->part_count == 1;
    cur_part_path = _get_part_path(target_dir, opts->pack_name, 1, skip_part_suffix, cur_part_path);

    if ((cur_part_file = fopen(cur_part_path, "wb")) == NULL) {
        free(cur_part_path);
        libarp_set_error("Failed to open first part file on disk");
        return -1;
    }

    uint16_t cur_part_index = 1;

    unsigned char read_buffer[IO_BUFFER_LEN];

    if (fseek(cur_part_file, sizes->first_body_off, SEEK_SET) != 0) {
        fclose(cur_part_file);
        unlink(cur_part_path);
        free(cur_part_path);

        libarp_set_error("Failed to seek to body offset");
        return errno;
    }

    sizes->part_count = 1;

    memset(sizes->body_lens, 0, sizeof(sizes->body_lens));

    uint64_t cur_body_off = sizes->first_body_off;

    // write node contents
    for (uint32_t i = 0; i < sizes->node_count; i++) {
        // disable lint to remove a very stubborn false positive
        // NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Assign)
        fs_node_ptr node = fs_flat[i];

        uint64_t new_part_len = cur_body_off + node->size;
        if (opts->max_part_len != 0 && new_part_len > opts->max_part_len) {
            fclose(cur_part_file);

            sizes->body_lens[cur_part_index] = sizes->first_body_off;
            cur_part_index += 1;
            sizes->part_count += 1;

            cur_part_path = _get_part_path(target_dir, opts->pack_name, cur_part_index, false, cur_part_path);

            if ((cur_part_file = fopen(cur_part_path, "wb")) == NULL) {
                free(cur_part_path);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index - 1, false);

                libarp_set_error("Failed to open part file for writing on disk");
                return -1;
            }

            // write part header
            unsigned char part_header[PACKAGE_PART_HEADER_LEN];

            memset(part_header, 0, sizeof(part_header));
            // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
            memcpy(part_header, PART_MAGIC, PART_MAGIC_LEN);
            copy_int_as_le(offset_ptr(part_header, PART_INDEX_OFF), &cur_part_index, sizeof(cur_part_index));

            if (fwrite(part_header, sizeof(part_header), 1, cur_part_file) != 1) {
                fclose(cur_part_file);
                free(cur_part_path);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index, false);

                libarp_set_error("Failed to write part header to disk");
                return -1;
            }

            cur_body_off = sizeof(part_header);
        }

        node->data_off = cur_part_index == 1
            ? (cur_body_off - sizes->first_body_off)
            : (cur_body_off - PACKAGE_PART_HEADER_LEN);
        node->part = cur_part_index;
        
        char err_msg[ERR_MSG_MAX_LEN];

        if (node->type == FS_NODE_TYPE_DIR) {
            uint32_t dir_listing_buffer[DIR_LIST_BUFFER_LEN];
            size_t dir_list_index = 0;

            uint32_t crc = 0;
            bool began_crc = false;

            if (node->children_count == 0) {
                node->packed_data_len = 0;
                node->crc = ~0;
            }

            size_t dir_data_len = 0;

            for (size_t cur_child_index = 0; cur_child_index < node->children_count; cur_child_index++) {
                dir_listing_buffer[dir_list_index] = node->children[cur_child_index]->index;
                dir_list_index += 1;

                if (dir_list_index == DIR_LIST_BUFFER_LEN) {
                    if (fwrite(dir_listing_buffer, sizeof(dir_listing_buffer), 1, cur_part_file) == 0) {
                        fclose(cur_part_file);
                        free(cur_part_path);
                        _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                        libarp_set_error("Failed to write directory contents to part file on disk");
                        return -1;
                    }

                    if (began_crc) {
                        crc = crc32c_cont(crc, dir_listing_buffer, sizeof(dir_listing_buffer));
                    } else {
                        crc = crc32c(dir_listing_buffer, sizeof(dir_listing_buffer));
                        began_crc = true;
                    }

                    dir_list_index = 0;
                    cur_body_off += sizeof(dir_listing_buffer);
                    dir_data_len += sizeof(dir_listing_buffer);
                }
            }

            if (dir_list_index != 0) {
                size_t write_bytes = dir_list_index * sizeof(dir_listing_buffer[0]);
                if (fwrite(dir_listing_buffer, write_bytes, 1, cur_part_file) == 0) {
                    fclose(cur_part_file);
                    free(cur_part_path);
                    _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                    libarp_set_error("Failed to write directory contents to part file on disk");
                    return -1;
                }

                if (began_crc) {
                    crc = crc32c_cont(crc, dir_listing_buffer, sizeof(dir_listing_buffer));
                } else {
                    crc = crc32c(dir_listing_buffer, sizeof(dir_listing_buffer));
                }

                cur_body_off += write_bytes;
                dir_data_len += write_bytes;
            }

            node->packed_data_len = dir_data_len;
            node->crc = crc;
        } else if (node->type == FS_NODE_TYPE_FILE || node->type == FS_NODE_TYPE_LINK) {
            stat_t node_stat;
            if (stat(node->target_path, &node_stat) != 0) {
                fclose(cur_part_file);
                free(cur_part_path);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                snprintf(err_msg, ERR_MSG_MAX_LEN, "Failed to stat node at path %s", node->target_path);
                libarp_set_error(err_msg);
                return -1;
            }

            uint64_t cur_node_size = node_stat.st_size;

            if (cur_node_size != node->size) {
                fclose(cur_part_file);
                free(cur_part_path);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                snprintf(err_msg, ERR_MSG_MAX_LEN, "Node changed sizes at path %s", node->target_path);
                libarp_set_error(err_msg);
                return -1;
            }

            FILE *cur_node_file = NULL;
            if ((cur_node_file = fopen(node->target_path, "rb")) == NULL) {
                fclose(cur_part_file);
                free(cur_part_path);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                snprintf(err_msg, ERR_MSG_MAX_LEN, "Failed to read node at path %s", node->target_path);
                libarp_set_error(err_msg);
                return -1;
            }

            uint32_t crc = 0;
            bool began_crc = false;

            uint64_t packed_data_len = 0;
            uint64_t raw_data_len = 0;

            void *compress_handle = NULL;

            if (strlen(opts->compression_type) > 0) {
                if (strcmp(opts->compression_type, ARP_COMPRESS_MAGIC_DEFLATE) == 0) {
                    compress_handle = compress_deflate_begin(cur_node_size);
                } else {
                    assert(false);
                }
            }

            size_t read_bytes = 0;
            clearerr(cur_node_file);
            uint64_t remaining = cur_node_size;
            while ((read_bytes = fread(read_buffer, 1, IO_BUFFER_LEN, cur_node_file)) > 0) {
                if (read_bytes > remaining) {
                    free(cur_part_path);

                    libarp_set_error("File size changed while reading");
                    return -1;
                }

                remaining -= read_bytes;

                void *processed_chunk = read_buffer;
                size_t to_write = read_bytes;

                if (strlen(opts->compression_type) > 0) {
                    if (strcmp(opts->compression_type, ARP_COMPRESS_MAGIC_DEFLATE) == 0) {
                        compress_deflate(compress_handle, read_buffer, read_bytes,
                                &processed_chunk, &to_write);
                    } else {
                        assert(false);
                    }
                }

                if (began_crc) {
                    crc = crc32c_cont(crc, processed_chunk, to_write);
                } else {
                    crc = crc32c(processed_chunk, to_write);
                    began_crc = true;
                }

                size_t written = fwrite(processed_chunk, to_write, 1, cur_part_file);

                if (processed_chunk != read_buffer) {
                    free(processed_chunk);
                }

                if (written != 1) {
                    fclose(cur_part_file);
                    free(cur_part_path);
                    _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                    libarp_set_error("Failed to copy node data to part file on disk");
                    return -1;
                }

                cur_body_off += to_write;
                packed_data_len += to_write;
                raw_data_len += read_bytes;

                if (remaining == 0) {
                    break;
                }
            }

            if (strlen(opts->compression_type) > 0) {
                if (strcmp(opts->compression_type, ARP_COMPRESS_MAGIC_DEFLATE) == 0) {
                    compress_deflate_end(compress_handle);
                } else {
                    assert(false);
                }
            }

            if (ferror(cur_node_file)) {
                fclose(cur_part_file);
                free(cur_part_path);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                snprintf(err_msg, ERR_MSG_MAX_LEN, "Encountered error while reading node at path %s", node->target_path);
                libarp_set_error(err_msg);
                return -1;
            }

            fclose(cur_node_file);

            node->crc = crc;
            node->packed_data_len = packed_data_len;
        } else {
            node->data_off = cur_body_off;
            node->packed_data_len = 0;
            // just skip it
            continue;
        }
    }

    FILE *first_part_file = NULL;
    if (cur_part_index == 1) {
        first_part_file = cur_part_file;
    } else {
        fclose(cur_part_file);

        cur_part_path = _get_part_path(target_dir, opts->pack_name, 1, skip_part_suffix, cur_part_path);

        if ((first_part_file = fopen(cur_part_path, "r+b")) == NULL) {
            free(cur_part_path);
            _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

            libarp_set_error("Failed to open first part file on disk");
            return -1;
        }
    }

    free(cur_part_path);

    // generate package header
    unsigned char pack_header[PACKAGE_HEADER_LEN];

    _populate_package_header(opts, sizes, pack_header);

    if (fseek(cur_part_file, 0, SEEK_SET) != 0) {
        _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

        libarp_set_error("Failed to seek to file start");
        return errno;
    }

    // write package header
    if (fwrite(pack_header, PACKAGE_HEADER_LEN, 1, cur_part_file) != 1) {
        _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

        libarp_set_error("Failed to write package header to disk");
        return -1;
    }

    if (fseek(first_part_file, sizes->cat_off, SEEK_SET) != 0) {
        _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

        libarp_set_error("Failed to seek to catalogue offset");
        return errno;
    }

    unsigned char cat_buf[IO_BUFFER_LEN];
    size_t cat_buf_len = 0;
    for (size_t i = 0; i < sizes->node_count; i++) {
        // flush catalogue buffer if it's potentially going to overflow this iteration
        if (cat_buf_len + NODE_DESC_MAX_LEN > IO_BUFFER_LEN) {
            if (fwrite(cat_buf, cat_buf_len, 1, first_part_file) != 1) {
                fclose(first_part_file);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                libarp_set_error("Failed to write catalogue to disk");
                return -1;
            }

            cat_buf_len = 0;
        }

        fs_node_ptr node = fs_flat[i];

        size_t name_len_s = strlen(node->file_stem);
        size_t ext_len_s = 0;
        size_t mt_len_s = 0;
        if (node->type != FS_NODE_TYPE_DIR) {
            ext_len_s = node->file_ext != NULL ? strlen(node->file_ext) : 0;
            mt_len_s = strlen(node->media_type);
        }

        unsigned char cur_node_buf[NODE_DESC_MAX_LEN];
        memset(cur_node_buf, 0, sizeof(cur_node_buf));

        char arp_type_ordinal = 0;
        switch (node->type) {
            case FS_NODE_TYPE_FILE: {
                arp_type_ordinal = PACK_NODE_TYPE_RESOURCE;
                break;
            }
            case FS_NODE_TYPE_DIR: {
                arp_type_ordinal = PACK_NODE_TYPE_DIRECTORY;
                break;
            }
            default: {
                fprintf(stderr, "Encountered unrecognized node type %d\n", node->type);
                assert(false);
            }
        }

        memcpy(offset_ptr(cur_node_buf, ND_TYPE_OFF), &arp_type_ordinal, ND_TYPE_LEN);
        copy_int_as_le(offset_ptr(cur_node_buf, ND_PART_OFF), &node->part, ND_PART_LEN);
        copy_int_as_le(offset_ptr(cur_node_buf, ND_DATA_OFF_OFF), &node->data_off, ND_DATA_OFF_LEN);
        copy_int_as_le(offset_ptr(cur_node_buf, ND_PACKED_DATA_LEN_OFF), &node->packed_data_len, ND_PACKED_DATA_LEN_LEN);
        copy_int_as_le(offset_ptr(cur_node_buf, ND_UNPACKED_DATA_LEN_OFF), &node->size, ND_UNPACKED_DATA_LEN_LEN);
        memcpy(offset_ptr(cur_node_buf, ND_CRC_OFF), &node->crc, ND_CRC_LEN);

        // root node must have empty name in package
        size_t real_name_len_s = i == 0 ? 0 : name_len_s;
        copy_int_as_le(offset_ptr(cur_node_buf, ND_NAME_LEN_OFF), &real_name_len_s,
                ND_NAME_LEN_LEN);

        if (node->type != FS_NODE_TYPE_DIR) {
            copy_int_as_le(offset_ptr(cur_node_buf, ND_EXT_LEN_OFF), &ext_len_s,
                    ND_EXT_LEN_LEN);
            copy_int_as_le(offset_ptr(cur_node_buf, ND_MT_LEN_OFF), &mt_len_s,
                    ND_MT_LEN_LEN);
        }

        size_t desc_len = NODE_DESC_BASE_LEN;

        // again, don't copy name of root node
        if (i > 0) {
            memcpy(offset_ptr(cur_node_buf, desc_len), node->file_stem, name_len_s);
            desc_len += name_len_s;
        }

        if (node->type != FS_NODE_TYPE_DIR) {
            memcpy(offset_ptr(cur_node_buf, desc_len), node->file_ext, ext_len_s);
            desc_len += ext_len_s;

            memcpy(offset_ptr(cur_node_buf, desc_len), node->media_type, mt_len_s);
            desc_len += mt_len_s;
        }

        // write descriptor length
        copy_int_as_le(offset_ptr(cur_node_buf, ND_LEN_OFF), &desc_len, ND_LEN_LEN);

        memcpy(offset_ptr(cat_buf, cat_buf_len), cur_node_buf, desc_len);

        cat_buf_len += desc_len;
    }

    // valgrind throws a really persistent false positive somewhere around here
    // when trying to write the buffer to disk. It thinks the CRC value of each
    // fs_node_t is somehow uninitialized, and copying it into the buffer above
    // results in the written buffer containing "uninitialized" bytes as well.
    // This is, of course, impossible, because the CRC is definitely being set
    // in all cases, and even if it weren't, the whole fs_node_t is being
    // calloced. valgrind, not to be deterred by reality, merrily continues to
    // insist that this is a genuine bug and there is literally no way to
    // suppress it (to my knowledge) besides just not copying the CRC (or
    // otherwise blanking the CRC bytes after they'be been copied).

    if (cat_buf_len != 0) {
        if (fwrite(cat_buf, cat_buf_len, 1, first_part_file) != 1) {
            fclose(first_part_file);
            _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

            libarp_set_error("Failed to write catalogue to disk");
            return -1;
        }
    }

    fclose(first_part_file);

    return 0;
}

static void _emit_message(void (*callback)(const char*), const char *msg) {
    if (callback != NULL) {
        callback(msg);
    }
}

static bool validate_src_path(const char *src_path) {
    stat_t src_stat;
    if (stat(src_path, &src_stat) != 0) {
        printf("src_path: %s\n", src_path);
        switch (errno) {
            case EACCES: {
                libarp_set_error("Cannot access source path");
                return false;
            }
            case ENAMETOOLONG: {
                libarp_set_error("Source path is too long");
                return false;
            }
            case ENOENT: {
                libarp_set_error("Source path does not exist");
                return false;
            }
            case ENOTDIR: {
                libarp_set_error("A component of the source path is not a directory");
                return false;
            }
            default: {
                char err_msg[ERR_MSG_MAX_LEN];
                snprintf(err_msg, ERR_MSG_MAX_LEN, "Failed to validate source directory (rc: %d)", errno);
                libarp_set_error(err_msg);
                return false;
            }
        }
    }

    if (!S_ISDIR(src_stat.st_mode)) {
        libarp_set_error("Source path is not a directory");
        return false;
    }

    return true;
}

static bool validate_output_path(const char *output_path) {
    stat_t output_stat;
    if (stat(output_path, &output_stat) != 0) {
        if (errno == ENOENT) {
            if (mkdir(output_path, 0755) != 0) {
                switch (errno) {
                    case EACCES: {
                        libarp_set_error("Cannot access output path prefix");
                        return false;
                    }
                    case ENAMETOOLONG: {
                        libarp_set_error("Output path is too long");
                        return false;
                    }
                    case ENOENT: {
                        libarp_set_error("Output path prefix does not exist");
                        return false;
                    }
                    case ENOSPC: {
                        libarp_set_error("Filesystem containing output path prefix is full");
                        return false;
                    }
                    case ENOTDIR: {
                        libarp_set_error("Output path prefix contains a non-directory");
                        return false;
                    }
                    case EROFS: {
                        libarp_set_error("Output path prefix is on read-only filesystem");
                        return false;
                    }
                    default: {
                        libarp_set_error("Failed to create output path");
                        return false;
                    }
                }
            }
        } else {
            switch (errno) {
                case EACCES: {
                    libarp_set_error("Cannot access source path");
                    return false;
                }
                case ENAMETOOLONG: {
                    libarp_set_error("Output path is too long");
                    return false;
                }
                case ENOENT: {
                    libarp_set_error("Output path does not exist");
                    return false;
                }
                case ENOTDIR: {
                    libarp_set_error("A component of the source path is not a directory");
                    return false;
                }
                default: {
                    char err_msg[ERR_MSG_MAX_LEN];
                    snprintf(err_msg, ERR_MSG_MAX_LEN, "Failed to validate source directory (rc: %d)", errno);
                    libarp_set_error(err_msg);
                    return false;
                }
            }
        }
    } else if (!S_ISDIR(output_stat.st_mode)) {
        libarp_set_error("Output path is not a directory");
        return false;
    }

    return true;
}

int create_arp_from_fs(const char *src_path, const char *output_dir, ArpPackingOptions opts,
        void (*msg_callback)(const char*)) {
    arp_packing_options_t *real_opts = (arp_packing_options_t*) opts;

    char *real_src_path = NULL;
    if ((real_src_path = malloc(strlen(src_path) + 1)) == NULL) {
        libarp_set_error("malloc failed");
        return ENOMEM;
    }

    memcpy(real_src_path, src_path, strlen(src_path) + 1);
    for (size_t i = strlen(real_src_path) - 1; i > 0; i--) {
        if (IS_PATH_DELIMITER(real_src_path[i])) {
            real_src_path[i] = '\0';
        } else {
            break;
        }
    }

    if (!validate_src_path(real_src_path)) {
        free(real_src_path);

        return -1;
    }

    if (!validate_output_path(output_dir)) {
        free(real_src_path);

        return -1;
    }

    csv_file_t *media_types = _load_media_types(real_opts);

    _emit_message(msg_callback, "Reading filesystem contents");

    fs_node_ptr fs_tree = NULL;
    int rc = _create_fs_tree(real_src_path, media_types, &fs_tree);
    free(real_src_path);
    if (rc != 0) {
        _free_fs_node(fs_tree);
        return rc;
    }

    free_csv(media_types);

    _emit_message(msg_callback, "Computing package parameters");

    package_important_sizes_t sizes;
    memset(&sizes, 0, sizeof(sizes));

    if ((rc = _compute_important_sizes(fs_tree, real_opts->max_part_len, &sizes)) != 0) {
        _free_fs_node(fs_tree);
        return rc;
    }

    sizes.cat_off = PACKAGE_HEADER_LEN;
    sizes.first_body_off = sizes.cat_off + sizes.cat_len;

    _emit_message(msg_callback, "Flattening filesystem map");

    fs_node_ptr_arr fs_flat = NULL;
    size_t fs_node_count = 0;
    if ((rc = _flatten_fs(fs_tree, &fs_flat, &fs_node_count)) != 0) {
        _free_fs_node(fs_tree);
        return rc;
    }

    assert(fs_node_count == sizes.node_count);

    _emit_message(msg_callback, "Writing package contents");

    rc = _write_package_contents_to_disk(fs_flat, output_dir, real_opts, &sizes);

    _free_fs_node(fs_tree);

    free(fs_flat);
    free(media_types);

    return rc;
}
