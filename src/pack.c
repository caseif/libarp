/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "libarp/common.h"
#include "libarp/pack.h"
#include "internal/common_util.h"
#include "internal/crc32c.h"
#include "internal/csv.h"
#include "internal/file_defines.h"
#include "internal/other_defines.h"
#include "internal/package_defines.h"
#include "internal/pack_util.h"
#include "internal/util.h"
#include "internal/generated/media_types.csv.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <libgen.h>
#endif

#define CURRENT_MAJOR_VERSION 1

#define COPY_BUFFER_LEN (128 * 1024) // 128 KB
#define DIR_LIST_BUFFER_LEN 1024 // 4 KB

ArpPackingOptions create_v1_packing_options(const char *pack_name, const char *pack_namespace, size_t max_part_len,
        const char *compression_type, const char *media_types_path) {
    size_t name_len_s = strlen(pack_name);
    size_t namespace_len_s = strlen(pack_namespace);
    size_t compression_type_len_s = compression_type != NULL ? strlen(compression_type) : 0;
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

    if (compression_type_len_s != 0 && compression_type_len_s != PACKAGE_COMPRESSION_LEN) {
        libarp_set_error("Compression type magic length is incorrect");
        return NULL;
    }

    if (max_part_len < PACKAGE_MIN_PART_LEN) {
        libarp_set_error("Max part length is too small");
        return NULL;
    }

    arp_packing_options_t *opts = calloc(1, sizeof(arp_packing_options_t));
    opts->pack_name = calloc(1, name_len_s + 1);
    opts->pack_namespace = calloc(1, PACKAGE_NAMESPACE_LEN + 1);
    opts->compression_type = calloc(1, PACKAGE_COMPRESSION_LEN + 1);
    opts->media_types_path = calloc(1, media_types_path_len_s + 1);

    memcpy(opts->pack_name, pack_name, name_len_s + 1);
    memcpy(opts->pack_namespace, pack_namespace, namespace_len_s + 1);
    if (compression_type != NULL) {
        memcpy(opts->compression_type, compression_type, compression_type_len_s + 1);
    }
    if (media_types_path != NULL) {
        memcpy(opts->media_types_path, media_types_path, media_types_path_len_s + 1);
    }

    opts->max_part_len = max_part_len;

    return opts;
}

void release_packing_options(ArpPackingOptions opts) {
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

    if (real_opts->compression_type != NULL) {
        free(real_opts->compression_type);
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

// annoyingly, the FS APIs are so different between Win32 and POSIX that we need
// totally separate implementations
#ifdef _WIN32
static int _create_fs_tree(const char *root_path, const csv_file_t *media_types, fs_node_ptr *res) {
    WIN32_FIND_DATAA find_data;

    HANDLE find_handle = FindFirstFileW(root_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    do {
        //TODO
    } while (FindNextFileW(find_handle, &find_data) != 0);
}
#else
static int _create_fs_tree(const char *root_path, const csv_file_t *media_types, fs_node_ptr *res) {
    static uint8_t recursion_count = 0;

    // we only need to do the nesting limit check in this function because once
    // the fs tree is constructed, it's guaranteed to be within the limit
    if (recursion_count > FILE_NESTING_LIMIT) {
        libarp_set_error("File nesting limit reached");
        return -1;
    }

    DIR *root = NULL;
    if ((root = opendir(root_path)) == NULL) {
        libarp_set_error("Failed to open directory");
        return -1;
    }

    fs_node_ptr node = NULL;
    if ((node = calloc(1, sizeof(fs_node_t))) == NULL) {
        libarp_set_error("calloc failed");
        return ENOMEM;
    }

    stat_t root_stat;
    if (stat(root_path, &root_stat) != 0) {
        _free_fs_node(node);

        libarp_set_error("stat failed");
        return -1;
    }

    if (S_ISDIR(root_stat.st_mode)) {
        node->type = FS_NODE_TYPE_DIR;
        // calloc sets the name and ext to null - the caller will set these if necessary

        char *child_full_path = NULL;
        if ((child_full_path = malloc(strlen(root_path) + 1 + NAME_MAX + 1)) == NULL) {
            _free_fs_node(node);

            libarp_set_error("malloc failed");
            return ENOMEM;
        }

        struct dirent *de = NULL;
        while ((de = readdir(root)) != NULL) {
            sprintf(child_full_path, "%s" PATH_SEPARATOR "%s", root_path, de->d_name);

            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                continue;
            }

            stat_t child_stat;
            stat(child_full_path, &child_stat);

            if (S_ISDIR(child_stat.st_mode) || S_ISREG(child_stat.st_mode)
                    || S_ISLNK(child_stat.st_mode)) {
                node->children_count++;
            }
        }

        if (node->children_count > 0) {
            if ((node->children = calloc(node->children_count, sizeof(fs_node_ptr))) == NULL) {
                free(child_full_path);
                _free_fs_node(node);

                libarp_set_error("malloc failed");
                return ENOMEM;
            }

            size_t child_index = 0;
            while ((de = readdir(root)) != NULL && child_index < node->children_count) {
                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                    continue;
                }

                sprintf(child_full_path, "%s" PATH_SEPARATOR "%s", root_path, de->d_name);

                stat_t child_stat;
                stat(child_full_path, &child_stat);

                fs_node_ptr child_node = NULL;
                recursion_count++;
                {
                    int rc = _create_fs_tree(child_full_path, media_types, &child_node);
                    if (rc != 0) {
                        free(child_full_path);
                        _free_fs_node(node);

                        *res = NULL;
                        return rc;
                    }
                }
                recursion_count--;

                node->children[child_index] = child_node;

                child_index++;
            }

            // just in case
            node->children_count = child_index;
        } else {
            node->children = NULL;
        }

        free(child_full_path);

        closedir(root);
    } else if (S_ISREG(root_stat.st_mode) || S_ISLNK(root_stat.st_mode)) {
        node->type = S_ISREG(root_stat.st_mode) ? FS_NODE_TYPE_FILE : FS_NODE_TYPE_LINK;
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
    size_t win32_path_len = GetFullPathNameW(root_path, MAX_PATH + 1, win32_path_buffer, NULL);

    if (win32_path_len == 0 || win32_path_len > MAX_PATH + 1) {
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
    #else
    // realpath returns a malloc'd string, so assigning it directly is fine
    node->target_path = realpath(root_path, NULL);
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
    PathStripPathW(file_name);
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

    if ((node->file_stem = malloc(stem_len_s + 1)) == NULL) {
        free(path_copy);
        _free_fs_node(node);

        libarp_set_error("malloc failed");
        return ENOMEM;
    }

    memcpy(node->file_stem, file_name, stem_len_s);

    if (ext_len_s > 0) {
        if ((node->file_ext = malloc(ext_len_s + 1)) == NULL) {
            free(path_copy);
            _free_fs_node(node);

            libarp_set_error("malloc failed");
            return ENOMEM;
        }

        memcpy(node->file_ext, (const void*) (file_name + stem_len_s + 1), ext_len_s);
    }

    free(path_copy);

    if (node->type != FS_NODE_TYPE_DIR) {
        const char *media_type = ext_len_s > 0 ? search_csv(media_types, node->file_ext) : DEFAULT_MEDIA_TYPE;
        if (media_type == NULL || strlen(media_type) == 0 || strlen(media_type) > NODE_MT_MAX_LEN) {
            media_type = DEFAULT_MEDIA_TYPE;
        }

        if ((node->media_type = malloc(strlen(media_type) + 1)) == NULL) {
            _free_fs_node(node);

            libarp_set_error("malloc failed");
            return ENOMEM;
        }

        memcpy(node->media_type, media_type, strlen(media_type) + 1);
    }

    *res = node;
    return 0;
}
#endif

// forward declaration required for recursive calls
static size_t _fs_node_count(fs_node_ptr root, bool dirs_only);

static size_t _fs_node_count(fs_node_ptr root, bool dirs_only) {
    if (root == NULL) {
        return 0;
    }

    if (root->type == FS_NODE_TYPE_DIR) {
        size_t count = 1;

        for (size_t i = 0; i < root->children_count; i++) {
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

    int rc = (int) 0xDEADBEEF;

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
static int _compute_important_sizes(const_fs_node_ptr fs_root, size_t max_part_len, package_important_sizes_t *sizes);

static int _compute_important_sizes(const_fs_node_ptr fs_root, size_t max_part_len, package_important_sizes_t *sizes) {
    if (sizes->part_count == 0) {
        sizes->part_count = 1;
    }

    size_t stem_len_s = strlen(fs_root->file_stem);

    if (fs_root->type == FS_NODE_TYPE_FILE || fs_root->type == FS_NODE_TYPE_LINK) {
        size_t ext_len_s = 0;
        if (fs_root->file_ext != NULL) {
            ext_len_s = strlen(fs_root->file_ext);
        }

        size_t media_type_len_s = strlen(fs_root->media_type);

        if (media_type_len_s == 0) {
            media_type_len_s = sizeof(DEFAULT_MEDIA_TYPE) - 1;
        }

        sizes->cat_len += NODE_DESC_BASE_LEN + stem_len_s + ext_len_s + media_type_len_s;

        stat_t node_stat;
        if (stat(fs_root->target_path, &node_stat) != 0) {
            libarp_set_error("stat failed");
            return -1;
        }

        size_t new_len = sizes->body_lens[sizes->part_count - 1] + node_stat.st_size;
        if (new_len > max_part_len) {
            if (sizes->part_count == PACKAGE_MAX_PARTS) {
                libarp_set_error("Part count would exceed maximum");
                return -1;
            }

            sizes->part_count += 1;
        }

        sizes->body_lens[sizes->part_count - 1] += node_stat.st_size;

        sizes->node_count += 1;
        sizes->resource_count += 1;
    } else if (fs_root->type == FS_NODE_TYPE_DIR) {
        sizes->cat_len += NODE_DESC_BASE_LEN + stem_len_s;

        size_t node_len = fs_root->children_count * NODE_DESCRIPTOR_INDEX_LEN;
        size_t new_len = sizes->body_lens[sizes->part_count - 1] + node_len;

        if (new_len > max_part_len) {
            if (sizes->part_count == PACKAGE_MAX_PARTS) {
                libarp_set_error("Part count would exceed maximum");
                return -1;
            }
        }

        sizes->body_lens[sizes->part_count - 1] += node_len;
        sizes->node_count += 1;

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

static int _write_package_contents_to_disk(const unsigned char *header_contents, fs_node_ptr_arr fs_flat,
        const char *target_dir, arp_packing_options_t *opts, package_important_sizes_t *important_sizes) {
    FILE *cur_part_file = NULL;
    char *cur_part_path = NULL;

    bool skip_part_suffix = important_sizes->part_count == 1;
    cur_part_path = _get_part_path(target_dir, opts->pack_name, 1, skip_part_suffix, cur_part_path);

    if ((cur_part_file = fopen(cur_part_path, "wb")) == NULL) {
        free(cur_part_path);
        libarp_set_error("Failed to open first part file on disk");
        return -1;
    }

    // write package header
    if (fwrite(header_contents, PACKAGE_HEADER_LEN, 1, cur_part_file) != 1) {
        fclose(cur_part_file);
        unlink(cur_part_path);
        free(cur_part_path);

        libarp_set_error("Failed to write package header to disk");
        return -1;
    }

    size_t cat_off = PACKAGE_HEADER_LEN;
    size_t body_start = cat_off + important_sizes->cat_len;
    size_t body_off = body_start;

    uint16_t cur_part_index = 1;

    unsigned char copy_buffer[COPY_BUFFER_LEN];

    // write node contents
    for (size_t i = 0; i < important_sizes->node_count; i++) {
        // disable lint to remove a very stubborn false positive
        // NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Assign)
        fs_node_ptr node = fs_flat[i];

        size_t new_part_len = body_off + node->size;
        if (new_part_len > opts->max_part_len) {
            fclose(cur_part_file);

            cur_part_index += 1;

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

            body_off = sizeof(part_header);
        }

        node->data_off = cur_part_index == 1 ? (body_off - body_start) : (body_off - PACKAGE_PART_HEADER_LEN);
        node->part = cur_part_index;
        
        char err_msg[ERR_MSG_MAX_LEN];

        if (node->type == FS_NODE_TYPE_DIR) {
            uint32_t dir_listing_buffer[DIR_LIST_BUFFER_LEN];
            size_t dir_list_index = 0;

            uint32_t crc = 0;
            bool began_crc = false;

            if (node->children_count == 0) {
                node->data_len = 0;
                node->crc = ~0;
            }

            size_t dir_data_len = 0;

            for (size_t cur_child_index = 0; i < node->children_count; i++) {
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
                    //TODO: handle compression
                    
                    dir_list_index = 0;
                    body_off += sizeof(dir_listing_buffer);
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
                //TODO: handle compression

                body_off += write_bytes;
                dir_data_len += write_bytes;
            }

            node->data_len = dir_data_len;
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

            size_t cur_node_size = node_stat.st_size;

            if (cur_node_size != node->size) {
                fclose(cur_part_file);
                free(cur_part_path);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                snprintf(err_msg, ERR_MSG_MAX_LEN, "Node changed sizes at path %s", node->target_path);
                libarp_set_error(err_msg);
                return -1;
            }

            FILE *cur_node_file = NULL;
            if ((cur_node_file = fopen(node->target_path, "rb")) != 0) {
                fclose(cur_part_file);
                free(cur_part_path);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                snprintf(err_msg, ERR_MSG_MAX_LEN, "Failed to read node at path %s", node->target_path);
                libarp_set_error(err_msg);
                return -1;
            }

            uint32_t crc = 0;
            bool began_crc = false;

            size_t data_len = 0;

            size_t read_bytes = 0;
            while ((read_bytes = fread(copy_buffer, 1, COPY_BUFFER_LEN, cur_node_file)) > 0) {
                if (fwrite(copy_buffer, read_bytes, 1, cur_part_file) != 1) {
                    fclose(cur_part_file);
                    free(cur_part_path);
                    _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                    libarp_set_error("Failed to copy node data to part file on disk");
                    return -1;
                }

                if (began_crc) {
                    crc = crc32c_cont(crc, copy_buffer, read_bytes);
                } else {
                    crc = crc32c(copy_buffer, read_bytes);
                }
                //TODO: handle compression

                body_off += read_bytes;
                data_len += read_bytes;
            }

            fclose(cur_node_file);

            if (ferror(cur_node_file)) {
                fclose(cur_part_file);
                free(cur_part_path);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                snprintf(err_msg, ERR_MSG_MAX_LEN, "Encountered error while reading node at path %s", node->target_path);
                libarp_set_error(err_msg);
                return -1;
            }

            node->crc = crc;
            node->data_len = data_len; //TODO: account for compression
        } else {
            node->data_off = body_off;
            node->data_len = 0;
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

        if ((first_part_file = fopen(cur_part_path, "wb")) == NULL) {
            free(cur_part_path);
            _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

            libarp_set_error("Failed to open first part file on disk");
            return -1;
        }
    }

    free(cur_part_path);                

    unsigned char cat_buf[COPY_BUFFER_LEN];
    size_t cat_buf_off = 0;
    for (size_t i = 0; i < important_sizes->node_count; i++) {
        if (cat_buf_off + NODE_DESC_MAX_LEN > COPY_BUFFER_LEN) {
            if (fwrite(cat_buf, cat_buf_off, 1, first_part_file) != 1) {
                fclose(first_part_file);
                _unlink_part_files(target_dir, opts->pack_name, cur_part_index, skip_part_suffix);

                libarp_set_error("Failed to write catalogue to disk");
                return -1;
            }

            cat_buf_off = 0;
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

        memcpy(offset_ptr(cur_node_buf, NODE_DESC_TYPE_OFF), &node->type, NODE_DESC_TYPE_LEN);
        copy_int_as_le(offset_ptr(cur_node_buf, NODE_DESC_PART_OFF), &node->part, NODE_DESC_PART_LEN);
        copy_int_as_le(offset_ptr(cur_node_buf, NODE_DESC_DATA_OFF_OFF), &node->data_off, NODE_DESC_DATA_OFF_LEN);
        copy_int_as_le(offset_ptr(cur_node_buf, NODE_DESC_DATA_LEN_OFF), &node->data_len, NODE_DESC_DATA_LEN_LEN);
        if (opts->compression_type != NULL) {
            //TODO: implement compression
            copy_int_as_le(offset_ptr(cur_node_buf, NODE_DESC_UC_DATA_LEN_OFF), &node->size, NODE_DESC_UC_DATA_LEN_LEN);
        }
        memcpy(offset_ptr(cur_node_buf, NODE_DESC_CRC_OFF), &node->crc, NODE_DESC_CRC_LEN);
        copy_int_as_le(offset_ptr(cur_node_buf, NODE_DESC_NAME_LEN_OFF), &name_len_s,
                NODE_DESC_NAME_LEN_LEN);
        if (node->type != FS_NODE_TYPE_DIR) {
            copy_int_as_le(offset_ptr(cur_node_buf, NODE_DESC_EXT_LEN_OFF), &ext_len_s,
                    NODE_DESC_EXT_LEN_LEN);
            copy_int_as_le(offset_ptr(cur_node_buf, NODE_DESC_MT_LEN_OFF), &mt_len_s,
                    NODE_DESC_MT_LEN_LEN);
        }

        size_t desc_len = NODE_DESC_BASE_LEN;

        memcpy(offset_ptr(cur_node_buf, desc_len), node->file_stem, name_len_s);
        desc_len += name_len_s;

        if (node->type != FS_NODE_TYPE_DIR) {
            memcpy(offset_ptr(cur_node_buf, desc_len), node->file_ext, ext_len_s);
            desc_len += ext_len_s;

            memcpy(offset_ptr(cur_node_buf, desc_len), node->media_type, mt_len_s);
            desc_len += mt_len_s;
        }

        // write descriptor length
        copy_int_as_le(offset_ptr(cur_node_buf, NODE_DESC_LEN_OFF), &desc_len, NODE_DESC_LEN_LEN);

        memcpy(offset_ptr(cat_buf, cat_buf_off), cur_node_buf, desc_len);
    }

    if (cat_buf_off != 0) {
        if (fwrite(cat_buf, cat_buf_off, 1, first_part_file) != 1) {
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

int create_arp_from_fs(const char *src_path, const char *target_dir, ArpPackingOptions opts,
        void (*msg_callback)(const char*)) {
    arp_packing_options_t *real_opts = (arp_packing_options_t*) opts;

    csv_file_t *media_types = _load_media_types(real_opts);

    _emit_message(msg_callback, "Reading filesystem contents");

    fs_node_ptr fs_tree = NULL;
    int rc = (int) 0xDEADBEEF;
    if ((rc = _create_fs_tree(src_path, media_types, &fs_tree)) != 0) {
        _free_fs_node(fs_tree);
        return rc;
    }

    _emit_message(msg_callback, "Computing package parameters");

    package_important_sizes_t important_sizes;
    memset(&important_sizes, 0, sizeof(important_sizes));
    if ((rc = _compute_important_sizes(fs_tree, real_opts->max_part_len, &important_sizes)) != 0) {
        _free_fs_node(fs_tree);
        return rc;
    }

    _emit_message(msg_callback, "Flattening filesystem map");

    fs_node_ptr_arr fs_flat = NULL;
    size_t fs_node_count = 0;
    if ((rc = _flatten_fs(fs_tree, &fs_flat, &fs_node_count)) != 0) {
        _free_fs_node(fs_tree);
        return rc;
    }

    assert(fs_node_count == important_sizes.node_count);

    _emit_message(msg_callback, "Generating package header");

    unsigned char pack_header[PACKAGE_HEADER_LEN];
    memset(pack_header, 0, sizeof(pack_header));

    size_t cat_off = PACKAGE_HEADER_LEN;
    size_t body_off = cat_off + important_sizes.cat_len;

    // header population
    // magic number
    // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
    memcpy(offset_ptr(pack_header, PACKAGE_MAGIC_OFF), FORMAT_MAGIC, PACKAGE_MAGIC_LEN);
    // version
    uint16_t version = CURRENT_MAJOR_VERSION;
    copy_int_as_le(offset_ptr(pack_header, PACKAGE_VERSION_OFF), &version, PACKAGE_VERSION_LEN);
    // compression
    if (real_opts->compression_type != NULL) {
        //TODO: implement compression
        //memcpy(offset_ptr(pack_header, PACKAGE_COMPRESSION_OFF), real_opts->compression_type, PACKAGE_COMPRESSION_LEN);
    }
    // namespace
    memcpy(offset_ptr(pack_header, PACKAGE_NAMESPACE_OFF), real_opts->pack_namespace, PACKAGE_NAMESPACE_LEN);
    // parts
    copy_int_as_le(offset_ptr(pack_header, PACKAGE_PARTS_OFF), &important_sizes.part_count, PACKAGE_PARTS_LEN);
    // catalogue offset
    copy_int_as_le(offset_ptr(pack_header, PACKAGE_CAT_OFF_OFF), &cat_off, PACKAGE_CAT_OFF_LEN);
    // catalogue size
    copy_int_as_le(offset_ptr(pack_header, PACKAGE_CAT_LEN_OFF), &important_sizes.cat_len, PACKAGE_CAT_LEN_LEN);
    // node count
    copy_int_as_le(offset_ptr(pack_header, PACKAGE_CAT_CNT_OFF), &important_sizes.node_count, PACKAGE_CAT_CNT_LEN);
    // resource count
    copy_int_as_le(offset_ptr(pack_header, PACKAGE_RES_CNT_OFF), &important_sizes.resource_count, PACKAGE_RES_CNT_LEN);
    // body offset
    copy_int_as_le(offset_ptr(pack_header, PACKAGE_BODY_OFF_OFF), &body_off, PACKAGE_BODY_OFF_LEN);
    // body size
    copy_int_as_le(offset_ptr(pack_header, PACKAGE_BODY_LEN_OFF), &important_sizes.body_lens[0], PACKAGE_BODY_LEN_LEN);
    // unused 1
    memset(offset_ptr(pack_header, PACKAGE_UNUSED_LEN), 0, PACKAGE_UNUSED_LEN);

    _emit_message(msg_callback, "Writing package contents");

    _write_package_contents_to_disk(pack_header, fs_flat, target_dir, real_opts, &important_sizes);

    free(fs_flat);
    free(media_types);

    return 0;
}
