/*
 * This file is a part of libarp.
 * Copyright (c) 2020, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "libarp/common.h"
#include "libarp/pack.h"
#include "internal/common_util.h"
#include "internal/csv.h"
#include "internal/file_defines.h"
#include "internal/other_defines.h"
#include "internal/package_defines.h"
#include "internal/pack_util.h"
#include "internal/util.h"
#include "internal/generated/media_types.csv.h"

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CURRENT_MAJOR_VERSION 1

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
    } else if (!validate_path_component(pack_namespace, namespace_len_s) != 0) {
        return NULL;
    }

    if (compression_type_len_s != 0 && compression_type_len_s != PACKAGE_COMPRESSION_LEN) {
        libarp_set_error("Compression type magic length is incorrect");
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
        FILE *user_file = fopen(opts->media_types_path, "r");
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

static void _free_fs_node(fs_node_t *node) {
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
        for (size_t i = 0; i < node->children_count; i++) {
            fs_node_t *child = node->children[i];
            if (child != NULL) {
                _free_fs_node(child);
            }
        }
    }

    free(node);
}

// annoyingly, the FS APIs are so different between Win32 and POSIX that we need
// totally separate implementations
#ifdef _WIN32
static fs_node_t *_create_fs_tree(const char *root_path) {
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
static fs_node_t *_create_fs_tree(const char *root_path) {
    static uint8_t recursion_count = 0;

    // we only need to do the nesting limit check in this function because once
    // the fs tree is constructed, it's guaranteed to be within the limit
    if (recursion_count > FILE_NESTING_LIMIT) {
        libarp_set_error("File nesting limit reached");
        return NULL;
    }

    DIR *root;
    if ((root = opendir(root_path)) == NULL) {
        libarp_set_error("Failed to open directory");
        return NULL;
    }

    fs_node_t *node;
    if ((node = malloc(sizeof(fs_node_t))) == NULL) {
        libarp_set_error("malloc failed");
        return NULL;
    }

    node->type = FS_NODE_TYPE_DIR;
    // we explicitly set the name and ext to null - the caller will set it if necessary
    node->file_stem = NULL;
    node->file_ext = NULL;

    char *child_full_path;
    if ((child_full_path = malloc(strlen(root_path) + 1 + NAME_MAX + 1)) == NULL) {
        free(node);

        libarp_set_error("malloc failed");
        return NULL;
    }

    struct dirent *de;
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

    if ((node->children = malloc(sizeof(void*) * node->children_count)) == NULL) {
        free(child_full_path);
        free(node);

        libarp_set_error("malloc failed");
        return NULL;
    }

    size_t child_index = 0;
    while ((de = readdir(root)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }

        sprintf(child_full_path, "%s" PATH_SEPARATOR "%s", root_path, de->d_name);

        stat_t child_stat;
        stat(child_full_path, &child_stat);

        fs_node_t *child_node;
        if (S_ISDIR(child_stat.st_mode)) {
            recursion_count++;
            child_node = _create_fs_tree(child_full_path);
            recursion_count--;
        } else if (S_ISREG(child_stat.st_mode) || S_ISLNK(child_stat.st_mode)) {
            if ((child_node = malloc(sizeof(fs_node_t))) == NULL) {
                free(child_full_path);
                _free_fs_node(node);

                libarp_set_error("malloc failed");
                return NULL;
            }

            child_node->type = S_ISREG(child_stat.st_mode) ? FS_NODE_TYPE_FILE : FS_NODE_TYPE_LINK;
        }

        #ifdef _WIN32
        char win32_path_buffer[MAX_PATH + 1];
        size_t win32_path_len = GetFullPathNameW(child_full_path, MAX_PATH + 1, win32_path_buffer, NULL);

        if (win32_path_len == 0 || win32_path_len > MAX_PATH + 1) {
            free(child_full_path);
            _free_fs_node(node);
            
            libarp_set_error("Failed to get full file path");
            return NULL;
        }

        if ((child_node->target_path = malloc(win32_path_len)) == NULL) {
            free(child_full_path);
            _free_fs_node(node);
            
            libarp_set_error("malloc failed");
            return NULL;
        }

        memcpy(child_node->target_path, win32_path_buffer, win32_path_len);
        #else
        // realpath returns a malloc'd string, so assigning it directly is fine
        child_node->target_path = realpath(child_full_path, NULL);
        #endif

        size_t stem_len_s;
        size_t ext_len_s;
        const char *ext_delim;

        if (child_node->type == FS_NODE_TYPE_DIR) {
            stem_len_s = strlen(de->d_name);
            ext_len_s = 0;
        } else {
            ext_delim = strrchr(de->d_name, '.');

            // file is considered to have no extension if:
            //   there is no dot, or
            //   the name starts with a dot and has no other dots, or
            //   the name ends with a dot
            if (ext_delim == NULL
                    || ext_delim == de->d_name
                    || (size_t) (ext_delim - de->d_name) == strlen(de->d_name)) {
                // file has no extension (or starts with a dot and has no other dot)
                stem_len_s = strlen(de->d_name);
                ext_len_s = 0;
            } else {
                stem_len_s = (size_t) (ext_delim - de->d_name);
                ext_len_s = strlen(de->d_name) - stem_len_s - 1;
            }
        }

        if ((child_node->file_stem = malloc(stem_len_s + 1)) == NULL) {
            free(child_node);
            free(child_full_path);
            _free_fs_node(node);

            libarp_set_error("malloc failed");
            return NULL;
        }

        memcpy(child_node->file_stem, de->d_name, stem_len_s);
        
        if (ext_len_s > 0) {
            if ((child_node->file_stem = malloc(ext_len_s + 1)) == NULL) {
                free(child_node);
                free(child_full_path);
                _free_fs_node(node);

                libarp_set_error("malloc failed");
                return NULL;
            }

            memcpy(child_node->file_ext, (const void*) (de->d_name + stem_len_s + 1), ext_len_s);
        }

        node->children[child_index] = child_node;

        child_index++;
    }

    free(child_full_path);

    closedir(root);

    return node;
}
#endif

// forward declaration required for recursive calls
static size_t _fs_node_count(fs_node_t *root, bool dirs_only);

static size_t _fs_node_count(fs_node_t *root, bool dirs_only) {
    if (root == NULL) {
        return 0;
    }

    if (root->type == FS_NODE_TYPE_DIR) {
        size_t count = 0;

        for (size_t i = 0; i < root->children_count; i++) {
            count += _fs_node_count(root->children[i], dirs_only);
        }

        return count + 1;
    } else {
        if (dirs_only) {
            return 0;
        } else {
            return 1;
        }
    }
}

// forward declaration required for recursive calls
static void _flatten_dir(fs_node_t *root, fs_node_t **node_arr, size_t *dir_off, size_t *file_off);

static void _flatten_dir(fs_node_t *root, fs_node_t **node_arr, size_t *dir_off, size_t *file_off) {
    if (root == NULL) {
        return;
    }

    if (root->type == FS_NODE_TYPE_DIR) {
        root->index = *dir_off;
        node_arr[*dir_off++] = root;
        for (size_t i = 0; i < root->children_count; i++) {
            _flatten_dir(root->children[i], node_arr, dir_off, file_off);
        }
    } else {
        root->index = *file_off;
        node_arr[*file_off++] = root;
    }
}

static fs_node_t **_flatten_fs(fs_node_t *root) {
    size_t total_count = _fs_node_count(root, false);
    size_t dir_count = _fs_node_count(root, true);

    fs_node_t **node_arr;
    if ((node_arr = malloc(sizeof(void*) * total_count)) == NULL) {
        libarp_set_error("malloc failed");
        return NULL;
    }

    size_t dir_off = 0;
    size_t file_off = dir_count;
    _flatten_dir(root, node_arr, &dir_off, &file_off);

    return node_arr;
}

// forward declaration required for recursive calls
static int _compute_catalogue_and_body_len(const fs_node_t *fs_root, const csv_file_t *media_types, size_t *cat_len,
        size_t *body_len);

static int _compute_catalogue_and_body_len(const fs_node_t *fs_root, const csv_file_t *media_types, size_t *cat_len,
        size_t *body_len) {
    size_t stem_len_s = strlen(fs_root->file_stem);

    if (fs_root->type == FS_NODE_TYPE_FILE || fs_root->type == FS_NODE_TYPE_LINK) {
        size_t ext_len_s = 0;
        size_t media_type_len_s = 0;
        if (fs_root->file_ext != NULL) {
            ext_len_s = strlen(fs_root->file_ext);

            const char *media_type = search_csv(media_types, fs_root->file_ext);
            if (media_type != NULL) {
                media_type_len_s = strlen(media_type);
            }

            if (media_type_len_s > NODE_MT_MAX_LEN) {
                media_type_len_s = 0;
            }
        }

        if (media_type_len_s == 0) {
            media_type_len_s = sizeof(DEFAULT_MEDIA_TYPE) - 1;
        }

        *cat_len += NODE_DESC_BASE_LEN + stem_len_s + ext_len_s + media_type_len_s;

        stat_t node_stat;
        if (stat(fs_root->target_path, &node_stat) != 0) {
            libarp_set_error("stat failed");
            return -1;
        }

        *body_len += node_stat.st_size;
    } else if (fs_root->type == FS_NODE_TYPE_DIR) {
        *cat_len += NODE_DESC_BASE_LEN + stem_len_s;
        *body_len *= fs_root->children_count * NODE_DESCRIPTOR_INDEX_LEN;

        for (size_t i = 0; i < fs_root->children_count; i++) {
            int rc = _compute_catalogue_and_body_len(fs_root->children[i], media_types, cat_len, body_len);
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

int create_arp_from_fs(const char *src_path, const char *target_dir, ArpPackingOptions opts) {
    arp_packing_options_t *real_opts = (arp_packing_options_t*) opts;

    csv_file_t *media_types = _load_media_types(real_opts);

    fs_node_t *fs_tree = _create_fs_tree(src_path);

    size_t cat_len;
    size_t body_len;
    _compute_catalogue_and_body_len(fs_tree, media_types, &cat_len, &body_len);

    unsigned char pack_header[PACKAGE_HEADER_LEN];
    memset(pack_header, 0, sizeof(pack_header));

    // initial header population
    memcpy(offset_ptr(pack_header, PACKAGE_MAGIC_OFF), FORMAT_MAGIC, PACKAGE_MAGIC_LEN);
    uint16_t version = CURRENT_MAJOR_VERSION;
    copy_int_as_le(offset_ptr(pack_header, PACKAGE_VERSION_OFF), &version, PACKAGE_VERSION_LEN);
    if (real_opts->compression_type != NULL) {
        memcpy(offset_ptr(pack_header, PACKAGE_COMPRESSION_OFF), real_opts->compression_type, PACKAGE_COMPRESSION_LEN);
    }
    memcpy(offset_ptr(pack_header, PACKAGE_NAMESPACE_OFF), real_opts->pack_namespace, PACKAGE_NAMESPACE_LEN);

    free(media_types);

    return 0;
}
