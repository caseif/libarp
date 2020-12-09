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
#include "internal/file_defines.h"
#include "internal/package_defines.h"
#include "internal/pack_util.h"
#include "internal/util.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CURRENT_MAJOR_VERSION 1

ArpPackingOptions create_v1_packing_options(const char *pack_name, const char *pack_namespace, size_t max_part_len,
        const char *compression_type, link_behavior_t link_behavior) {

    size_t name_len_s = strlen(pack_name);
    size_t namespace_len_s = strlen(pack_namespace);
    size_t compression_type_len_s = strlen(compression_type);

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

    if (compression_type_len_s != PACKAGE_COMPRESSION_LEN) {
        libarp_set_error("Compression type magic length is incorrect");
        return NULL;
    }

    arp_packing_options_t *opts = calloc(1, sizeof(arp_packing_options_t));
    opts->pack_name = calloc(1, name_len_s + 1);
    opts->pack_namespace = calloc(1, PACKAGE_NAMESPACE_LEN + 1);
    opts->compression_type = calloc(1, PACKAGE_COMPRESSION_LEN + 1);

    memcpy(opts->pack_name, pack_name, name_len_s + 1);
    memcpy(opts->pack_namespace, pack_name, namespace_len_s + 1);
    memcpy(opts->compression_type, pack_name, compression_type_len_s + 1);

    opts->max_part_len = max_part_len;
    opts->link_behavior = link_behavior;

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

    free(real_opts);
}

static void _free_fs_node(fs_node_t *node) {
    if (node == NULL) {
        return;
    }

    if (node->name != NULL) {
        free(node->name);
    }

    if (node->type == FS_NODE_TYPE_LINK && node->link_target != NULL) {
        free(node->link_target);
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

#ifdef _WIN32
static fs_node_t *_create_fs_tree(const char *root_path, link_behavior_t link_behavior) {
    WIN32_FIND_DATAA find_data;

    HANDLE find_handle = FindFirstFileA(root_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    do {
        //TODO
    } while (FindNextFileA(find_handle, &find_data) != 0);
}
#else
static fs_node_t *_create_fs_tree(const char *root_path, link_behavior_t link_behavior) {
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
    // we explicitly set the name to null - the caller will set it if necessary
    node->name = NULL;

    char *child_full_path;
    if ((child_full_path = malloc(strlen(root_path) + 1 + NAME_MAX + 1)) == NULL) {
        free(node);

        libarp_set_error("malloc failed");
        return NULL;
    }

    size_t dir_count = 0;

    struct dirent *de;
    while ((de = readdir(root)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }

        stat_t child_stat;
        stat(child_full_path, &child_stat);

        if (S_ISDIR(child_stat.st_mode) || S_ISREG(child_stat.st_mode)
                || (S_ISLNK(child_stat.st_mode) && link_behavior != LB_IGNORE)) {
            dir_count++;
        }
    }

    node->children_count = dir_count;
    if ((node->children = malloc(sizeof(void*) * dir_count)) == NULL) {
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

        sprintf(child_full_path, "%s/%s", root_path, de->d_name);

        stat_t child_stat;
        stat(child_full_path, &child_stat);

        fs_node_t *child_node;
        if (S_ISDIR(child_stat.st_mode)) {
            child_node = _create_fs_tree(child_full_path, link_behavior);
        } else if (S_ISREG(child_stat.st_mode)) {
            child_node = malloc(sizeof(fs_node_t));
            child_node->type = FS_NODE_TYPE_FILE;
        } else if (S_ISLNK(child_stat.st_mode)) {
            if (link_behavior == LB_IGNORE) {
                continue;
            }

            child_node = malloc(sizeof(fs_node_t));
            child_node->type = FS_NODE_TYPE_LINK;

            char *link_target = realpath(child_full_path, NULL);

            if ((child_node->link_target = malloc(strlen(link_target))) == NULL) {
                free(link_target);
                free(child_node);
                free(child_full_path);
                _free_fs_node(node);

                libarp_set_error("malloc failed");
                return NULL;
            }

            memcpy(child_node->link_target, link_target, strlen(link_target) + 1);

            free(link_target);
        }

        if ((child_node->name = malloc(strlen(de->d_name) + 1)) == NULL) {
            free(child_node);
            free(child_full_path);
            _free_fs_node(node);

            libarp_set_error("malloc failed");
            return NULL;
        }

        memcpy(child_node->name, de->d_name, strlen(de->d_name) + 1);

        node->children[child_index] = child_node;

        child_index++;
    }

    free(child_full_path);

    closedir(root);

    return node;
}
#endif

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

static size_t _compute_catalogue_len(fs_node_t *fs_root) {
    //TODO
    return 0;
}

int create_arp_from_fs(const char *src_path, const char *target_dir, ArpPackingOptions opts) {
    arp_packing_options_t *real_opts = (arp_packing_options_t*) opts;

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

    fs_node_t *fs_tree = _create_fs_tree(src_path, real_opts->link_behavior);

    return 0;
}
