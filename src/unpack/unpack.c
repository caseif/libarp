/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "arp/unpack/types.h"
#include "arp/unpack/unpack.h"
#include "internal/defines/file.h"
#include "internal/defines/misc.h"
#include "internal/unpack/types.h"
#include "internal/unpack/load_util.h"
#include "internal/unpack/unpack_util.h"
#include "internal/util/bt.h"
#include "internal/util/error.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#endif

int _unpack_node_to_fs(node_desc_t *node, const char *cur_dir,
        uint16_t *last_part_index, FILE **last_part);

int _unpack_node_to_fs(node_desc_t *node, const char *cur_dir,
        uint16_t *last_part_index, FILE **last_part) {
    int rc = UNINIT_U32;

    assert((last_part == NULL) == (last_part_index == NULL));

    arp_package_t *pack = node->package;

    if (node->type == PACK_NODE_TYPE_DIRECTORY) {
        size_t new_dir_path_len_s = strlen(cur_dir) + 1 + node->name_len_s + 1;
        size_t new_dir_path_len_b = new_dir_path_len_s + 1;

        char *new_dir_path = NULL;

        if (node->index == 0) {
            new_dir_path = strdup(cur_dir);
        } else {
            if ((new_dir_path = malloc(new_dir_path_len_b)) == NULL) {
                arp_set_error("malloc failed");
                return ENOMEM;
            }

            snprintf(new_dir_path, new_dir_path_len_b, "%s%c%s", cur_dir, FS_PATH_DELIMITER, node->name);
        }
        
        stat_t dir_stat;
        if (stat(new_dir_path, &dir_stat) != 0) {
            if (errno == ENOENT) {
                if (mkdir(new_dir_path, PERM_MASK_RWX_RX_RX) != 0) {
                    free(new_dir_path);

                    char err_msg[ERR_MSG_MAX_LEN];
                    snprintf(err_msg, ERR_MSG_MAX_LEN, "Failed to create directory (rc: %d)", errno);
                    arp_set_error(err_msg);
                    return errno;
                }
            } else {
                free(new_dir_path);

                char err_msg[ERR_MSG_MAX_LEN];
                snprintf(err_msg, ERR_MSG_MAX_LEN, "Failed to stat directory (rc: %d)", errno);
                arp_set_error(err_msg);
                return errno;
            }
        }

        node_desc_t **child_ptr = NULL;
        bt_reset_iterator(&node->children_tree);
        while ((child_ptr = (node_desc_t**) bt_iterate(&node->children_tree)) != NULL) {
            rc = _unpack_node_to_fs(*child_ptr, new_dir_path, last_part_index, last_part);
            if (rc != 0) {
                free(new_dir_path);

                return rc;
            }
        }

        free(new_dir_path);

        return 0;
    } else if (node->type == PACK_NODE_TYPE_RESOURCE) {
        if (node->part_index == 0 || node->part_index > pack->total_parts) {
            arp_set_error("Node part index is invalid");
            return -1;
        }

        if (last_part != NULL && *last_part != NULL && node->part_index != *last_part_index) {
            fclose(*last_part);
        }

        FILE *cur_part = NULL;

        if (last_part_index == NULL || node->part_index != *last_part_index) {
            if (last_part_index != NULL) {
                *last_part_index = node->part_index;
            }

            if ((cur_part = open_part_file_for_node(node)) == NULL) {
                return errno;
            }

            if (last_part != NULL) {
                *last_part = cur_part;
            }
        } else {
            cur_part = *last_part;
        }

        size_t res_path_len_s = strlen(cur_dir) + 1 + node->name_len_s + 1 + node->ext_len_s;
        size_t res_path_len_b = res_path_len_s + 1;

        char *res_path = NULL;
        if ((res_path = malloc(res_path_len_b)) == NULL) {
            if (last_part == NULL) {
                fclose(cur_part);
            }

            arp_set_error("malloc failed");
            return ENOMEM;
        }

        snprintf(res_path, res_path_len_b, "%s%c%s%c%s", cur_dir, FS_PATH_DELIMITER, node->name, '.', node->ext);

        FILE *res_file = NULL;
        if ((res_file = fopen(res_path, "w+b")) == NULL) {
            free(res_path);

            if (last_part == NULL) {
                fclose(cur_part);
            }

            arp_set_error("Failed to open output file for resource");
            return errno;
        }

        rc = unpack_node_data(node, res_file, NULL, NULL, NULL, cur_part);

        fclose(res_file);

        if (last_part == NULL) {
            fclose(cur_part);
        }

        if (rc != 0) {
            unlink(res_path);
            free(res_path);

            return rc;
        }

        free(res_path);

        return 0;
    } else {
        arp_set_error("Encountered invalid node type");
        return EINVAL;
    }
}

int arp_unpack_to_fs(ConstArpPackage package, const char *target_dir) {
    const arp_package_t *real_pack = (const arp_package_t*) package;

    if (real_pack->node_count == 0) {
        arp_set_error("Package does not contain any nodes");
        return -1;
    }

    FILE *last_part = NULL;
    uint16_t last_part_index = 0;

    int rc = _unpack_node_to_fs(real_pack->all_nodes[0], target_dir, &last_part_index, &last_part);

    if (last_part != NULL) {
        fclose(last_part);
    }

    return rc;
}

int arp_unpack_resource_to_fs(const arp_resource_meta_t *meta, const char *target_dir) {
    return _unpack_node_to_fs((node_desc_t*) meta->extra, target_dir, NULL, NULL);
}
