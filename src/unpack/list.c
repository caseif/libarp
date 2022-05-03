/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "arp/util/defines.h"
#include "arp/unpack/list.h"
#include "arp/unpack/unpack.h"
#include "internal/defines/misc.h"
#include "internal/unpack/types.h"
#include "internal/util/error.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static int _list_node_contents(node_desc_t *node, const char *pack_ns, const char *running_path,
        arp_resource_listing_t *listing_arr, size_t *cur_off);

static int _list_node_contents(node_desc_t *node, const char *pack_ns, const char *running_path,
        arp_resource_listing_t *listing_arr, size_t *cur_off) {
    if (*cur_off == SIZE_MAX) {
        arp_set_error("Too many nodes");
        return -1;
    }

    if (node->type == PACK_NODE_TYPE_RESOURCE) {
        size_t path_len_s = strlen(running_path)
                + node->name_len_s;
        size_t path_len_b = path_len_s + 1;

        char *buf = NULL;
        if ((buf = malloc(path_len_b)) == NULL) {
            arp_set_error("malloc failed");
            return ENOMEM;
        }

        char *path = buf;
        snprintf(path, path_len_b, "%s%s", running_path, node->name);

        arp_resource_listing_t *listing = &listing_arr[*cur_off];
        *cur_off += 1;

        listing->path = path;
        listing->meta.base_name = node->name;
        listing->meta.extension = node->ext;
        listing->meta.media_type = node->media_type;

        return 0;
    } else if (node->type == PACK_NODE_TYPE_DIRECTORY) {
        char *base_running_path = NULL;

        if (running_path != NULL) {
            base_running_path = strdup(running_path);
        } else {
            size_t brp_len_s = strlen(pack_ns) + 2;
            base_running_path = malloc(brp_len_s);
            snprintf(base_running_path, brp_len_s, "%s%c", pack_ns, ARP_NAMESPACE_DELIMITER);
        }

        int rc = UNINIT_U32;

        node_desc_t **child_ptr = NULL;
        bt_reset_iterator(&node->children_tree);
        while ((child_ptr = (node_desc_t**) bt_iterate(&node->children_tree)) != NULL) {
            node_desc_t *child = *child_ptr;

            if (child == NULL) {
                continue;
            }

            char *new_running_path = base_running_path;

            if (child->name != NULL && strlen(child->name) > 0) {
                if (child->type == PACK_NODE_TYPE_DIRECTORY) {
                    char *child_name = child->name != NULL ? child->name : "";

                    size_t new_rp_len_s = strlen(base_running_path) + 1 + strlen(child_name);
                    size_t new_rp_len_b = new_rp_len_s + 1;

                    if ((new_running_path = malloc(new_rp_len_b)) == NULL) {
                        if (base_running_path != running_path) {
                            free(base_running_path);
                        }

                        arp_set_error("malloc failed");
                        return ENOMEM;
                    }

                    snprintf(new_running_path, new_rp_len_b, "%s%s%c", base_running_path, child_name,
                            ARP_PATH_DELIMITER);
                }
            }

            rc = _list_node_contents(child, pack_ns, new_running_path,
                    listing_arr, cur_off);

            if (new_running_path != base_running_path) {
                free(new_running_path);
            }

            if (rc != 0) {
                free(base_running_path);
                return rc;
            }
        }

        if (base_running_path != running_path) {
            free(base_running_path);
        }

        return 0;
    } else {
        arp_set_error("Unrecognized node type");
        return -1;
    }
}

int arp_get_resource_listing(ConstArpPackage package, arp_resource_listing_t **listing_arr_out, size_t *count_out) {
    *listing_arr_out = NULL;
    *count_out = 0;

    if (package == NULL) {
        arp_set_error("Package cannot be null");
        return -1;
    }

    const arp_package_t *real_pack = (const arp_package_t*) package;

    if (real_pack->resource_count == 0) {
        arp_set_error("Package contains no resources");
        return -1;
    }

    node_desc_t *root_node = real_pack->all_nodes[0];
    if (root_node->type != PACK_NODE_TYPE_DIRECTORY) {
        arp_set_error("Root package node is not a directory");
        return -1;
    }

    arp_resource_listing_t *listing_arr = NULL;
    if ((listing_arr = calloc(real_pack->resource_count, sizeof(arp_resource_listing_t))) == NULL) {
        arp_set_error("calloc failed");
        return ENOMEM;
    }

    int rc = UNINIT_U32;

    size_t cur_off = 0;
    if ((rc = _list_node_contents(real_pack->all_nodes[0], real_pack->package_namespace, NULL, listing_arr, &cur_off)) != 0) {
        free(listing_arr);
        
        return rc;
    }

    *listing_arr_out = listing_arr;
    *count_out = cur_off;

    return 0;
}

void arp_free_resource_listing(arp_resource_listing_t *listing, size_t count) {
    if (listing == NULL) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        if (listing->path != NULL) {
            free(listing->path);
            listing->path = NULL; // not required but for some reason clang throws a warning without it
        }
    }

    free(listing);
}
