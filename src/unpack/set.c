/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "arp/unpack/load.h"
#include "arp/unpack/set.h"
#include "internal/defines/misc.h"
#include "internal/unpack/types.h"
#include "internal/util/bt.h"
#include "internal/util/error.h"
#include "internal/util/ll.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_SET_CAP 16

static int _cmp_pack_ll_head_to_pack_ll_head(const linked_list_t *a, const linked_list_t *b) {
    arp_package_t *real_pack_a = (arp_package_t*) ((linked_list_t*) a)->data;
    arp_package_t *real_pack_b = (arp_package_t*) ((linked_list_t*) b)->data;
    return strncmp(real_pack_a->package_namespace, real_pack_b->package_namespace, sizeof(real_pack_b->package_namespace));
}

static int _cmp_pack_to_pack_ll_head(const arp_package_t *pack, const linked_list_t *ll) {
    arp_package_t *real_pack = (arp_package_t*) ((linked_list_t*) ll)->data;
    return strncmp(pack->package_namespace, real_pack->package_namespace, sizeof(real_pack->package_namespace));
}

ArpPackageSet arp_create_set(void) {
    arp_package_set_t *set = NULL;
    if ((set = malloc(sizeof(arp_package_set_t))) == NULL) {
        arp_set_error("malloc failed");
        errno = ENOMEM;
        return NULL;
    }
    
    if (bt_create(INITIAL_SET_CAP, &set->tree) == NULL) {
        free(set);

        arp_set_error("Failed to create binary tree");
        return NULL;
    }

    return set;
}

int arp_add_to_set(ArpPackageSet set, ArpPackage package) {
    arp_package_set_t *real_set = (arp_package_set_t*) set;

    linked_list_t *existing = bt_find(&real_set->tree, package, (BtFindCmpFn) _cmp_pack_to_pack_ll_head);

    if (existing != NULL) {
        ll_push_back(existing, package);
    } else {
        bt_insert(&real_set->tree, ll_create(package), (BtInsertCmpFn) _cmp_pack_ll_head_to_pack_ll_head);
    }

    return 0;
}

void arp_remove_from_set(ArpPackageSet set, ArpPackage package) {
    arp_package_set_t *real_set = (arp_package_set_t*) set;

    linked_list_t *existing = bt_find(&real_set->tree, package, (BtFindCmpFn) _cmp_pack_to_pack_ll_head);

    if (existing != NULL) {
        ll_remove(existing, package);
        if (existing->data == NULL) {
            // remove the list from the tree if it's now empty
            bt_remove(&real_set->tree, existing, (BtFindCmpFn) _cmp_pack_ll_head_to_pack_ll_head);
            ll_free(existing);
        }
    }

}

int arp_unload_set_packages(ArpPackageSet set) {
    arp_package_set_t *real_set = (arp_package_set_t*) set;
    
    int rc = 0;
    linked_list_t **ll;
    bt_reset_iterator(&real_set->tree);
    while ((ll = (linked_list_t**) bt_iterate(&real_set->tree)) != NULL) {
        while (ll != NULL) {
            arp_package_t *pack = (arp_package_t*) (*ll)->data;
            int rc_temp = arp_unload(pack);
            if (rc_temp != 0) {
                rc = rc_temp;
            }
            ll = (*ll)->next != NULL ? &(*ll)->next : NULL;
        }
    }

    return rc;
}

void arp_destroy_set(ArpPackageSet set) {
    arp_package_set_t *real_set = (arp_package_set_t*) set;

    linked_list_t **ll;
    bt_reset_iterator(&real_set->tree);
    while ((ll = (linked_list_t**) bt_iterate(&real_set->tree)) != NULL) {
        ll_free(*ll);
    }

    bt_free(&real_set->tree);

    free(real_set);
}
