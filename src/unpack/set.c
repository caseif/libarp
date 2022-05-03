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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_SET_CAP 16

static int _package_cmp_fn(const arp_package_t *a, const arp_package_t *b) {
    return strncmp(a->package_namespace, b->package_namespace, sizeof(a->package_namespace));
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
    if (!bt_insert_distinct(&real_set->tree, package, (BtInsertCmpFn) _package_cmp_fn)) {
        arp_set_error("Set contains package with identical namespace");
        return -1;
    }

    return 0;
}

void arp_remove_from_set(ArpPackageSet set, ArpPackage package) {
    arp_package_set_t *real_set = (arp_package_set_t*) set;
    bt_remove(&real_set->tree, package, (BtInsertCmpFn) _package_cmp_fn);
}

int arp_unload_set_packages(ArpPackageSet set) {
    arp_package_set_t *real_set = (arp_package_set_t*) set;
    
    int rc = 0;
    arp_package_t **pack;
    bt_reset_iterator(&real_set->tree);
    while ((pack = (arp_package_t**) bt_iterate(&real_set->tree)) != NULL) {
        int rc_temp = arp_unload(*pack);
        if (rc_temp != 0) {
            rc = rc_temp;
        }
    }

    return rc;
}

void arp_destroy_set(ArpPackageSet set) {
    arp_package_set_t *real_set = (arp_package_set_t*) set;

    bt_free(&real_set->tree);

    free(real_set);
}
