#include "libarp/unpack/set.h"
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

ArpPackageSet create_package_set(void) {
    arp_package_set_t *set = NULL;
    if ((set = malloc(sizeof(arp_package_set_t))) == NULL) {
        libarp_set_error("malloc failed");
        errno = ENOMEM;
        return NULL;
    }
    
    if (bt_create(INITIAL_SET_CAP, &set->tree) == NULL) {
        free(set);

        libarp_set_error("Failed to create binary tree");
        return NULL;
    }

    return set;
}

int add_package_to_set(ArpPackageSet set, ArpPackage package) {
    arp_package_set_t *real_set = (arp_package_set_t*) set;
    if (!bt_insert_distinct(&real_set->tree, package, (BtInsertCmpFn) _package_cmp_fn)) {
        libarp_set_error("Set contains package with identical namespace");
        return -1;
    }

    return 0;
}

void remove_package_from_set(ArpPackageSet set, ArpPackage package) {
    arp_package_set_t *real_set = (arp_package_set_t*) set;
    bt_remove(&real_set->tree, package, (BtInsertCmpFn) _package_cmp_fn);
}

void destroy_package_set(ArpPackageSet set) {
    arp_package_set_t *real_set = (arp_package_set_t*) set;

    bt_free(&real_set->tree);

    free(real_set);
}
