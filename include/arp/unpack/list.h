#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "arp/unpack/types.h"

#include <stddef.h>

typedef struct ArpResourceListing {
    arp_resource_meta_t meta;
    char *path;
} arp_resource_listing_t;

int arp_get_resource_listing(ConstArpPackage package, arp_resource_listing_t **listing_out, size_t *count_out);

void arp_free_resource_listing(arp_resource_listing_t *listing, size_t count);

#ifdef __cplusplus
}
#endif
