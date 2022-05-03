/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

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
