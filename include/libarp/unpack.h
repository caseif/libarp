/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include "libarp/common.h"

#include <stdlib.h>

typedef struct ArpResourceMeta {
    ArpPackage package;
    char *base_name;
    char *extension;
    char *media_type;
    size_t size;

    void *extra;
} arp_resource_meta_t;

typedef struct ArpResourceListing {
    arp_resource_meta_t meta;
    char *path;
} arp_resource_listing_t;

typedef struct ArpResource {
    arp_resource_meta_t meta;
    void *data;
} arp_resource_t;

int load_package_from_file(const char *path, ArpPackage *package);

int load_package_from_memory(const unsigned char *data, size_t package_len, ArpPackage *package);

int unload_package(ArpPackage package);

int get_resource_meta(ConstArpPackage package, const char *path, arp_resource_meta_t *out_meta);

arp_resource_t *load_resource(arp_resource_meta_t *meta);

void unload_resource(arp_resource_t *resource);

int unpack_arp_to_fs(ConstArpPackage package, const char *target_dir);

int get_resource_listing(ConstArpPackage package, arp_resource_listing_t **listing_out, size_t *count_out);

void free_resource_listing(arp_resource_listing_t *listing, size_t count);
