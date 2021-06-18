#pragma once

#include "arp/unpack/types.h"

typedef struct ArpResource {
    arp_resource_meta_t meta;
    void *data;
} arp_resource_t;

int find_resource(ConstArpPackage package, const char *path, arp_resource_meta_t *out_meta);

int find_resource_in_set(ConstArpPackage package, const char *path, arp_resource_meta_t *out_meta);

arp_resource_t *load_resource(arp_resource_meta_t *meta);

void unload_resource(arp_resource_t *resource);
