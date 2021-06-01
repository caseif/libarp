#pragma once

#include "libarp/unpack/types.h"

typedef struct ArpResource {
    arp_resource_meta_t meta;
    void *data;
} arp_resource_t;

int get_resource_meta(ConstArpPackage package, const char *path, arp_resource_meta_t *out_meta);

arp_resource_t *load_resource(arp_resource_meta_t *meta);

void unload_resource(arp_resource_t *resource);
