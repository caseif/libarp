#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "arp/unpack/types.h"

typedef struct ArpResource {
    arp_resource_meta_t meta;
    void *data;
} arp_resource_t;

int arp_find_resource(ConstArpPackage package, const char *path, arp_resource_meta_t *out_meta);

int arp_find_resource_in_set(ConstArpPackageSet set, const char *path, arp_resource_meta_t *out_meta);

arp_resource_t *arp_load_resource(arp_resource_meta_t *meta);

void arp_unload_resource(arp_resource_t *resource);

#ifdef __cplusplus
}
#endif
