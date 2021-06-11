#pragma once

#include <stdint.h>

typedef void *ArpPackage;
typedef const void *ConstArpPackage;

typedef void *ArpPackageSet;
typedef const void *ConstArpPackageSet;

typedef struct ArpResourceMeta {
    ArpPackage package;
    char *base_name;
    char *extension;
    char *media_type;
    uint64_t size;

    void *extra;
} arp_resource_meta_t;
