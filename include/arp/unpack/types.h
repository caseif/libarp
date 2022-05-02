#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "arp/util/defines.h"

#include <stdint.h>

typedef void *ArpPackage;
typedef const void *ConstArpPackage;

typedef void *ArpPackageSet;
typedef const void *ConstArpPackageSet;

typedef union ArpPackageMeta {
    struct {
        uint16_t major_version;
        char compression_type[PACKAGE_COMPRESSION_LEN + 1];
        char package_namespace[PACKAGE_NAMESPACE_LEN + 1];
        uint16_t total_parts;
        uint64_t cat_off;
        uint64_t cat_len;
        uint32_t node_count;
        uint32_t directory_count;
        uint32_t resource_count;
        uint64_t body_off;
        uint64_t body_len;
    };
    // Reserve space to allow new members for metadata that might exist in
    // future ARP revisions, and over-reserve to account for null-terminators
    // and other "padding" that might be necessary for said new members.
    unsigned char reserved[384];
} arp_package_meta_t;

typedef struct ArpResourceMeta {
    ArpPackage package;
    char *base_name;
    char *extension;
    char *media_type;
    uint64_t size;

    void *extra;
} arp_resource_meta_t;

#ifdef __cplusplus
}
#endif
