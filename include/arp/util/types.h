#pragma once

#include "arp/util/defines.h"

#include <stdint.h>

typedef struct ArpPackageMeta {
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
} arp_package_meta_t;
