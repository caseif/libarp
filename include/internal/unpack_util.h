#pragma once

#include "libarp/common.h"
#include "internal/package_defines.h"

#include <stddef.h>
#include <stdint.h>

typedef struct NodeDesc {
    uint8_t type;
    uint16_t part_index;
    uint64_t data_off;
    uint64_t data_len;
    uint64_t data_uc_len;
    uint32_t crc;
    uint8_t name_len_s;
    uint8_t ext_len_s;
    uint8_t media_type_len_s;
    char *name;
    char *ext;
    char *media_type;

    arp_resource_t *loaded_data;
    bt_node_t *children_tree;
} node_desc_t;

typedef struct ArgusPack {
    uint16_t major_version;
    char compression_type[PACKAGE_COMPRESSION_LEN + 1];
    char package_namespace[PACKAGE_NAMESPACE_LEN + 1];
    uint16_t total_parts;
    uint64_t cat_off;
    uint64_t cat_len;
    uint32_t node_count;
    uint64_t body_off;
    uint64_t body_len;
    node_desc_t **all_nodes;
    char **part_paths;
} argus_package_t;
