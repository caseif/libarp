#pragma once

#include "internal/bt.h"

#include <stdint.h>

#define PACKAGE_EXT "arp"

#define FORMAT_MAGIC "\x1B\x41\x52\x47\x55\x53\x52\x50"

#define ENTRY_TYPE_RESOURCE 0
#define ENTRY_TYPE_DIRECTORY 1

#define PACKAGE_HEADER_LEN 0x100
#define PACKAGE_MAGIC_LEN 8
#define PACKAGE_VERSION_LEN 2
#define PACKAGE_COMPRESSION_LEN 2
#define PACKAGE_NAMESPACE_LEN 0x30
#define PACKAGE_PARTS_LEN 2
#define PACKAGE_CAT_OFF_LEN 8
#define PACKAGE_CAT_LEN_LEN 8
#define PACKAGE_CAT_CNT_LEN 4
#define PACKAGE_BODY_OFF_LEN 8
#define PACKAGE_BODY_LEN_LEN 8

#define PART_MAGIC "\x1B\x41\x52\x47\x55\x53\x50\x54"
#define PART_MAGIC_LEN 8
#define PART_INDEX_LEN 2

#define PACKAGE_PART_HEADER_LEN 0x10

#define COMPRESS_MAGIC_DEFLATE "df"

#define PACKAGE_MAX_PARTS 999

#define PACKAGE_PART_1_SUFFIX ".part001"

#define NODE_DESC_BASE_LEN 0x19
#define NODE_DESC_MIN_LEN 0x1B
#define NODE_NAME_MAX_LEN 0xFF
#define NODE_MIME_MAX_LEN 0xFF
#define NODE_DESC_MAX_LEN (NODE_DESC_MIN_LEN + NODE_NAME_MAX_LEN + NODE_MIME_MAX_LEN)

#define NODE_DESCRIPTOR_INDEX_LEN 4

#define NODE_TYPE_RESOURCE 0
#define NODE_TYPE_DIRECTORY 1

#define DIRECTORY_CONTENT_MAX_LEN 4294967296 * 4 // we need _some_ sane limit

#define NAMESPACE_DELIM ':'
#define PATH_DELIM '/'

typedef struct NodeDesc {
    uint8_t type;
    uint16_t part_index;
    uint64_t data_off;
    uint64_t data_len;
    uint32_t crc;
    uint8_t name_len_s;
    char *name;
    uint8_t mime_len_s;
    char *mime_type;

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

node_desc_t *create_dir_entry_dir(uint8_t name_length, char *name, uint64_t data_offset);

node_desc_t *create_dir_entry_res(uint8_t name_length, char *name, uint16_t part_index, uint64_t data_offset,
        uint64_t data_len, uint32_t crc);
