#pragma once

#include <stdint.h>

#define FORMAT_MAGIC "\x1B\x41\x52\x47\x55\x53\x52\x50"
#define PART_MAGIC "\x1B\x41\x52\x47\x55\x53\x50\x54"

#define ENTRY_TYPE_RESOURCE 0
#define ENTRY_TYPE_DIRECTORY 1

#define PACKAGE_HEADER_LEN 256
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

#define COMPRESS_MAGIC_DEFLATE "df"

#define PACKAGE_MAX_PARTS 999

typedef struct {
    uint16_t major_version;
    char compression_type[PACKAGE_COMPRESSION_LEN];
    char package_namespace[PACKAGE_NAMESPACE_LEN];
    uint16_t total_parts;
    uint64_t cat_off;
    uint64_t cat_len;
    uint64_t node_count;
    uint64_t body_off;
    uint64_t body_len;
} argus_package_t;

typedef struct {
    uint8_t name_length;
    uint8_t entry_type;
    uint16_t part_index;
    uint64_t data_offset;
    uint64_t data_length;
    uint32_t crc;
    char entry_name[];
} dir_entry_t;

dir_entry_t *create_dir_entry_dir(uint8_t name_length, char *name, uint64_t data_offset);

dir_entry_t *create_dir_entry_res(uint8_t name_length, char *name, uint16_t part_index, uint64_t data_offset,
        uint64_t data_len, uint32_t crc);
