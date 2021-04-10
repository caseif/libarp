/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include "libarp/pack.h"

#include <stddef.h>

#define FS_NODE_TYPE_DIR 'd'
#define FS_NODE_TYPE_FILE 'f'
#define FS_NODE_TYPE_LINK 'l'

typedef struct ArpPackingOptions {
    char *pack_name;
    char *pack_namespace;
    size_t max_part_len;
    char compression_type[PACKAGE_COMPRESSION_LEN + 1];
    char *media_types_path;
} arp_packing_options_t;

typedef struct FsNode {
    unsigned char type;
    char *target_path;
    char *file_stem;
    char *file_ext;
    char *media_type;
    size_t size;
    struct FsNode **children;
    size_t children_count;

    uint64_t index;
    uint16_t part;
    uint64_t packed_data_len;
    uint64_t data_off;
    uint32_t crc;
} fs_node_t;

typedef fs_node_t *fs_node_ptr;

typedef const fs_node_t *const_fs_node_ptr;

typedef fs_node_ptr *fs_node_ptr_arr;

typedef struct PackageImportantSizes {
    uint64_t cat_len;
    uint32_t node_count;
    uint32_t directory_count;
    uint32_t resource_count;
    uint16_t part_count;
    uint64_t body_lens[PACKAGE_MAX_PARTS];
} package_important_sizes_t;
