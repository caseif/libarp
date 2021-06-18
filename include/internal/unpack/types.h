/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include "arp/unpack/resource.h"
#include "arp/unpack/unpack.h"
#include "internal/defines/misc.h"
#include "internal/defines/package.h"
#include "internal/util/bt.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// forward decl
struct ArpPackageStruct;

typedef struct NodeDesc {
    struct ArpPackageStruct *package;

    uint8_t type;
    uint16_t part_index;
    uint64_t data_off;
    uint64_t packed_data_len;
    uint64_t unpacked_data_len;
    uint32_t crc;
    uint8_t name_len_s;
    uint8_t ext_len_s;
    uint8_t media_type_len_s;
    char *name;
    char *ext;
    char *media_type;

    uint64_t index;
    void *loaded_data;
    binary_tree_t children_tree;
} node_desc_t;

typedef struct ArpPackageSetStruct {
    binary_tree_t tree;
} arp_package_set_t;

typedef struct ArpPackageStruct {
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
    node_desc_t **all_nodes;
    char **part_paths;
} arp_package_t;

typedef struct ArpResourceStream {
    // intrinsic properties
    size_t chunk_len;
    arp_resource_meta_t meta;

    // buffers
    void *read_buf; // length == chunk_len
    void *prim_buf; // length == chunk_len
    void *sec_buf; // length == chunk_len
    void *tert_buf; // length == chunk_len
    void *overflow_buf; // length == variable
    size_t overflow_len;
    size_t overflow_cap;

    // state
    FILE *file;
    uint64_t base_off;
    uint64_t packed_pos; // total number of packed bytes read
    uint64_t unpacked_pos; // total number of unpacked bytes read, including data written to overflow_buf
    unsigned char next_buf; // the next buffer to load data into
    void *compression_data;
} arp_resource_stream_t;
