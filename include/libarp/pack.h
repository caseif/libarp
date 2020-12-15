/*
 * This file is a part of libarp.
 * Copyright (c) 2020, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include "libarp/common.h"

typedef void* ArpPackingOptions;

typedef enum LinkBehavior {
    LB_LINK,
    LB_COPY,
    LB_IGNORE,
} link_behavior_t;

ArpPackingOptions create_v1_packing_options(const char *pack_name, const char *pack_namespace, size_t max_part_len,
        const char *compression_type, link_behavior_t link_behavior);

void release_packing_options(ArpPackingOptions opts);

int create_arp_from_fs(const char *src_path, const char *target_dir, ArpPackingOptions opts);
