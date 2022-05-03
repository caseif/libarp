/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define DEFAULT_MEDIA_TYPE "application/octet-stream"

typedef void* ArpPackingOptions;

ArpPackingOptions arp_create_v1_packing_options(const char *pack_name, const char *pack_namespace, uint64_t max_part_len,
        const char *compression_type, const char *media_types_path);

void arp_free_packing_options(ArpPackingOptions opts);

int arp_pack_from_fs(const char *src_path, const char *target_dir, ArpPackingOptions opts,
        void (*msg_callback)(const char*));

#ifdef __cplusplus
}
#endif
