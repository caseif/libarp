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

#include "arp/unpack/types.h"

#include <stddef.h>

#define ARP_STREAM_EOF ((int32_t) 0xDEADDEAD)

typedef void *ArpResourceStream;

ArpResourceStream arp_create_resource_stream(arp_resource_meta_t *meta, size_t chunk_len);

int arp_stream_resource(ArpResourceStream stream, void **out_data, size_t *out_data_len);

void arp_free_resource_stream(ArpResourceStream stream);

#ifdef __cplusplus
}
#endif
