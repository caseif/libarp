/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include <string.h>

#include "internal/package_defines.h"

#define CMPR_ANY(magic) (strlen(magic) > 0)
#define CMPR_DEFLATE(magic) (strcmp(magic, ARP_COMPRESS_MAGIC_DEFLATE) == 0)

typedef void *DeflateStream;

DeflateStream compress_deflate_begin(size_t total_input_bytes);

int compress_deflate(DeflateStream stream, void *data, size_t data_len, void **out_data, size_t *out_data_len);

void compress_deflate_end(DeflateStream stream);

DeflateStream decompress_deflate_begin(size_t total_input_bytes, size_t total_output_bytes);

int decompress_deflate(DeflateStream stream, void *in_data, size_t in_data_len, void **out_data, size_t *out_data_len);

void decompress_deflate_end(DeflateStream stream);
