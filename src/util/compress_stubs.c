/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/defines/misc.h"
#include "internal/util/compress.h"
#include "internal/util/error.h"

#include <errno.h>

#ifndef FEATURE_DEFLATE
DeflateStream compress_deflate_begin(uint64_t total_input_bytes) {
    arp_set_error(DEFLATE_SUPPORT_ERROR);
    errno = -1;
    return NULL;
}

int compress_deflate(DeflateStream stream, void *data, size_t data_len, void **out_data, size_t *out_data_len) {
    arp_set_error(DEFLATE_SUPPORT_ERROR);
    return -1;
}

void compress_deflate_end(DeflateStream stream) {
    arp_set_error(DEFLATE_SUPPORT_ERROR);
    errno = -1;
}

DeflateStream decompress_deflate_begin(uint64_t total_input_bytes, uint64_t total_output_bytes) {
    arp_set_error(DEFLATE_SUPPORT_ERROR);
    errno = -1;
    return NULL;
}

int decompress_deflate(DeflateStream stream, void *in_data, size_t in_data_len, void **out_data, size_t *out_data_len) {
    arp_set_error(DEFLATE_SUPPORT_ERROR);
    return -1;
}

void decompress_deflate_end(DeflateStream stream) {
    arp_set_error(DEFLATE_SUPPORT_ERROR);
    errno = -1;
}
#endif
