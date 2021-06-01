/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/util/common.h"
#include "internal/util/compress.h"
#include "internal/util/error.h"
#include "internal/defines/misc.h"

#include "zlib.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFLATE_CHUNK_LEN 262144 // 256K

#define DEFLATE_BUF_MARGIN 1.1L

typedef struct DeflateStream {
    uint64_t total_input_bytes;
    uint64_t total_output_bytes;
    uint64_t processed_bytes;
    z_stream zlib_stream;
    unsigned char in_buf[DEFLATE_CHUNK_LEN];
    unsigned char out_buf[DEFLATE_CHUNK_LEN];
} deflate_stream_t;

DeflateStream compress_deflate_begin(const uint64_t total_input_bytes) {
    deflate_stream_t *stream = NULL;
    if ((stream = malloc(sizeof(deflate_stream_t))) == NULL) {
        libarp_set_error("malloc failed");
        return NULL;
    }

    stream->total_input_bytes = total_input_bytes;
    stream->processed_bytes = 0;

    stream->zlib_stream.zalloc = Z_NULL;
    stream->zlib_stream.zfree = Z_NULL;
    stream->zlib_stream.opaque = Z_NULL;
    int rc = deflateInit(&stream->zlib_stream, Z_DEFAULT_COMPRESSION);
    if (rc != Z_OK) {
        free(stream);

        libarp_set_error("zlib: deflateInit failed");
        errno = rc;
        return NULL;
    }

    return stream;
}

int compress_deflate(DeflateStream stream, void *data, size_t data_len, void **out_data, size_t *out_data_len) {
    deflate_stream_t *real_stream = (deflate_stream_t*) stream;

    // we don't really need precision here, we just need the result to be roughly a certain margin larger
    size_t output_buf_len = (size_t) (data_len * DEFLATE_BUF_MARGIN); // should be far more than enough
    // just in case it overflows
    if (output_buf_len < data_len) {
        output_buf_len = data_len;
    }

    void *output_buf = NULL;
    if ((output_buf = malloc(output_buf_len)) == NULL) {
        libarp_set_error("malloc failed");
        return ENOMEM;
    }

    size_t total_out_bytes = 0;
    size_t remaining = data_len;
    void *data_window = data;

    int rc = UNINIT_U32;
    while (remaining > 0) {
        size_t to_read = MIN(remaining, sizeof(real_stream->in_buf));
        assert(real_stream->processed_bytes + to_read <= real_stream->total_input_bytes);
        
        real_stream->zlib_stream.avail_in = to_read;
        real_stream->zlib_stream.next_in = data_window;

        remaining -= to_read;
        data_window = (void*) ((uintptr_t) data_window + to_read);

        real_stream->zlib_stream.avail_out = sizeof(real_stream->out_buf);
        real_stream->zlib_stream.next_out = real_stream->out_buf;

        do {
            int flush = Z_NO_FLUSH;
            if (real_stream->processed_bytes + to_read == real_stream->total_input_bytes) {
                flush = Z_FINISH;
            }

            rc = deflate(&real_stream->zlib_stream, flush);
            assert(rc != Z_STREAM_ERROR);

            size_t out_bytes = sizeof(real_stream->out_buf) - real_stream->zlib_stream.avail_out;

            if (out_bytes + total_out_bytes > output_buf_len) {
                // I don't think this should ever run, but just in case...
                output_buf_len += DEFLATE_CHUNK_LEN;
                void *output_buf_new = NULL;
                if ((output_buf_new = realloc(output_buf, output_buf_len)) == NULL) {
                    free(output_buf);

                    libarp_set_error("realloc failed");
                    return ENOMEM;
                }

                output_buf = output_buf_new;
            }

            memcpy((void*) ((uintptr_t) output_buf + total_out_bytes), real_stream->out_buf, out_bytes);

            total_out_bytes += out_bytes;
            real_stream->processed_bytes += to_read;
        } while (real_stream->zlib_stream.avail_out == 0);

        assert(real_stream->zlib_stream.avail_in == 0);
    }

    if (real_stream->processed_bytes == real_stream->total_input_bytes) {
        assert(rc == Z_STREAM_END);
    }

    *out_data = output_buf;
    *out_data_len = total_out_bytes;

    return 0;
}

void compress_deflate_end(DeflateStream stream) {
    deflate_stream_t *real_stream = (deflate_stream_t*) stream;

    deflateEnd(&real_stream->zlib_stream);
    free(real_stream);
}

DeflateStream decompress_deflate_begin(const uint64_t total_input_bytes, const uint64_t total_output_bytes) {
    deflate_stream_t *stream = NULL;
    if ((stream = malloc(sizeof(deflate_stream_t))) == NULL) {
        libarp_set_error("malloc failed");
        return NULL;
    }

    stream->total_input_bytes = total_input_bytes;
    stream->total_output_bytes = total_output_bytes;
    stream->processed_bytes = 0;

    stream->zlib_stream.zalloc = Z_NULL;
    stream->zlib_stream.zfree = Z_NULL;
    stream->zlib_stream.opaque = Z_NULL;
    stream->zlib_stream.avail_in = 0;
    stream->zlib_stream.next_in = Z_NULL;

    int rc = UNINIT_U32;
    if ((rc = inflateInit(&stream->zlib_stream)) != Z_OK) {
        free(stream);

        errno = rc;
        libarp_set_error("zlib: inflateInit failed");
        return NULL;
    }

    return stream;
}

int decompress_deflate(DeflateStream stream, void *in_data, size_t in_data_len, void **out_data, size_t *out_data_len) {
    int rc = UNINIT_U32;

    deflate_stream_t *real_stream = (deflate_stream_t*) stream;

    size_t remaining = in_data_len;
    size_t total_out_bytes = 0;
    const void *data_window = in_data;

    size_t output_buf_len = in_data_len * 2;
    void *output_buf = NULL;
    if ((output_buf = malloc(output_buf_len)) == NULL) {
        libarp_set_error("malloc failed");
        return ENOMEM;
    }

    z_stream *defl_stream = &real_stream->zlib_stream;

    bool at_end = false;

    while (remaining > 0) {
        size_t to_read = MIN(remaining, sizeof(real_stream->out_buf));

        defl_stream->avail_in = to_read;
        defl_stream->next_in = (void*) data_window;

        remaining -= to_read;
        data_window = (void*) ((uintptr_t) data_window + to_read);

        do {
            defl_stream->avail_out = sizeof(real_stream->out_buf);
            defl_stream->next_out = real_stream->out_buf;

            rc = inflate(defl_stream, Z_NO_FLUSH);
            switch (rc) {
                case Z_OK:
                case Z_BUF_ERROR:
                    break;
                case Z_STREAM_END:
                    if (remaining > 0) {
                        free(output_buf);

                        libarp_set_error("Encountered premature end of DEFLATE stream");
                        return -1;
                    }
                    at_end = true;
                    break;
                case Z_STREAM_ERROR:
                case Z_NEED_DICT:
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                default:
                    free(output_buf);

                    libarp_set_error("zlib: Inflate failed");
                    return rc;
            }

            size_t out_bytes = sizeof(real_stream->out_buf) - defl_stream->avail_out;

            if (real_stream->total_output_bytes != 0
                    && total_out_bytes + out_bytes > real_stream->total_output_bytes) {
                free(output_buf);

                libarp_set_error("Decompressed data exceeds expected length");
                return -1;
            }

            if (total_out_bytes + out_bytes > output_buf_len) {
                output_buf_len += DEFLATE_CHUNK_LEN;
                void *output_buf_new = NULL;
                if ((output_buf_new = realloc(output_buf, output_buf_len)) == NULL) {
                    free(output_buf);

                    libarp_set_error("realloc failed");
                    return ENOMEM;
                }

                output_buf = output_buf_new;
            }

            memcpy((void*) ((uintptr_t) output_buf + total_out_bytes), real_stream->out_buf, out_bytes);
            total_out_bytes += out_bytes;

            if (at_end || remaining == 0) {
                goto end_inflate_loop; // ew
            }
        } while (defl_stream->avail_out > 0);
    }

    end_inflate_loop:

    if (real_stream->total_output_bytes != 0
            && real_stream->processed_bytes == real_stream->total_output_bytes && !at_end) {
        free(output_buf);

        libarp_set_error("DEFLATE stream is incomplete");
        return -1;
    }

    *out_data = output_buf;
    *out_data_len = total_out_bytes;

    return 0;
}

void decompress_deflate_end(DeflateStream stream) {
    deflate_stream_t *real_stream = (deflate_stream_t*) stream;

    inflateEnd(&real_stream->zlib_stream);

    free(real_stream);
}
