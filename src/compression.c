#include "internal/common_util.h"
#include "internal/compression.h"
#include "internal/util.h"

#include "zlib.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFLATE_CHUNK_LEN 262144 // 256K

typedef struct DeflateStream {
    size_t total_input_bytes;
    size_t processed_bytes;
    z_stream zlib_stream;
    unsigned char in_buf[DEFLATE_CHUNK_LEN];
    unsigned char out_buf[DEFLATE_CHUNK_LEN];
} deflate_stream_t;

DeflateStream compress_deflate_init(const size_t total_input_bytes) {
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
    size_t output_buf_len = (size_t) (data_len * 1.1L); // should be far more than enough

    void *output_buf = NULL;
    if ((output_buf = malloc(output_buf_len)) == NULL) {
        libarp_set_error("malloc failed");
        return ENOMEM;
    }

    size_t total_out_bytes = 0;
    size_t remaining = data_len;
    void *data_window = data;

    int rc = 0xDEADBEEF;
    while (remaining > 0) {
        size_t to_read = MIN(remaining, sizeof(real_stream->in_buf));
        printf("total: %d | processed: %d | to_read: %d\n", real_stream->total_input_bytes,
                real_stream->processed_bytes, to_read);
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
                printf("finish\n");
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

void compress_deflate_finish(DeflateStream stream) {
    deflate_stream_t *real_stream = (deflate_stream_t*) stream;

    deflateEnd(&real_stream->zlib_stream);
    free(real_stream);

    return;
}

int decompress_deflate(const void *compressed_data, size_t compressed_len, size_t final_len, void **out_data) {
    int rc = (int) 0xDEADBEEF;

    void *inflated_data = NULL;
    if ((inflated_data = malloc(final_len)) == NULL) {
        libarp_set_error("malloc failed");
        return ENOMEM;
    }

    z_stream defl_stream;
    defl_stream.zalloc = Z_NULL;
    defl_stream.zfree = Z_NULL;
    defl_stream.opaque = Z_NULL;
    defl_stream.avail_in = 0;
    defl_stream.next_in = Z_NULL;
    
    if ((rc = inflateInit(&defl_stream)) != Z_OK) {
        libarp_set_error("zlib: inflateInit failed");
        return -1;
    }

    size_t remaining = compressed_len;
    size_t bytes_decompressed = 0;
    const void *data_window = compressed_data;

    unsigned char dfl_out_buf[DEFLATE_CHUNK_LEN];

    while (remaining > 0) {
        size_t to_read = MIN(remaining, sizeof(dfl_out_buf));

        defl_stream.avail_in = to_read;
        defl_stream.next_in = (void*) data_window;

        remaining -= to_read;
        data_window = (void*) ((uintptr_t) data_window + to_read);

        do {
            defl_stream.avail_out = sizeof(dfl_out_buf);
            defl_stream.next_out = dfl_out_buf;

            rc = inflate(&defl_stream, Z_NO_FLUSH);
            switch (rc) {
                case Z_STREAM_END:
                    goto end_inflate_loop; // ew
                case Z_STREAM_ERROR:
                case Z_NEED_DICT:
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                default:
                    inflateEnd(&defl_stream);

                    free(inflated_data);

                    libarp_set_error("zlib: Inflate failed");
                    return -1;
            }

            size_t got_len = sizeof(dfl_out_buf) - defl_stream.avail_out;

            if (bytes_decompressed + got_len > final_len) {
                inflateEnd(&defl_stream);

                free(inflated_data);

                libarp_set_error("Decompressed data exceeds expected length");
                return -1;
            }

            memcpy((void*) ((uintptr_t) inflated_data + bytes_decompressed), dfl_out_buf, got_len);
            bytes_decompressed += got_len;
        } while (defl_stream.avail_out == 0);
    }
    
    end_inflate_loop:
    inflateEnd(&defl_stream);

    if (rc != Z_STREAM_END) {
        free(inflated_data);

        libarp_set_error("DEFLATE stream is incomplete");
        return -1;
    }

    *out_data = inflated_data;

    return 0;
}
