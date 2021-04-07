#include "internal/common_util.h"
#include "internal/compression.h"
#include "internal/util.h"

#include "zlib.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define DEFLATE_CHUNK_LEN 262144 // 256K

int compress_deflate(void) {
    //TODO
    return 0;
}

int decompress_deflate(const void *compressed_data, size_t compressed_len, size_t final_len, void **output_buf) {
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
        libarp_set_error("zlib inflateInit failed");
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

        while (defl_stream.avail_out == 0) {
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

                    libarp_set_error("zlib inflate failed");
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
        }
    }
    
    end_inflate_loop:
    inflateEnd(&defl_stream);

    if (rc != Z_STREAM_END) {
        free(inflated_data);

        libarp_set_error("DEFLATE stream is incomplete");
        return -1;
    }

    *output_buf = inflated_data;

    return 0;
}
