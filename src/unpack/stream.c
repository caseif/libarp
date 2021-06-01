#include "libarp/util/error.h"
#include "libarp/unpack/stream.h"
#include "libarp/unpack/types.h"
#include "internal/unpack/load_util.h"
#include "internal/unpack/types.h"
#include "internal/util/common.h"
#include "internal/util/compress.h"
#include "internal/util/error.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define IO_BUFFER_LEN (128 * 1024) // 128 KB

#define DEFLATE_BUF_MARGIN 1.05L

ArpResourceStream create_resource_stream(arp_resource_meta_t *meta, size_t chunk_len) {
    if (chunk_len == 0 || chunk_len > INT_MAX) {
        errno = EINVAL;
        libarp_set_error("Streaming chunk length must be between 1 and 2147483647 bytes");
        return NULL;
    }

    const node_desc_t *node = (node_desc_t*) meta->extra;

    arp_resource_stream_t *stream = NULL;
    if ((stream = malloc(sizeof(arp_resource_stream_t))) == NULL) {
        libarp_set_error("malloc failed");
        errno = ENOMEM;
        return NULL;
    }

    memcpy(&stream->meta, meta, sizeof(arp_resource_meta_t));
    stream->chunk_len = chunk_len;
    stream->packed_pos = 0;
    stream->unpacked_pos = 0;
    stream->next_buf = 0;
    stream->overflow_len = 0;
    stream->overflow_cap = 0;
    stream->overflow_buf = NULL;

    size_t res_base_off = 0;
    if (node->part_index == 1) {
        res_base_off = node->package->body_off;
    } else {
        res_base_off = PACKAGE_PART_HEADER_LEN;
    }

    res_base_off += node->data_off;

    if ((stream->file = open_part_file_for_node(node)) == NULL) {
        free(stream);

        return NULL;
    }

    if ((stream->prim_buf = malloc(chunk_len)) == NULL) {
        fclose(stream->file);
        free(stream);

        libarp_set_error("malloc failed");
        errno = ENOMEM;
        return NULL;
    }

    if ((stream->sec_buf = malloc(chunk_len)) == NULL) {
        free(stream->prim_buf);
        fclose(stream->file);
        free(stream);

        libarp_set_error("malloc failed");
        errno = ENOMEM;
        return NULL;
    }

    if ((stream->tert_buf = malloc(chunk_len)) == NULL) {
        free(stream->sec_buf);
        free(stream->prim_buf);
        fclose(stream->file);
        free(stream);

        libarp_set_error("malloc failed");
        errno = ENOMEM;
        return NULL;
    }

    if (CMPR_ANY(node->package->compression_type)) {
        if (CMPR_DEFLATE(node->package->compression_type)) {
            if ((stream->compression_data
                    = decompress_deflate_begin(node->packed_data_len, node->unpacked_data_len)) == NULL) {
                free(stream->sec_buf);
                free(stream->prim_buf);
                fclose(stream->file);
                free(stream);

                return NULL;
            }
        } else {
            assert(false);
        }
    }

    return stream;
}

int stream_resource(ArpResourceStream stream, void **out_data, size_t *out_data_len) {
    arp_resource_stream_t *real_stream = (arp_resource_stream_t*) stream;

    node_desc_t *node = (node_desc_t*) real_stream->meta.extra;
    arp_package_t *pack = (arp_package_t*) real_stream->meta.package;

    if (real_stream->unpacked_pos == node->unpacked_data_len) {
        return ARP_STREAM_EOF;
    }

    void *target_buf = NULL;
    switch (real_stream->next_buf) {
        case 0:
            target_buf = real_stream->prim_buf;
            break;
        case 1:
            target_buf = real_stream->sec_buf;
            break;
        case 2:
            target_buf = real_stream->tert_buf;
            break;
        default:
            assert(false);
    }

    uint64_t unread_packed_bytes = node->packed_data_len - real_stream->packed_pos;

    uint64_t unread_unpacked_bytes = node->unpacked_data_len - real_stream->unpacked_pos;
    uint64_t unstreamed_unpacked_bytes = unread_unpacked_bytes + real_stream->overflow_len;

    size_t total_required_out = MIN(real_stream->chunk_len, unstreamed_unpacked_bytes);
    size_t required_from_disk = real_stream->overflow_len >= total_required_out
            ? 0
            : total_required_out - real_stream->overflow_len;

    if (real_stream->overflow_len >= total_required_out) {
        // we already have all the data we need in the overflow buffer

        memcpy(target_buf, real_stream->overflow_buf, total_required_out);

        size_t extra_overflow = real_stream->overflow_len - total_required_out;
        void *extra_start = (void*) ((uintptr_t) real_stream->overflow_buf + total_required_out);

        if (extra_overflow > 0) {
             if (extra_overflow > total_required_out) {
                void *intermediate_buf = NULL;
                if ((intermediate_buf = malloc(extra_overflow)) == NULL) {
                    libarp_set_error("malloc failed");
                    return ENOMEM;
                }

                memcpy(intermediate_buf, extra_start, extra_overflow);
                memcpy(real_stream->overflow_buf, intermediate_buf, extra_overflow);

                free(intermediate_buf);
            } else {
                // can copy directly to the beginning of the overflow buffer
                memcpy(real_stream->overflow_buf, extra_start, extra_overflow);
            }
        }

        real_stream->overflow_len -= total_required_out;
    } else {
        // we need to read at least some data from disk

        // we account for the data already in the overflow buffer to hopefully minimize the utilization of it
        size_t max_to_read = required_from_disk;
        if (CMPR_ANY(node->package->compression_type)) {
            // include a small buffer space to allow efficient processing of uncompressible data
            max_to_read *= DEFLATE_BUF_MARGIN;
        }

        size_t output_buf_off = 0;

        size_t remaining_needed = total_required_out;

        if (real_stream->overflow_len > 0) {
            // we comsume the whole overflow buffer because it's guaranteed to
            // be less than the required output length
            memcpy(target_buf, real_stream->overflow_buf, real_stream->overflow_len);
            output_buf_off = real_stream->overflow_len;
            remaining_needed -= real_stream->overflow_len;

            real_stream->overflow_len = 0;
        }

        size_t to_read = MIN(max_to_read, unread_packed_bytes);

        unsigned char read_buf[IO_BUFFER_LEN];
        size_t read_bytes = 0;
        while (remaining_needed > 0
                && (read_bytes = fread(read_buf, 1, MIN(sizeof(read_buf), to_read), real_stream->file)) > 0) {
            size_t read_bytes_unpacked = read_bytes;
            size_t copied_bytes = read_bytes;
            to_read -= read_bytes;

            void *offset_buf = (void*) ((uintptr_t) target_buf + output_buf_off);

            if (CMPR_ANY(pack->compression_type)) {
                if (CMPR_DEFLATE(pack->compression_type)) {
                    void *unpack_buf = NULL;
                    size_t unpacked_len = 0;
                    int rc = 0;
                    if ((rc = decompress_deflate(real_stream->compression_data, read_buf, read_bytes,
                            &unpack_buf, &unpacked_len) != 0)) {
                        return rc;
                    }

                    if (unpacked_len > remaining_needed) {
                        size_t overflowed_bytes = unpacked_len - remaining_needed;
                        void *overflow_start = (void*) ((uintptr_t) unpack_buf + remaining_needed);
                        if (real_stream->overflow_cap == 0) {
                            // we multiply by 2 to hopefully avoid having to realloc later in the stream
                            if ((real_stream->overflow_buf = malloc(overflowed_bytes * 2)) == NULL) {
                                libarp_set_error("malloc failed");
                                return ENOMEM;
                            }
                        } else if (real_stream->overflow_cap - real_stream->overflow_len < overflowed_bytes) {
                            size_t extra_needed = overflowed_bytes
                                    - (real_stream->overflow_cap - real_stream->overflow_len);
                            void *new_overflow_buf = realloc(real_stream->overflow_buf,
                                    real_stream->overflow_cap + extra_needed);
                            if (new_overflow_buf == NULL) {
                                libarp_set_error("realloc failed");
                                return ENOMEM;
                            }
                            real_stream->overflow_buf = new_overflow_buf;
                        }

                        void *offset_overflow_buf = (void*) ((uintptr_t) real_stream->overflow_buf
                                + real_stream->overflow_len);
                        memcpy(offset_overflow_buf, overflow_start, overflowed_bytes);

                        real_stream->overflow_len += overflowed_bytes;
                    }

                    copied_bytes = MIN(unpacked_len, remaining_needed);
                    memcpy(offset_buf, unpack_buf, copied_bytes);

                    free(unpack_buf);

                    read_bytes_unpacked = unpacked_len;
                } else {
                    assert(false);
                }
            } else {
                memcpy(offset_buf, read_buf, read_bytes);
            }

            remaining_needed -= copied_bytes;
            output_buf_off += copied_bytes;
            real_stream->unpacked_pos += read_bytes_unpacked;
        }

        real_stream->next_buf += 1;
    }

    // loop back around to 0 if required since we only have 3 buffers
    real_stream->next_buf = (real_stream->next_buf + 1) % 3;

    // we don't update the pos fields because we didn't read anything from disk

    *out_data = target_buf;
    *out_data_len = total_required_out;

    return 0;
}

void free_resource_stream(ArpResourceStream stream) {
    arp_resource_stream_t *real_stream = (arp_resource_stream_t*) stream;
    node_desc_t *node = (node_desc_t*) real_stream->meta.extra;

    if (real_stream->overflow_buf != NULL) {
        free(real_stream->overflow_buf);
    }

    free(real_stream->prim_buf);
    free(real_stream->sec_buf);
    free(real_stream->tert_buf);

    fclose(real_stream->file);

    if (CMPR_ANY(node->package->compression_type)) {
        if (CMPR_DEFLATE(node->package->compression_type)) {
            decompress_deflate_end(real_stream->compression_data);
        } else {
            assert(false);
        }
    }

    free(real_stream);
}
