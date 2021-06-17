#include "internal/defines/misc.h"
#include "internal/unpack/load_util.h"
#include "internal/unpack/unpack_util.h"
#include "internal/util/common.h"
#include "internal/util/compress.h"
#include "internal/util/crc32c.h"
#include "internal/util/error.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define IO_BUFFER_LEN (128 * 1024) // 128 KB

int unpack_node_data(const node_desc_t *node, FILE *out_file,
        void **out_data, size_t *out_data_len, FILE *part) {
    assert((out_data != NULL) ^ (out_file != NULL)); // only one can be supplied

    int rc = UNINIT_U32;

    arp_package_t *pack = node->package;

    FILE *part_file = NULL;
    if (part != NULL) {
        part_file = part;

        if ((rc = setup_part_file_for_node(part_file, node)) != 0) {
            return rc;
        }
    } else {
        if ((part_file = open_part_file_for_node(node)) == NULL) {
            return errno;
        }
    }
    
    void *unpacked_data = NULL;
    size_t unpacked_data_len = node->unpacked_data_len;
    if (out_data != NULL) {
        if ((unpacked_data = malloc(unpacked_data_len)) == NULL) {
            //TODO: maybe handle a malloc failure specially here
            if (part == NULL) {
                fclose(part_file);
            }

            libarp_set_error("malloc failed");
            return ENOMEM;
        }
    }

    void *compress_data = NULL;
    if (CMPR_ANY(pack->compression_type)) {
        if (CMPR_DEFLATE(pack->compression_type)) {
            compress_data = decompress_deflate_begin(node->packed_data_len, node->unpacked_data_len);
        } else {
             // should have already validated by now
            assert(false);
        }
    }

    size_t remaining = node->packed_data_len;
    size_t written_bytes = 0;
    unsigned char read_buf[IO_BUFFER_LEN];
    uint32_t real_crc = 0;
    bool began_crc = false;

    while (remaining > 0) {
        size_t to_read = MIN(sizeof(read_buf), remaining);
        if ((fread(read_buf, to_read, 1, part_file)) != 1) {
            if (unpacked_data != NULL) {
                free(unpacked_data);
            }

            if (part == NULL) {
                fclose(part_file);
            }

            libarp_set_error("Failed to read from part file");
            return -1;
        }

        remaining -= to_read;

        if (part == NULL) {
            fclose(part_file);
        }

        if (began_crc) {
            real_crc = crc32c_cont(real_crc, read_buf, to_read);
        } else {
            real_crc = crc32c(read_buf, to_read);
            began_crc = true;
        }

        void *unpacked_chunk = read_buf;
        size_t unpacked_chunk_len = to_read;

        if (CMPR_ANY(pack->compression_type)) {
            if (CMPR_DEFLATE(pack->compression_type)) {
                if ((rc = decompress_deflate(compress_data, read_buf, to_read,
                        &unpacked_chunk, &unpacked_chunk_len)) != 0) {
                    if (unpacked_data != NULL) {
                        free(unpacked_data);
                    }

                    decompress_deflate_end(compress_data);

                    return rc;
                }
            } else {
                // should have already validated by now
                assert(false);
            }
        }
        
        if (out_file != NULL) {
            if (fwrite(unpacked_chunk, unpacked_chunk_len, 1, out_file) != 1) {
                libarp_set_error("Failed to write resource data to disk");
                return errno;
            }
        } else {
            memcpy((char*) unpacked_data + written_bytes, unpacked_chunk, unpacked_chunk_len);
        }

        written_bytes += unpacked_chunk_len;

        if (unpacked_chunk != read_buf) {
            free(unpacked_chunk);
        }
    }

    if (CMPR_ANY(pack->compression_type)) {
        if (CMPR_DEFLATE(pack->compression_type)) {
            decompress_deflate_end(compress_data);
        } else {
             // should have already validated by now
            assert(false);
        }
    }

    if (real_crc != node->crc) {
        if (unpacked_data != NULL) {
            free(unpacked_data);
        }

        libarp_set_error("CRC mismatch");
        return -1;
    }

    if (out_data != NULL) {
        *out_data = unpacked_data;
    }
    if (out_data_len != NULL) {
        *out_data_len = unpacked_data_len;
    }

    return 0;
}
