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

static int _unpack_node_from_memory(arp_package_t *pack, const node_desc_t *node,
        void **out_data, size_t *out_data_len, bool *out_malloced) {
    if (node->part_index != 1) {
        arp_set_error("In-memory node has invalid part index");
        return EINVAL;
    }

    void *unpacked_data = NULL;
    size_t unpacked_len = 0;

    void *node_ptr = (void*) ((uintptr_t) pack->in_mem_body + node->data_off);

    uint32_t crc = crc32c(node_ptr, node->packed_data_len);

    if (crc != node->crc) {
        arp_set_error("CRC mismatch");
        return -1;
    }

    bool malloced = false;

    if (CMPR_ANY(pack->compression_type)) {
        if (CMPR_DEFLATE(pack->compression_type)) {
            DeflateStream defl_stream = decompress_deflate_begin(node->packed_data_len, node->unpacked_data_len);
            malloced = true;

            if (defl_stream == NULL) {
                return errno;
            }

            int rc = UNINIT_U32;
            if ((rc = decompress_deflate(defl_stream, node_ptr, node->packed_data_len, &unpacked_data, &unpacked_len))
                    != 0) {
                return rc;
            }

            decompress_deflate_end(defl_stream);
        } else {
            assert(0);
        }
    } else {
        unpacked_data = node_ptr;
        unpacked_len = node->unpacked_data_len;
    }

    assert(unpacked_data != NULL);

    *out_data = unpacked_data;
    *out_data_len = unpacked_len;
    *out_malloced = malloced;

    return 0;
}

static int _unpack_node_from_file(arp_package_t *pack, const node_desc_t *node, FILE *out_file,
        void **out_data, size_t *out_data_len, bool *out_malloced, FILE *part) {
        int rc = UNINIT_U32;

    void *unpacked_data = NULL;

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

    bool malloced = false;

    size_t unpacked_data_len = node->unpacked_data_len;
    if (out_data != NULL) {
        if ((unpacked_data = malloc(unpacked_data_len)) == NULL) {
            //TODO: maybe handle a malloc failure specially here
            if (part == NULL) {
                fclose(part_file);
            }

            arp_set_error("malloc failed");
            return ENOMEM;
        }

        malloced = true;
    }

    void *compress_data = NULL;
    if (CMPR_ANY(pack->compression_type)) {
        if (CMPR_DEFLATE(pack->compression_type)) {
            if ((compress_data = decompress_deflate_begin(node->packed_data_len, node->unpacked_data_len)) == NULL) {
                if (unpacked_data != NULL) {
                    free(unpacked_data);
                }

                return errno;
            }
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

            arp_set_error("Failed to read from part file");
            return -1;
        }

        remaining -= to_read;

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
                if (unpacked_data != NULL) {
                    free(unpacked_data);
                }

                arp_set_error("Failed to write resource data to disk");
                return errno;
            }
        } else {
            assert(unpacked_data != NULL);
            memcpy((char*) unpacked_data + written_bytes, unpacked_chunk, unpacked_chunk_len);
        }

        written_bytes += unpacked_chunk_len;

        if (unpacked_chunk != read_buf) {
            free(unpacked_chunk);
        }
    }

    if (part == NULL) {
        fclose(part_file);
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

        arp_set_error("CRC mismatch");
        return -1;
    }

    if (out_data != NULL) {
        *out_data = unpacked_data;
    }

    if (out_data_len != NULL) {
        *out_data_len = unpacked_data_len;
    }

    *out_malloced = malloced;

    return 0;
}

int unpack_node_data(const node_desc_t *node, FILE *out_file,
        void **out_data, size_t *out_data_len, bool *out_malloced, FILE *part) {
    assert((out_data != NULL) ^ (out_file != NULL)); // only one can be supplied

    arp_package_t *pack = node->package;

    if (pack->in_mem_body != NULL) {
        if (out_file != NULL) {
            arp_set_error("Unpacking in-memory nodes to disk is not supported");
            return EINVAL;
        }

        return _unpack_node_from_memory(pack, node, out_data, out_data_len, out_malloced);
    } else {
        return _unpack_node_from_file(pack, node, out_file, out_data, out_data_len, out_malloced, part);
    }
}
