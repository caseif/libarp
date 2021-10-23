/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/util/common.h"
#include "internal/util/error.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <intrin.h>
#else
#include <immintrin.h>
#include <sys/mman.h>
#endif

// This function actually works for both copying LE file data to BE system
// memory, and vice versa. all we care about is if the source and target
// endianness mismatch (which will only happen if the system is BE since the
// file data is guaranteed to be LE), so simply flipping the bytes in this case
// will work regardless of which direction we're copying.
void copy_int_as_le(void *dst, void *src, size_t len) {
    memcpy(dst, src, len);

    int x = 1;
    if (((unsigned char*) &x)[0] == 0) {
        // system is big-endian, so we need to convert to little
        #ifdef _WIN32
        if (len == 2) {
            *((uint16_t*) dst) = _byteswap_ushort(*((uint16_t*) dst));
        } else if (len == 3 || len == 4) {
            *((uint32_t*) dst) = _byteswap_ulong(*((uint32_t*) dst));
        } else if (len == 8) {
            *((uint64_t*) dst) = _byteswap_uint64(*((uint64_t*) dst));
        }
        #else
        if (len == 2) {
            *((uint16_t*) dst) = __builtin_bswap16(*((uint16_t*) dst));
        } else if (len == 3 || len == 4) {
            *((uint32_t*) dst) = __builtin_bswap32(*((uint32_t*) dst));
        } else if (len == 8) {
            *((uint64_t*) dst) = __builtin_bswap64(*((uint64_t*) dst));
        }
        #endif
    }
}

int validate_path_component(const char *cmpnt, uint8_t len_s) {
    for (uint8_t i = 0; i < len_s; i++) {
        unsigned char c = (unsigned char) cmpnt[i];
        if (c & 0x80) {
            // we can take a shortcut since we only care about specific code points, most of which are in ASCII
            if ((c & 0xE0) == 0xC0) {
                if (i == len_s - 1) {
                    break;
                }

                uint16_t cp = (uint16_t) (((c & 0x1FU) << 6) | (cmpnt[i + 1] & 0x3F));

                if (cp >= 0x80 && cp <= 0x9F) {
                    arp_set_error("Path component must not contain control characters");
                    return -1;
                }

                // 2-byte character, skip one extra byte
                i += 1;
            } else if ((c & 0xF0) == 0xE0) {
                // 3-byte character, skip two extra bytes
                i += 2;
            } else if ((c & 0xF8) == 0xF0) {
                // 4-byte character, skip three extra bytes
                i += 3;
            } else {
                // note that this most definitely does not catch all cases of illegal UTF-8
                arp_set_error("Path component is not legal UTF-8");
                return -1;
            }
            
            continue;
        }

        // we're guaranteed to be working with an ASCII character at this point
        if (c <= 0x1F || c == 0x7F) {
            arp_set_error("Path component must not contain control characters");
            return -1;
        }

        if (c == '/' || c == '\\' || c == ':') {
            arp_set_error("Path component must not contain reserved characters");
            return -1;
        }
    }
    
    return 0;
}
