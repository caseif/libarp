/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/crc32c.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#include <intrin.h>
#endif

#include <immintrin.h>

#define CRC_POLY_REV 0x82F63B78

#if defined(__x86_64__) || defined(_M_X64)
#define ARCH_X64
#endif

#define CRC_LOOKUP_TABLE_SIZE 256U
#define CRC_INITIAL_INV 0

#define BITS_PER_BYTE 8U
#define BYTES_PER_U64 8U
#define BIT_MASK_8 0xFF

static bool lookup_table_initted = false;
static uint32_t crc_lookup[CRC_LOOKUP_TABLE_SIZE];

static void _compute_crc_lookup_table(void) {
    for (uint16_t i = 0; i < CRC_LOOKUP_TABLE_SIZE; i++) {
        uint32_t crc = i;
        for (uint8_t j = 0; j < BITS_PER_BYTE; j++) {
            crc = crc & 1U ? (crc >> 1U) ^ CRC_POLY_REV : crc >> 1U;
        }
        crc_lookup[i] = crc;
    }
}

#ifdef ARCH_X64
static inline bool _is_sse42_supported(void) {
    #ifdef _WIN32
    int cpu_info[4];
    __cpuid(cpu_info, 1);
    return cpu_info[1] & (1 << 20);
    #else
    __builtin_cpu_init();
    return __builtin_cpu_supports("sse4.2");
    #endif
}
#endif

static inline uint32_t _x86_crc32c(uint32_t initial, const void *data, size_t len) {
    size_t data_block_len = BYTES_PER_U64;

    uint32_t crc = initial;
    for (size_t i = 0; i < len - (len % data_block_len); i += data_block_len) {
        crc = _mm_crc32_u64(crc, *((uint64_t*) ((uintptr_t) data + i)));
    }
    for (size_t i = len - (len % data_block_len); i < len; i++) {
        crc = _mm_crc32_u8(crc, *((uint8_t*) ((uintptr_t) data + i)));
    }
    return ~crc;
}

static inline uint32_t _sw_crc32c(uint32_t initial, const void *data, size_t len) {
    if (!lookup_table_initted) {
        _compute_crc_lookup_table();
        lookup_table_initted = true;
    }

    unsigned char *data_uc = (unsigned char*) data;

    uint32_t crc = initial;

    for (size_t i = 0; i < len; i++) {
        crc = (crc >> BITS_PER_BYTE) ^ crc_lookup[(crc & BIT_MASK_8) ^ data_uc[i]];
    }

    return ~crc;
}

uint32_t crc32c_cont(uint32_t initial, const void *data, size_t len) {
    uint32_t real_initial = ~initial;

    #ifdef ARCH_X64
    if (_is_sse42_supported()) {
        return _x86_crc32c(real_initial, data, len);
    }
    #endif

    return _sw_crc32c(real_initial, data, len);
}

uint32_t crc32c(const void *data, size_t len) {
    return crc32c_cont(CRC_INITIAL_INV, data, len);
}
