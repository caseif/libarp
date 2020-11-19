#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "internal/crc32c.h"

#define CRC_POLY_REV 0x82F63B78

static bool lookup_table_initted = false;
static uint32_t crc_lookup[256];

static void _compute_crc_lookup_table(void) {
    for (uint16_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (uint8_t i = 0; i < 8; i++) {
            crc = crc & 1 ? (crc >> 1) ^ CRC_POLY_REV : crc >> 1;
        }
        crc_lookup[i] = crc;
    }
}

static inline bool _is_sse42_supported(void) {
    #ifdef _WIN32
    return false;
    #else
    __builtin_cpu_init();
    return __builtin_cpu_supports("sse4.2");
    #endif
}

static inline uint32_t _intrinsic_crc32c(const void *data, size_t len) {
    #ifdef _WIN32
    return 0;
    #else
    uint32_t crc = ~0;
    for (size_t i = 0; i < len - (len % 8); i += 8) {
        crc = __builtin_ia32_crc32di(crc, *((uint64_t*) ((uintptr_t) data + i)));
    }
    for (size_t i = len - (len % 8); i < len; i++) {
        crc = __builtin_ia32_crc32qi(crc, *((uint8_t*) ((uintptr_t) data + i)));
    }
    return ~crc;
    #endif
}

static inline uint32_t _sw_crc32c(const void *data, size_t len) {
    unsigned char *data_uc = (unsigned char*) data;

    uint32_t crc = ~0;

    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc_lookup[(crc & 0xFF) ^ data_uc[i]];
    }

    return ~crc;
}

uint32_t crc32c(const void *data, size_t len) {
    if (!lookup_table_initted) {
        _compute_crc_lookup_table();
        lookup_table_initted = true;
    }

    if (_is_sse42_supported()) {
        printf("Using intrinsic impl\n");
        return _intrinsic_crc32c(data, len);
    } else {
        printf("Using software impl\n");
        return _sw_crc32c(data, len);
    }
}
