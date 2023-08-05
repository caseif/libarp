/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "arp/unpack/peek.h"
#include "internal/defines/file.h"
#include "internal/defines/package.h"
#include "internal/util/error.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _MSC_VER
#include <malloc.h>
#endif

static bool _check_magic(const char *path, const char *magic, size_t magic_len) {
    FILE *package_file = fopen(path, "r");

    if (package_file == NULL) {
        arp_set_error("Failed to open package file");
        return false;
    }

    stat_t package_file_stat;
    if (fstat(fileno(package_file), &package_file_stat) != 0) {
        fclose(package_file);

        arp_set_error("Failed to stat package file");
        return false;
    }

    if ((size_t) package_file_stat.st_size < magic_len) {
        fclose(package_file);
        return false;
    }
    
    #ifdef _MSC_VER
    unsigned char *magic_data = (unsigned char*) _malloca(magic_len);
    #else
    unsigned char magic_data[magic_len];
    #endif
    memset(magic_data, 0, magic_len);

    if (fread(magic_data, magic_len, 1, package_file) != 1) {
        fclose(package_file);

        arp_set_error("Failed to read magic from file");
        return false;
    }

    fclose(package_file);

    bool res = memcmp(magic_data, magic, magic_len) == 0;

    #ifdef MSVC
    _freea(res);
    #endif

    return res;
}

bool arp_is_base_archive(const char *path) {
    return _check_magic(path, FORMAT_MAGIC, PACKAGE_MAGIC_LEN);
}

bool arp_is_part_archive(const char *path) {
    return _check_magic(path, PART_MAGIC, PART_MAGIC_LEN);
}
