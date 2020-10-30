/*
 * This file is a part of libarp.
 * Copyright (c) 2020, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libarp/unpack.h"
#include "internal/file_defines.h"
#include "internal/package.h"
#include "internal/util.h"

#define COPY_TO_FIELD(src, dst, len, off) memcpy(&dst, src + off, len); off += len
#define COPY_TO_FIELD_STR(src, dst, len, off) memcpy(dst, src + off, len); off += len

static int _parse_package_header(argus_package_t *pack, unsigned char header_data[PACKAGE_HEADER_LEN]) {
    size_t header_off = 0;

    if (memcmp(header_data, FORMAT_MAGIC, PACKAGE_MAGIC_LEN) != 0) {
        libarp_set_error("Package magic is incorrect");
        return -1;
    }
    header_off += sizeof(FORMAT_MAGIC);

    COPY_TO_FIELD(header_data, pack->major_version, PACKAGE_VERSION_LEN, header_off);

    if (pack->major_version != 1) {
        libarp_set_error("Package version is not supported");
        return -1;
    }

    COPY_TO_FIELD_STR(header_data, pack->compression_type, PACKAGE_COMPRESSION_LEN, header_off);
    COPY_TO_FIELD_STR(header_data, pack->package_namespace, PACKAGE_NAMESPACE_LEN, header_off);
    COPY_TO_FIELD(header_data, pack->total_parts, PACKAGE_PARTS_LEN, header_off);
    COPY_TO_FIELD(header_data, pack->cat_off, PACKAGE_CAT_OFF_LEN, header_off);
    COPY_TO_FIELD(header_data, pack->cat_len, PACKAGE_CAT_LEN_LEN, header_off);
    COPY_TO_FIELD(header_data, pack->node_count, PACKAGE_CAT_CNT_LEN, header_off);
    COPY_TO_FIELD(header_data, pack->body_off, PACKAGE_BODY_OFF_LEN, header_off);
    COPY_TO_FIELD(header_data, pack->body_len, PACKAGE_BODY_LEN_LEN, header_off);

    return 0;
}

static int _validate_package_header(argus_package_t *pack, size_t pack_size) {
    if (pack->compression_type[0] != '\0'
            && memcmp(pack->compression_type, COMPRESS_MAGIC_DEFLATE, PACKAGE_MAGIC_LEN) != 0) {
        libarp_set_error("Package compression is not supported");
        return -1;
    }

    if (pack->package_namespace[0] == '\0' || pack->package_namespace[PACKAGE_NAMESPACE_LEN - 1] != '\0') {
        libarp_set_error("Package namespace is not valid");
        return -1;
    }

    if (pack->total_parts < 1 || pack->total_parts > PACKAGE_MAX_PARTS) {
        libarp_set_error("Package part count is invalid");
        return -1;
    }

    if (pack->node_count == 0) {
        libarp_set_error("Package catalogue is empty");
        return -1;
    }

    if (pack->cat_off < PACKAGE_HEADER_LEN) {
        libarp_set_error("Package catalogue offset is too small");
        return -1;
    }

    if (pack->cat_len + pack->body_len > pack_size - PACKAGE_HEADER_LEN) {
        libarp_set_error("Combined package catalogue+body length is too large");
        return -1;
    }

    if (pack->cat_off < pack->body_off && pack->cat_off + pack->cat_len > pack->body_off) {
        libarp_set_error("Package catalogue would overlap body section");
        return -1;
    } else if (pack->body_off < pack->cat_off && pack->body_off + pack->body_len > pack->cat_off) {
        libarp_set_error("Body section would overlap package catalogue");
        return -1;
    }

    return 0;
}

int load_package_from_file(const char *path, ArgusPackage *package) {
    FILE *file = fopen(path, "r");

    if (file == NULL) {
        libarp_set_error("Failed to open package file");
        return -1;
    }

    stat_t file_stat;
    if (fstat(fileno(file), &file_stat) != 0) {
        libarp_set_error("Failed to stat package file");
        return -1;
    }

    size_t file_size = file_stat.st_size;

    if (file_size < PACKAGE_HEADER_LEN) {
        libarp_set_error("File is too small to contain package header");
        return -1;
    }

    unsigned char pack_header[PACKAGE_HEADER_LEN];

    if (fread(pack_header, PACKAGE_HEADER_LEN, 1, file) != 1) {
        libarp_set_error("Failed to read package header from file");
        return -1;
    }

    argus_package_t *pack = malloc(sizeof(argus_package_t));

    int rc;
    if ((rc = _parse_package_header(pack, pack_header)) != 0) {
        free(pack);
        return rc;
    }

    if ((rc = _validate_package_header(pack, file_size)) != 0) {
        free(pack);
        return rc;
    }

    *package = pack;
    return 0;
}

int load_package_from_memory(const unsigned char *data, size_t package_len, ArgusPackage *package) {
    if (package_len < PACKAGE_HEADER_LEN) {
        libarp_set_error("File is too small to contain package header");
        return -1;
    }

    unsigned char pack_header[PACKAGE_HEADER_LEN];

    memcpy(pack_header, data, PACKAGE_HEADER_LEN);

    argus_package_t *pack = malloc(sizeof(argus_package_t));

    int rc;
    if ((rc = _parse_package_header(pack, pack_header)) != 0) {
        return rc;
    }

    if ((rc = _validate_package_header(pack, package_len)) != 0) {
        return rc;
    }

    if (pack->total_parts > 1) {
        libarp_set_error("Memory-resident packages may not contain more than 1 part");
        return -1;
    }

    *package = pack;
    return 0;
}

int unload_package(ArgusPackage package) {
    free(package);
    return 0;
}
