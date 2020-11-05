/*
 * This file is a part of libarp.
 * Copyright (c) 2020, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "libarp/unpack.h"
#include "internal/file_defines.h"
#include "internal/package.h"
#include "internal/util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#define MAX(a, b) (a > b ? a : b)

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

    //TODO: deal with endianness
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

    if (pack->body_off < PACKAGE_HEADER_LEN) {
        libarp_set_error("Package body offset is too small");
    }

    if (pack->cat_off + pack->cat_len > pack_size) {
        libarp_set_error("Package catalogue offset and length are incorrect");
    }

    if (pack->body_off + pack->body_len > pack_size) {
        libarp_set_error("Package body offset and length are incorrect");
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

static int _parse_package_catalogue(argus_package_t *pack) {
    node_desc_t **nodes = calloc(1, pack->node_count * sizeof(void*));

    //TODO

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

    #ifdef _WIN32
    char *real_path = _fullpath(NULL, path, size_t(-1));
    #else
    char *real_path = realpath(path, NULL);
    #endif
    if (real_path == NULL) {
        libarp_set_error("Failed to get absolute path of package file");
        return -1;
    }

    const char *file_base;

    #ifdef _WIN32
    if ((file_base = MAX(strrchr(real_path, '\\'), strrche(real_path, '/'))) != NULL) {
        file_base += 1;
    } else {
        file_base = real_path;
    }
    #else
    if ((file_base = strrchr(real_path, '/')) != NULL) {
        file_base += 1;
    } else {
        file_base = real_path;
    }
    #endif

    // _b = buffer length, includes null terminator
    // _s = string length, does not include null terminator
    size_t base_len_s = strlen(file_base);

    if (memcmp(file_base + base_len_s - sizeof("." PACKAGE_EXT), "." PACKAGE_EXT, sizeof("." PACKAGE_EXT)) != 0) {
        libarp_set_error("Unexpected file extension for primary package file");
        return -1;
    }

    size_t stem_len_b = base_len_s - sizeof("." PACKAGE_EXT) + 1;
    char *file_stem = malloc(stem_len_b);
    memcpy(file_stem, file_base, stem_len_b - 1);
    file_stem[stem_len_b - 1] = '\0';

    char *parent_dir;
    size_t parent_dir_len_b;
    if (file_base != real_path) {
        parent_dir_len_b = file_base - real_path + 1;
        parent_dir = malloc(parent_dir_len_b);
        memcpy(parent_dir, real_path, parent_dir_len_b - 1);
        parent_dir[parent_dir_len_b - 1] = '\0';
    } else {
        parent_dir_len_b = 1;
        parent_dir = malloc(parent_dir_len_b);
        parent_dir[0] = '\0';
    }

    size_t suffix_index = stem_len_b - 1 - sizeof(PACKAGE_PART_1_SUFFIX);
    if (stem_len_b > sizeof(PACKAGE_PART_1_SUFFIX) - 1
            && memcmp(file_base + suffix_index, PACKAGE_PART_1_SUFFIX, sizeof(PACKAGE_PART_1_SUFFIX) - 1) == 0) {
        stem_len_b -= sizeof(PACKAGE_PART_1_SUFFIX);
        file_stem = realloc(file_stem, stem_len_b);
    }

    size_t file_size = file_stat.st_size;

    if (file_size < PACKAGE_HEADER_LEN) {
        free(parent_dir);
        free(file_stem);

        libarp_set_error("File is too small to contain package header");
        return -1;
    }

    unsigned char pack_header[PACKAGE_HEADER_LEN];

    if (fread(pack_header, PACKAGE_HEADER_LEN, 1, file) != 1) {
        free(parent_dir);
        free(file_stem);

        libarp_set_error("Failed to read package header from file");
        return -1;
    }

    argus_package_t *pack = calloc(1, sizeof(argus_package_t));

    int rc;
    if ((rc = _parse_package_header(pack, pack_header)) != 0) {
        unload_package(pack);
        free(parent_dir);
        free(file_stem);

        return rc;
    }

    if ((rc = _validate_package_header(pack, file_size)) != 0) {
        unload_package(pack);
        free(parent_dir);
        free(file_stem);

        return rc;
    }

    pack->part_paths = calloc(1, sizeof(void*) * pack->total_parts);

    pack->part_paths[0] = malloc(base_len_s + 1);

    for (int i = 2; i <= pack->total_parts; i++) {
        char *part_path = malloc(parent_dir_len_b - 1 + stem_len_b - 1 + sizeof(".part000") - 1 + sizeof("." PACKAGE_EXT));
        sprintf(part_path, "%s%s.part%03d." PACKAGE_EXT, parent_dir, file_stem, i);
        
        pack->part_paths[i - 1] = part_path;
        
        FILE *part_file = fopen(part_path, "r");

        if (part_file == NULL) {
            if (errno == ENOENT) {
                libarp_set_error("Part file for package is missing");
            } else if (errno == EPERM) {
                libarp_set_error("Cannot access part file for package");
            } else if (errno == EIO) {
                libarp_set_error("I/O error occurred while accessing part file for package");
            } else {
                libarp_set_error("Error occurred accesing part file for package");
            }
            
            unload_package(pack);
            free(parent_dir);
            free(file_stem);

            return -1;
        }

        stat_t part_stat;
        if (fstat(fileno(part_file), &part_stat) != 0) {
            libarp_set_error("Failed to stat package part file");
            
            unload_package(pack);
            free(parent_dir);
            free(file_stem);

            return -1;
        }

        if (part_stat.st_size < PACKAGE_PART_HEADER_LEN) {
            libarp_set_error("Package part file is too small");
            
            unload_package(pack);
            free(parent_dir);
            free(file_stem);

            return -1;
        }

        unsigned char part_header[PACKAGE_PART_HEADER_LEN];
        if (fread(part_header, PACKAGE_PART_HEADER_LEN, 1, part_file) != 0) {
            libarp_set_error("Failed to read package part header");
            
            unload_package(pack);
            free(parent_dir);
            free(file_stem);

            return -1;
        }

        if (memcmp(part_header, PART_MAGIC, PART_MAGIC_LEN) != 0) {
            libarp_set_error("Package part magic is invalid");
            
            unload_package(pack);
            free(parent_dir);
            free(file_stem);

            return -1;
        }

        uint16_t part_index = part_header[PART_MAGIC_LEN] | part_header[PART_MAGIC_LEN + 1] << 8;
        if (part_index != i) {
            libarp_set_error("Package part index is incorrect");
            
            unload_package(pack);
            free(parent_dir);
            free(file_stem);

            return -1;
        }
    }

    if ((rc = _parse_package_catalogue(pack)) != 0) {
        unload_package(pack);
        free(parent_dir);
        free(file_stem);

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

    argus_package_t *pack = calloc(1, sizeof(argus_package_t));

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
    argus_package_t *real_pack = (argus_package_t*)package;

    for (size_t i = 0; i < real_pack->total_parts; i++) {
        char *part_path = real_pack->part_paths[i];
        if (part_path == NULL) {
            break;
        }
        free(part_path);
    }
    
    if (real_pack->part_paths != NULL) {
        free(real_pack->part_paths);
    }
    
    free(package);
    return 0;
}
