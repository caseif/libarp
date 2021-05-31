/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "libarp/defines.h"
#include "libarp/unpack.h"
#include "internal/bt.h"
#include "internal/common_util.h"
#include "internal/compression.h"
#include "internal/crc32c.h"
#include "internal/file_defines.h"
#include "internal/other_defines.h"
#include "internal/package_defines.h"
#include "internal/stack.h"
#include "internal/unpack_util.h"
#include "internal/util.h"

#include "zlib.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#include <intrin.h>
#include <memoryapi.h>
#include <windows.h>
#else
#include <immintrin.h>
#include <sys/mman.h>
#endif

#define IO_BUFFER_LEN (128 * 1024) // 128 KB

#define VAR_STR_BUF_LEN 256

#define DEFLATE_BUF_MARGIN 1.05L

static void _copy_int_to_field(void *dst, const void *src, const size_t dst_len, size_t src_off) {
    copy_int_as_le(dst, (void*) ((uintptr_t) src + src_off), dst_len);
}

static void _copy_str_to_field(void *dst, const void *src, const size_t dst_len, size_t src_off) {
    memcpy(dst, (void*) ((uintptr_t) src + src_off), dst_len);
}

static int _parse_package_header(arp_package_t *pack, const unsigned char header_data[PACKAGE_HEADER_LEN]) {
    if (memcmp(header_data, FORMAT_MAGIC, PACKAGE_MAGIC_LEN) != 0) {
        libarp_set_error("Package magic is incorrect");
        return -1;
    }

    _copy_int_to_field(&pack->major_version, header_data, PACKAGE_VERSION_LEN, PACKAGE_VERSION_OFF);

    if (pack->major_version != 1) {
        libarp_set_error("Package version is not supported");
        return -1;
    }

    _copy_str_to_field(&pack->compression_type, header_data, PACKAGE_COMPRESSION_LEN, PACKAGE_COMPRESSION_OFF);
    _copy_str_to_field(&pack->package_namespace, header_data, PACKAGE_NAMESPACE_LEN, PACKAGE_NAMESPACE_OFF);
    _copy_int_to_field(&pack->total_parts, header_data, PACKAGE_PARTS_LEN, PACKAGE_PARTS_OFF);
    _copy_int_to_field(&pack->cat_off, header_data, PACKAGE_CAT_OFF_LEN, PACKAGE_CAT_OFF_OFF);
    _copy_int_to_field(&pack->cat_len, header_data, PACKAGE_CAT_LEN_LEN, PACKAGE_CAT_LEN_OFF);
    _copy_int_to_field(&pack->node_count, header_data, PACKAGE_CAT_CNT_LEN, PACKAGE_CAT_CNT_OFF);
    _copy_int_to_field(&pack->directory_count, header_data, PACKAGE_DIR_CNT_LEN, PACKAGE_DIR_CNT_OFF);
    _copy_int_to_field(&pack->resource_count, header_data, PACKAGE_RES_CNT_LEN, PACKAGE_RES_CNT_OFF);
    _copy_int_to_field(&pack->body_off, header_data, PACKAGE_BODY_OFF_LEN, PACKAGE_BODY_OFF_OFF);
    _copy_int_to_field(&pack->body_len, header_data, PACKAGE_BODY_LEN_LEN, PACKAGE_BODY_LEN_OFF);

    return 0;
}

static int _validate_package_header(const arp_package_t *pack, const uint64_t pack_size) {
    if (pack->compression_type[0] != '\0'
            && memcmp(pack->compression_type, ARP_COMPRESS_MAGIC_DEFLATE, PACKAGE_COMPRESSION_LEN) != 0) {
        libarp_set_error("Package compression type is not supported");
        return EINVAL;
    }

    if (validate_path_component(pack->package_namespace,
            MIN(strlen(pack->package_namespace), PACKAGE_NAMESPACE_LEN)) != 0) {
        return EINVAL;
    }

    if (pack->total_parts < 1 || pack->total_parts > PACKAGE_MAX_PARTS) {
        libarp_set_error("Package part count is invalid");
        return EINVAL;
    }

    if (pack->node_count == 0) {
        libarp_set_error("Package catalogue is empty");
        return EINVAL;
    }

    if (pack->resource_count == 0) {
        libarp_set_error("Package does not contain any resources");
        return EINVAL;
    }

    if (pack->cat_off < PACKAGE_HEADER_LEN) {
        libarp_set_error("Package catalogue offset is too small");
        return EINVAL;
    }

    if (pack->body_off < PACKAGE_HEADER_LEN) {
        libarp_set_error("Package body offset is too small");
        return EINVAL;
    }

    if (pack->cat_off + pack->cat_len > pack_size) {
        libarp_set_error("Package catalogue offset and length are incorrect");
        return EINVAL;
    }

    if (pack->body_off + pack->body_len > pack_size) {
        libarp_set_error("Package body offset and length are incorrect");
        return EINVAL;
    }

    if (pack->cat_off < pack->body_off && pack->cat_off + pack->cat_len > pack->body_off) {
        libarp_set_error("Package catalogue would overlap body section");
        return EINVAL;
    } else if (pack->body_off < pack->cat_off && pack->body_off + pack->body_len > pack->cat_off) {
        libarp_set_error("Body section would overlap package catalogue");
        return EINVAL;
    }

    if (pack->cat_off > SIZE_MAX || pack->cat_len > SIZE_MAX
            || pack->body_off > SIZE_MAX || pack->body_len > SIZE_MAX) {
        //TODO: work around this at some point
        libarp_set_error("Package is too large to load on a 32-bit architecture");
        return E2BIG;
    }

    return 0;
}

static int _verify_parts_exist(arp_package_t *pack, const char *primary_path) {
    char *real_path = NULL;
    #ifdef _WIN32
    real_path = _fullpath(NULL, primary_path, (size_t) -1);
    #else
    real_path = realpath(primary_path, NULL);
    #endif
    if (real_path == NULL) {
        free(real_path);

        libarp_set_error("Failed to get absolute path of package file");
        return -1;
    }

    size_t real_path_len_s = strlen(real_path);
    size_t real_path_len_b = real_path_len_s + 1;

    const char *file_base = NULL;

    #ifdef _WIN32
    if ((file_base = MAX(strrchr(real_path, '\\'), strrchr(real_path, '/'))) != NULL) {
        file_base += 1;
    } else {
        file_base = real_path;
    }
    #else
    if ((file_base = strrchr(real_path, FS_PATH_DELIMITER)) != NULL) {
        file_base += 1;
    } else {
        file_base = real_path;
    }
    #endif

    // _b = buffer length, includes null terminator
    // _s = string length, does not include null terminator
    size_t file_base_len_s = strlen(file_base);

    if (memcmp(file_base + file_base_len_s - strlen("." PACKAGE_EXT), "." PACKAGE_EXT, sizeof("." PACKAGE_EXT)) != 0) {
        free(real_path);

        libarp_set_error("Unexpected file extension for primary package file");
        return -1;
    }

    size_t stem_len_s = file_base_len_s - strlen("." PACKAGE_EXT);
    size_t stem_len_b = stem_len_s + 1;
    char *file_stem = NULL;
    if ((file_stem = malloc(stem_len_b)) == NULL) {
        free(real_path);

        libarp_set_error("malloc failed");
        return -1;
    }
    memcpy(file_stem, file_base, stem_len_s);
    file_stem[stem_len_b - 1] = '\0';

    char *parent_dir = NULL;
    size_t parent_dir_len_s = 0;
    size_t parent_dir_len_b = 0;
    if (file_base != real_path) {
        parent_dir_len_s = file_base - real_path;
        parent_dir_len_b = parent_dir_len_s + 1;
        if ((parent_dir = malloc(parent_dir_len_b)) == NULL) {
            free(file_stem);
            free(real_path);

            libarp_set_error("malloc failed");
            return -1;
        }
        memcpy(parent_dir, real_path, parent_dir_len_s);
        parent_dir[parent_dir_len_b - 1] = '\0';
    } else {
        parent_dir_len_s = 0;
        parent_dir_len_b = parent_dir_len_s + 1;
        if ((parent_dir = malloc(parent_dir_len_b)) == NULL) {
            free(file_stem);
            free(real_path);

            libarp_set_error("malloc failed");
            return -1;
        }
        parent_dir[parent_dir_len_b - 1] = '\0';
    }

    size_t suffix_index = stem_len_s - strlen(PACKAGE_PART_1_SUFFIX);
    if (stem_len_b > strlen(PACKAGE_PART_1_SUFFIX)
            && memcmp(file_stem + suffix_index, PACKAGE_PART_1_SUFFIX, strlen(PACKAGE_PART_1_SUFFIX)) == 0) {
        stem_len_s -= strlen(PACKAGE_PART_1_SUFFIX);
        stem_len_b = stem_len_s + 1;
        char *file_stem_new = NULL;
        if ((file_stem_new = realloc(file_stem, stem_len_b)) == NULL) {
            free(parent_dir);
            free(file_stem);
            free(real_path);

            libarp_set_error("realloc failed");
            return -1;
        }
        file_stem = file_stem_new;

        file_stem[stem_len_b - 1] = '\0';
    }

    if ((pack->part_paths[0] = malloc(real_path_len_b)) == NULL) {
        free(parent_dir);
        free(file_stem);
        free(real_path);

        libarp_set_error("malloc failed");
        return -1;
    }

    memcpy(pack->part_paths[0], real_path, real_path_len_b);

    free(real_path);

    int rc = UNINIT_U32;

    bool part_err = false;
    for (int i = 2; i <= pack->total_parts; i++) {
        char *part_path = NULL;
        size_t part_path_len_s = parent_dir_len_s
                + 1
                + stem_len_s
                + strlen(".part000")
                + strlen("." PACKAGE_EXT);
        size_t part_path_len_b = part_path_len_s + 1;

        if ((part_path = malloc(part_path_len_b)) == NULL) {
            libarp_set_error("malloc failed");

            part_err = true;
            break;
        }

        sprintf(part_path, "%s%s.part%03d." PACKAGE_EXT, parent_dir, file_stem, i);

        if ((pack->part_paths[i - 1] = malloc(part_path_len_b)) == NULL) {
            free(part_path);

            libarp_set_error("malloc failed");

            part_err = true;
            break;
        }

        memcpy(pack->part_paths[i - 1], part_path, part_path_len_b);

        stat_t part_stat;
        if (stat(part_path, &part_stat) != 0) {
            free(part_path);

            libarp_set_error("Failed to stat part file");

            rc = errno;
            part_err = true;
            break;
        }

        if (!S_ISREG(part_stat.st_mode)) {
            free(part_path);

            libarp_set_error("Part file must be regular file or symlink to regular file");

            rc = EINVAL;
            part_err = EINVAL;
            break;
        }

        if (part_stat.st_size < PACKAGE_PART_HEADER_LEN) {
            free(part_path);

            libarp_set_error("Package part file is too small");
            
            rc = EINVAL;
            part_err = true;
            break;
        }
        
        FILE *part_file = fopen(part_path, "r");

        free(part_path);
        part_path = NULL;

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
            
            part_err = true;
            break;
        }

        unsigned char part_header[PACKAGE_PART_HEADER_LEN];
        if (fread(part_header, PACKAGE_PART_HEADER_LEN, 1, part_file) != 1) {
            rc = ferror(part_file);
            if (rc == 0) {
                rc = -1;
            }
            fclose(part_file);

            libarp_set_error("Failed to read package part header");
            
            part_err = true;
            break;
        }

        fclose(part_file);

        if (memcmp(part_header, PART_MAGIC, PART_MAGIC_LEN) != 0) {
            libarp_set_error("Package part magic is invalid");
            
            rc = EINVAL;
            part_err = true;
            break;
        }

        uint16_t part_index = 0;
        copy_int_as_le(&part_index, offset_ptr(part_header, PART_INDEX_OFF), PART_INDEX_LEN);
        if (part_index != i) {
            libarp_set_error("Package part index is incorrect");
            
            rc = EINVAL;
            part_err = true;
            break;
        }
    }

    free(file_stem);
    free(parent_dir);

    return part_err ? rc : 0;
}

static int _compare_node_names(const node_desc_t *a, const node_desc_t *b) {
    return memcmp(a->name, b->name, MIN(a->name_len_s, b->name_len_s));
}

static int _read_var_string(const void *catalogue, size_t off, char **target, size_t str_len_s) {
    assert(str_len_s < VAR_STR_BUF_LEN);

    size_t str_len_b = str_len_s + 1;

    if (str_len_s > 0) {
        char tmp[VAR_STR_BUF_LEN];
        _copy_str_to_field(tmp, catalogue, str_len_s, off);
        tmp[str_len_s] = '\0';

        if ((*target = malloc(str_len_b)) == NULL) {
            libarp_set_error("malloc failed");
            return -1;
        }
        memcpy(*target, tmp, str_len_b);
    } else {
        *target = NULL;
    }

    return 0;
}

static int _parse_package_catalogue(arp_package_t *pack, const void *pack_data_view) {
    if ((pack->all_nodes = calloc(1, pack->node_count * sizeof(void*))) == NULL) {
        libarp_set_error("calloc failed");
        return -1;
    }

    unsigned char *catalogue = (unsigned char*) ((uintptr_t) pack_data_view + pack->cat_off);
    
    size_t node_start = 0;
    uint32_t real_node_count = 0;
    uint32_t real_resource_count = 0;
    for (size_t i = 0; i < pack->node_count; i++) {
        if (pack->cat_len - node_start < ND_LEN_LEN) {
            libarp_set_error("Catalogue underflow");

            return -1;
        }

        if (real_node_count > UINT32_MAX) {
            libarp_set_error("Package contains too many nodes");
            return E2BIG;
        }
        
        real_node_count += 1;
        if (real_node_count > pack->node_count) {
            libarp_set_error("Actual node count mismatches header field");
        }

        uint16_t node_desc_len = 0;
        _copy_int_to_field(&node_desc_len, catalogue, ND_LEN_LEN, node_start + ND_LEN_OFF);

        if (node_desc_len < NODE_DESC_BASE_LEN) {
            libarp_set_error("Node descriptor is too small");
            return -1;
        } else if (node_desc_len > NODE_DESC_MAX_LEN) {
            libarp_set_error("Node descriptor is too large");
            return -1;
        } else if (pack->cat_len - node_start < node_desc_len) {
            libarp_set_error("Catalogue underflow");
            return -1;
        }

        node_desc_t *node = NULL;
        if ((node = malloc(sizeof(node_desc_t))) == NULL) {
            libarp_set_error("malloc failed");
            return -1;
        }

        node->children_tree.initialized = false;

        node->loaded_data = NULL;

        pack->all_nodes[i] = node;

        node->package = pack;
        node->index = i;

        _copy_int_to_field(&node->type, catalogue, ND_TYPE_LEN, node_start + ND_TYPE_OFF);
        _copy_int_to_field(&node->part_index, catalogue, ND_PART_LEN, node_start + ND_PART_OFF);
        _copy_int_to_field(&node->data_off, catalogue, ND_DATA_OFF_LEN, node_start + ND_DATA_OFF_OFF);
        _copy_int_to_field(&node->packed_data_len, catalogue, ND_PACKED_DATA_LEN_LEN, node_start + ND_PACKED_DATA_LEN_OFF);
        _copy_int_to_field(&node->unpacked_data_len, catalogue, ND_UNPACKED_DATA_LEN_LEN, node_start + ND_UNPACKED_DATA_LEN_OFF);
        memcpy(&node->crc, catalogue + node_start + ND_CRC_OFF, ND_CRC_LEN);
        _copy_int_to_field(&node->name_len_s, catalogue, ND_NAME_LEN_LEN, node_start + ND_NAME_LEN_OFF);
        _copy_int_to_field(&node->ext_len_s, catalogue, ND_EXT_LEN_LEN, node_start + ND_EXT_LEN_OFF);
        _copy_int_to_field(&node->media_type_len_s, catalogue, ND_MT_LEN_LEN, node_start + ND_MT_LEN_OFF);

        if (NODE_DESC_BASE_LEN + node->name_len_s + node->media_type_len_s > node_desc_len) {
            libarp_set_error("Variable string lengths mismatch descriptor length");
            return -1;
        }

        if (i == 0 && node->name_len_s > 0) {
            libarp_set_error("Root node name must be empty string");
            return -1;
        }

        if (node->type == PACK_NODE_TYPE_DIRECTORY && node->media_type_len_s > 0) {
            libarp_set_error("Directory nodes may not have media types");
            return -1;
        }

        size_t name_off = node_start + ND_NAME_OFF;
        size_t ext_off = name_off + node->name_len_s;
        size_t mt_off = ext_off + node->ext_len_s;

        _read_var_string(catalogue, name_off, &node->name, node->name_len_s);
        _read_var_string(catalogue, ext_off, &node->ext, node->ext_len_s);
        _read_var_string(catalogue, mt_off, &node->media_type, node->media_type_len_s);

        node_start = mt_off + node->media_type_len_s;

        validate_path_component(node->name, node->name_len_s);

        if (node->type != PACK_NODE_TYPE_RESOURCE && node->type != PACK_NODE_TYPE_DIRECTORY) {
            libarp_set_error("Invalid node type");
            return -1;
        }

        if (node->type == PACK_NODE_TYPE_DIRECTORY) {
            if (node->part_index != 1) {
                libarp_set_error("Directory node content must be in primary part");
                return -1;
            }

            if ((node->packed_data_len % 4) != 0) {
                libarp_set_error("Directory content length must be divisible by 4");
                return -1;
            }

            if (node->unpacked_data_len > DIRECTORY_CONTENT_MAX_LEN) {
                libarp_set_error("Directory contains too many files");
                return -1;
            }
        } else if (node->type == PACK_NODE_TYPE_RESOURCE) {
            if (real_resource_count > UINT32_MAX) {
                libarp_set_error("Package contains too many resources");
                return E2BIG;
            }

            real_resource_count += 1;
        }
    }

    if (real_node_count != pack->node_count) {
        libarp_set_error("Actual node count mismatches header field");
        return -1;
    }

    if (real_resource_count != pack->resource_count) {
        libarp_set_error("Actual resource count mismatches header field");
        return -1;
    }

    unsigned char *body = (unsigned char*) ((uintptr_t) pack_data_view + pack->body_off);

    for (uint64_t i = 0; i < pack->node_count; i++) {
        node_desc_t *node = pack->all_nodes[i];
        
        if (node->type != PACK_NODE_TYPE_DIRECTORY) {
            continue;
        }

        uint64_t child_count = node->packed_data_len / 4;

        if (child_count >= SIZE_MAX) {
            libarp_set_error("Too many directory children to store in binary tree");
            return E2BIG;
        }

        uint32_t *node_children = (uint32_t*) ((uintptr_t) body + node->data_off);

        if (bt_create((size_t) (child_count + 1), &node->children_tree) == NULL) {
            return errno;
        }

        for (size_t j = 0; j < child_count; j++) {
            uint32_t child_index = node_children[j];

            if (child_index == 0 || child_index >= pack->node_count) {
                libarp_set_error("Illegal node index in directory");
                return EINVAL;
            }

            bt_insert(&node->children_tree, pack->all_nodes[child_index], (BtInsertCmpFn) _compare_node_names);
        }
    }

    return 0;
}

int load_package_from_file(const char *path, ArpPackage *package) {
    stat_t package_file_stat;
    if (stat(path, &package_file_stat) != 0) {
        libarp_set_error("Failed to stat package file");
        return EINVAL;
    }

    if (!S_ISREG(package_file_stat.st_mode)) {
        libarp_set_error("Source path must point to regular file or symlink to regular file");
        return EINVAL;
    }

    size_t package_file_size = package_file_stat.st_size;

    if (package_file_size < PACKAGE_HEADER_LEN) {
        libarp_set_error("File is too small to contain package header");
        return -1;
    }

    FILE *package_file = fopen(path, "r");

    if (package_file == NULL) {
        libarp_set_error("Failed to open package file");
        return -1;
    }

    unsigned char pack_header[PACKAGE_HEADER_LEN];
    memset(pack_header, 0, PACKAGE_HEADER_LEN);

    if (fread(pack_header, PACKAGE_HEADER_LEN, 1, package_file) != 1) {
        fclose(package_file);

        libarp_set_error("Failed to read package header from file");
        return -1;
    }

    arp_package_t *pack = NULL;
    if ((pack = calloc(1, sizeof(arp_package_t))) == NULL) {
        fclose(package_file);

        libarp_set_error("calloc failed");
        return -1;
    }

    int rc = UNINIT_U32;
    if ((rc = _parse_package_header(pack, pack_header)) != 0) {
        unload_package(pack);
        fclose(package_file);

        return rc;
    }

    if ((rc = _validate_package_header(pack, package_file_size)) != 0) {
        unload_package(pack);
        fclose(package_file);

        return rc;
    }

    if ((pack->part_paths = calloc(pack->total_parts, sizeof(void*))) == NULL) {
        unload_package(pack);
        fclose(package_file);

        libarp_set_error("calloc failed");
        return -1;
    }

    if ((rc = _verify_parts_exist(pack, path)) != 0) {
        unload_package(pack);
        fclose(package_file);

        return rc;
    }

    void *pack_data_view = NULL;
    #ifdef _WIN32
    HANDLE win32_pack_file = (HANDLE) _get_osfhandle(_fileno(package_file));

    HANDLE file_mapping = CreateFileMapping(win32_pack_file, NULL, PAGE_READONLY,
            package_file_size >> 32, package_file_size & 0xFFFFFFFF, NULL);

    if (file_mapping == NULL) {
        unload_package(pack);
        fclose(package_file);

        libarp_set_error("Failed to memory-map package file\n");
        return GetLastError();
    }

    if ((pack_data_view = MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, package_file_size)) == NULL) {
        CloseHandle(file_mapping);
        unload_package(pack);
        fclose(package_file);

        libarp_set_error("Failed to map view of package file\n");
        return GetLastError();
    }
    #else
    pack_data_view = mmap(NULL, package_file_size, PROT_READ, MAP_PRIVATE, fileno(package_file), 0);
    #endif

    rc = _parse_package_catalogue(pack, pack_data_view);

    #ifdef _WIN32
    UnmapViewOfFile(pack_data_view);
    // An great exmaple of why the Win32 API sucks. Why would you want one
    // function to deal with 19 different types of handles? It just makes
    // for more ambiguous code.
    CloseHandle(file_mapping);
    #else
    munmap(pack_data_view, pack->cat_len);
    #endif

    fclose(package_file);

    if (rc != 0) {
        unload_package(pack);

        return rc;
    }

    *package = pack;
    return 0;
}

int load_package_from_memory(const unsigned char *data, size_t package_len, ArpPackage *package) {
    if (package_len < PACKAGE_HEADER_LEN) {
        libarp_set_error("Package is too small to contain package header");
        return -1;
    }

    unsigned char pack_header[PACKAGE_HEADER_LEN];

    memcpy(pack_header, data, PACKAGE_HEADER_LEN);

    arp_package_t *pack = NULL;
    if ((pack = calloc(1, sizeof(arp_package_t))) == NULL) {
        return ENOMEM;
    }

    int rc = UNINIT_U32;
    if ((rc = _parse_package_header(pack, pack_header)) != 0) {
        unload_package(pack);
        return rc;
    }

    if ((rc = _validate_package_header(pack, package_len)) != 0) {
        unload_package(pack);
        return rc;
    }

    rc = _parse_package_catalogue(pack, data);

    if (pack->total_parts > 1) {
        unload_package(pack);

        libarp_set_error("Memory-resident packages may not contain more than 1 part");
        return -1;
    }

    *package = pack;
    return 0;
}

static void _unload_node(node_desc_t *node) {
    if (node != NULL) {
        if (node->loaded_data != NULL) {
            if (node->loaded_data->data != NULL) {
                free(node->loaded_data->data);
            }
            free(node->loaded_data);
        }
        
        if (node->children_tree.initialized) {
            bt_free(&node->children_tree);
        }

        if (node->name != NULL) {
            free(node->name);
        }

        if (node->ext != NULL) {
            free(node->ext);
        }

        if (node->media_type != NULL) {
            free(node->media_type);
        }
        
        free(node);
    }
}

int unload_package(ArpPackage package) {
    arp_package_t *real_pack = (arp_package_t*)package;

    if (real_pack->all_nodes != NULL) {
        for (uint32_t i = 0; i < real_pack->node_count; i++) {
            node_desc_t *node = (real_pack->all_nodes)[i];
            _unload_node(node);
        }

        free(real_pack->all_nodes);
    }

    if (real_pack->part_paths != NULL) {
        for (uint16_t i = 0; i < real_pack->total_parts; i++) {
            char *part_path = real_pack->part_paths[i];
            if (part_path == NULL) {
                break;
            }
            free(part_path);
        }

        free(real_pack->part_paths);
    }

    free(package);
    return 0;
}

static int _cmp_node_names(const void *a, const void *b) {
    node_desc_t *real_a = (node_desc_t*) a;
    node_desc_t *real_b = (node_desc_t*) b;
    return strncmp(real_a->name, real_b->name, MIN(real_a->name_len_s, real_b->name_len_s));
}

static int _cmp_node_name_to_needle(const void *name, const void *node) {
    node_desc_t *real_node = (node_desc_t*) node;
    return strncmp(name, real_node->name, real_node->name_len_s);
}

static int _validate_part_file(FILE *file, const node_desc_t *node) {
    stat_t part_stat;
    if (fstat(fileno(file), &part_stat) != 0) {
        libarp_set_error("Failed to stat part file");
        return -1;
    }

    if ((size_t) part_stat.st_size < PACKAGE_PART_HEADER_LEN + node->data_off + node->packed_data_len) {
        libarp_set_error("Part file is too small to fit node data");
        return -1;
    }

    return 0;
}

static int _seek_to_node(FILE *part_file, const node_desc_t *node) {
    size_t part_body_start = 0;
    if (node->part_index == 1) {
        part_body_start = node->package->body_off;
    } else {
        part_body_start = PACKAGE_PART_HEADER_LEN;
    }

    int rc = UNINIT_U32;
    if ((rc = fseek(part_file, (long) (part_body_start + node->data_off), SEEK_SET)) != 0) {
        libarp_set_error("Failed to seek to node offset");
        return rc;
    }

    return 0;
}

static FILE *_open_part_file_for_node(const node_desc_t *node) {
    if (node->part_index > node->package->total_parts) {
        libarp_set_error("Node part index is invalid");
        return NULL;
    }

    FILE *part_file = fopen(node->package->part_paths[node->part_index - 1], "rb");
    if (part_file == NULL) {
        libarp_set_error("Failed to open part file for loading");
        return NULL;
    }

    if (_validate_part_file(part_file, node) != 0) {
        fclose(part_file);
        return NULL;
    }

    if (_seek_to_node(part_file, node) != 0) {
        fclose(part_file);
        return NULL;
    }

    return part_file;
}

static int _unpack_node_data(const node_desc_t *node, FILE *out_file,
        void **out_data, size_t *out_data_len, FILE *part) {
    assert((out_data != NULL) ^ (out_file != NULL)); // only one can be supplied

    int rc = UNINIT_U32;

    arp_package_t *pack = node->package;

    FILE *part_file = NULL;
    if (part != NULL) {
        part_file = part;

        if ((rc = _validate_part_file(part, node)) != 0) {
            return rc;
        }

        if ((rc = _seek_to_node(part, node)) != 0) {
            return rc;
        }
    } else {
        if ((part_file = _open_part_file_for_node(node)) == NULL) {
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
                int rc = UNINIT_U32;
                if ((rc = decompress_deflate(compress_data, read_buf, to_read,
                        &unpacked_chunk, &unpacked_chunk_len)) != 0) {
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
            memcpy((void*) ((uintptr_t) unpacked_data + written_bytes), unpacked_chunk, unpacked_chunk_len);
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

int get_resource_meta(ConstArpPackage package, const char *path, arp_resource_meta_t *out_meta) {
        const arp_package_t *real_pack = (const arp_package_t*) package;

    size_t path_len_s = strlen(path);

    char *path_copy = NULL;
    if ((path_copy = malloc(path_len_s + 1)) == NULL) {
        libarp_set_error("malloc failed");
        return ENOMEM;
    }

    memcpy(path_copy, path, path_len_s + 1);
    char *path_tail = path_copy;
    size_t cursor = 0;
    char *needle = NULL;

    if ((needle = strchr(path_tail, ARP_NAMESPACE_DELIMITER)) == NULL) {
        free(path_copy);

        libarp_set_error("Path must contain a namespace");
        return EINVAL;
    }

    cursor = needle - path_tail;

    size_t namespace_len_s = cursor;
    path_tail[cursor] = '\0';
    if (strlen(real_pack->package_namespace) != namespace_len_s
            || strncmp(path_tail, real_pack->package_namespace, MIN(namespace_len_s, PACKAGE_NAMESPACE_LEN)) != 0) {
        free(path_copy);

        libarp_set_error("Namespace does not match package");
        return EINVAL;
    }

    path_tail += cursor + 1;

    // start at root
    node_desc_t *node = real_pack->all_nodes[0];

    while ((needle = strchr(path_tail, ARP_PATH_DELIMITER)) != NULL) {
        cursor = needle - path_tail;

        path_tail[cursor] = '\0';

        node = bt_find(&node->children_tree, path_tail, _cmp_node_names);
        if (node == NULL) {
            free(path_copy);

            libarp_set_error("Resource does not exist at the specified path");
            return ENOENT;
        }

        path_tail += cursor + 1;
    }

    // should be at terminal component now
    node = bt_find(&node->children_tree, path_tail, _cmp_node_name_to_needle);
    if (node == NULL) {
        free(path_copy);

        libarp_set_error("Resource does not exist at the specified path");
        return ENOENT;
    }

    free(path_copy);

    if (node->type == PACK_NODE_TYPE_DIRECTORY) {
        libarp_set_error("Requested path points to directory");
        return EISDIR;
    }

    arp_resource_meta_t meta;

    meta.package = node->package;
    meta.base_name = node->name;
    meta.extension = node->ext;
    meta.media_type = node->media_type;
    meta.size = node->unpacked_data_len;
    meta.extra = node;

    memcpy(out_meta, &meta, sizeof(arp_resource_meta_t));

    return 0;
}

arp_resource_t *load_resource(arp_resource_meta_t *meta) {
    node_desc_t *node = (node_desc_t*) meta->extra;

    if (node->loaded_data != NULL) {
        return node->loaded_data;
    }

    void *res_data = NULL;
    size_t res_data_len = 0;
    int rc = 0;
    if ((rc = _unpack_node_data(node, NULL, &res_data, &res_data_len, NULL)) != 0) {
        errno = rc;
        return NULL;
    }

    arp_resource_t *res = NULL;
    if ((res = malloc(sizeof(arp_resource_t))) == NULL) {
        free(res_data);

        libarp_set_error("malloc failed");
        errno = ENOMEM;
        return NULL;
    }

    // important to note: arp_resource_t contains a copy of the meta, not just a pointer
    res->meta.base_name = node->name;
    res->meta.extension = node->ext;
    res->meta.media_type = node->media_type;
    res->meta.size = res_data_len;
    res->meta.extra = node;

    res->data = res_data;

    node->loaded_data = res;

    return res;
}

void unload_resource(arp_resource_t *resource) {
    if (resource == NULL) {
        return;
    }

    if (resource->data != NULL) {
        free(resource->data);
    }

    ((node_desc_t*) resource->meta.extra)->loaded_data = NULL;

    free(resource);
}

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

    if ((stream->file = _open_part_file_for_node(node)) == NULL) {
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

int _unpack_node_to_fs(node_desc_t *node, const char *cur_dir,
        uint16_t *last_part_index, FILE **last_part);

int _unpack_node_to_fs(node_desc_t *node, const char *cur_dir,
        uint16_t *last_part_index, FILE **last_part) {
    int rc = UNINIT_U32;

    assert((last_part == NULL) == (last_part_index == NULL));

    arp_package_t *pack = node->package;

    if (node->type == PACK_NODE_TYPE_DIRECTORY) {
        size_t new_dir_path_len_s = strlen(cur_dir) + 1 + node->name_len_s + 1;
        size_t new_dir_path_len_b = new_dir_path_len_s + 1;

        char *new_dir_path = NULL;

        if (node->index == 0) {
            new_dir_path = strdup(cur_dir);
        } else {
            if ((new_dir_path = malloc(new_dir_path_len_b)) == NULL) {
                libarp_set_error("malloc failed");
                return ENOMEM;
            }

            snprintf(new_dir_path, new_dir_path_len_b, "%s%c%s", cur_dir, FS_PATH_DELIMITER, node->name);
        }
        
        stat_t dir_stat;
        if (stat(new_dir_path, &dir_stat) != 0) {
            if (errno == ENOENT) {
                if (mkdir(new_dir_path, 0755) != 0) {
                    free(new_dir_path);

                    char err_msg[ERR_MSG_MAX_LEN];
                    snprintf(err_msg, ERR_MSG_MAX_LEN, "Failed to create directory (rc: %d)", errno);
                    libarp_set_error(err_msg);
                    return errno;
                }
            } else {
                free(new_dir_path);

                char err_msg[ERR_MSG_MAX_LEN];
                snprintf(err_msg, ERR_MSG_MAX_LEN, "Failed to stat directory (rc: %d)", errno);
                libarp_set_error(err_msg);
                return errno;
            }
        }

        node_desc_t **child_ptr = NULL;
        bt_reset_iterator(&node->children_tree);
        while ((child_ptr = (node_desc_t**) bt_iterate(&node->children_tree)) != NULL) {
            rc = _unpack_node_to_fs(*child_ptr, new_dir_path, last_part_index, last_part);
            if (rc != 0) {
                free(new_dir_path);

                return rc;
            }
        }

        free(new_dir_path);

        return 0;
    } else if (node->type == PACK_NODE_TYPE_RESOURCE) {
        if (node->part_index == 0 || node->part_index > pack->total_parts) {
            libarp_set_error("Node part index is invalid");
            return -1;
        }

        if (last_part != NULL && *last_part != NULL && node->part_index != *last_part_index) {
            fclose(*last_part);
        }

        FILE *cur_part = NULL;

        if (last_part_index == NULL || node->part_index != *last_part_index) {
            if (last_part_index != NULL) {
                *last_part_index = node->part_index;
            }

            if ((cur_part = _open_part_file_for_node(node)) == NULL) {
                return errno;
            }

            if (last_part != NULL) {
                *last_part = cur_part;
            }
        } else {
            cur_part = *last_part;
        }

        size_t res_path_len_s = strlen(cur_dir) + 1 + node->name_len_s + 1 + node->ext_len_s;
        size_t res_path_len_b = res_path_len_s + 1;

        char *res_path = NULL;
        if ((res_path = malloc(res_path_len_b)) == NULL) {
            if (last_part == NULL) {
                fclose(cur_part);
            }

            libarp_set_error("malloc failed");
            return ENOMEM;
        }

        snprintf(res_path, res_path_len_b, "%s%c%s%c%s", cur_dir, FS_PATH_DELIMITER, node->name, '.', node->ext);

        FILE *res_file = NULL;
        if ((res_file = fopen(res_path, "w+b")) == NULL) {
            free(res_path);

            if (last_part == NULL) {
                fclose(cur_part);
            }

            libarp_set_error("Failed to open output file for resource");
            return errno;
        }

        rc = _unpack_node_data(node, res_file, NULL, NULL, cur_part);

        fclose(res_file);

        if (last_part == NULL) {
            fclose(cur_part);
        }

        if (rc != 0) {
            unlink(res_path);
            free(res_path);

            return rc;
        }

        free(res_path);

        return 0;
    } else {
        libarp_set_error("Encountered invalid node type");
        return EINVAL;
    }
}

int unpack_arp_to_fs(ConstArpPackage package, const char *target_dir) {
    const arp_package_t *real_pack = (const arp_package_t*) package;

    if (real_pack->node_count == 0) {
        libarp_set_error("Package does not contain any nodes");
        return -1;
    }

    FILE *last_part = NULL;
    uint16_t last_part_index = 0;

    int rc = _unpack_node_to_fs(real_pack->all_nodes[0], target_dir, &last_part_index, &last_part);

    if (last_part != NULL) {
        fclose(last_part);
    }

    return rc;
}

int unpack_resource_to_fs(const arp_resource_meta_t *meta, const char *target_dir) {
    return _unpack_node_to_fs((node_desc_t*) meta->extra, target_dir, NULL, NULL);
}

int _list_node_contents(node_desc_t *node, const char *pack_ns, const char *running_path,
        arp_resource_listing_t *listing_arr, size_t *cur_off);

int _list_node_contents(node_desc_t *node, const char *pack_ns, const char *running_path,
        arp_resource_listing_t *listing_arr, size_t *cur_off) {
    if (*cur_off == SIZE_MAX) {
        libarp_set_error("Too many nodes");
        return -1;
    }

    if (node->type == PACK_NODE_TYPE_RESOURCE) {
        size_t path_len_s = strlen(running_path)
                + node->name_len_s;
        size_t path_len_b = path_len_s + 1;

        char *buf = NULL;
        if ((buf = malloc(path_len_b)) == NULL) {
            libarp_set_error("malloc failed");
            return ENOMEM;
        }

        char *path = buf;
        snprintf(path, path_len_b, "%s%s", running_path, node->name);

        arp_resource_listing_t *listing = &listing_arr[*cur_off];
        *cur_off += 1;

        listing->path = path;
        listing->meta.base_name = node->name;
        listing->meta.extension = node->ext;
        listing->meta.media_type = node->media_type;

        return 0;
    } else if (node->type == PACK_NODE_TYPE_DIRECTORY) {
        char *base_running_path = NULL;

        if (running_path != NULL) {
            base_running_path = strdup(running_path);
        } else {
            size_t brp_len_s = strlen(pack_ns) + 2;
            base_running_path = malloc(brp_len_s);
            snprintf(base_running_path, brp_len_s, "%s%c", pack_ns, ARP_NAMESPACE_DELIMITER);
        }

        int rc = UNINIT_U32;

        node_desc_t **child_ptr = NULL;
        bt_reset_iterator(&node->children_tree);
        while ((child_ptr = (node_desc_t**) bt_iterate(&node->children_tree)) != NULL) {
            node_desc_t *child = *child_ptr;

            if (child == NULL) {
                continue;
            }

            char *new_running_path = base_running_path;

            if (child->name != NULL && strlen(child->name) > 0) {
                if (child->type == PACK_NODE_TYPE_DIRECTORY) {
                    char *child_name = child->name != NULL ? child->name : "";

                    size_t new_rp_len_s = strlen(base_running_path) + 1 + strlen(child_name);
                    size_t new_rp_len_b = new_rp_len_s + 1;

                    if ((new_running_path = malloc(new_rp_len_b)) == NULL) {
                        if (base_running_path != running_path) {
                            free(base_running_path);
                        }

                        libarp_set_error("malloc failed");
                        return ENOMEM;
                    }

                    snprintf(new_running_path, new_rp_len_b, "%s%s%c", base_running_path, child_name,
                            ARP_PATH_DELIMITER);
                }
            }

            rc = _list_node_contents(child, pack_ns, new_running_path,
                    listing_arr, cur_off);

            if (new_running_path != base_running_path) {
                free(new_running_path);
            }

            if (rc != 0) {
                free(base_running_path);
                return rc;
            }
        }

        if (base_running_path != running_path) {
            free(base_running_path);
        }

        return 0;
    } else {
        libarp_set_error("Unrecognized node type");
        return -1;
    }
}

int get_resource_listing(ConstArpPackage package, arp_resource_listing_t **listing_arr_out, size_t *count_out) {
    *listing_arr_out = NULL;
    *count_out = 0;

    if (package == NULL) {
        libarp_set_error("Package cannot be null");
        return -1;
    }

    const arp_package_t *real_pack = (const arp_package_t*) package;

    if (real_pack->resource_count == 0) {
        libarp_set_error("Package contains no resources");
        return -1;
    }

    node_desc_t *root_node = real_pack->all_nodes[0];
    if (root_node->type != PACK_NODE_TYPE_DIRECTORY) {
        libarp_set_error("Root package node is not a directory");
        return -1;
    }

    arp_resource_listing_t *listing_arr = NULL;
    if ((listing_arr = calloc(real_pack->resource_count, sizeof(arp_resource_listing_t))) == NULL) {
        libarp_set_error("calloc failed");
        return ENOMEM;
    }

    int rc = UNINIT_U32;

    size_t cur_off = 0;
    if ((rc = _list_node_contents(real_pack->all_nodes[0], real_pack->package_namespace, NULL, listing_arr, &cur_off)) != 0) {
        free(listing_arr);
        
        return rc;
    }

    *listing_arr_out = listing_arr;
    *count_out = cur_off;

    return 0;
}

void free_resource_listing(arp_resource_listing_t *listing, size_t count) {
    if (listing == NULL) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        if (listing->path != NULL) {
            free(listing->path);
        }
    }

    free(listing);
}
