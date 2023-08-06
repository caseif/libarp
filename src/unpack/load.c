/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "arp/unpack/load.h"
#include "arp/util/defines.h"
#include "internal/defines/file.h"
#include "internal/defines/misc.h"
#include "internal/unpack/types.h"
#include "internal/util/common.h"
#include "internal/util/error.h"
#include "internal/util/util.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <intrin.h>
#include <io.h>
#include <memoryapi.h>
#include <windows.h>
#else
#include <immintrin.h>
#include <sys/mman.h>
#endif

#define VAR_STR_BUF_LEN 256

static void _copy_int_to_field(void *dst, const void *src, const size_t dst_len, size_t src_off) {
    copy_int_as_le(dst, (void*) ((uintptr_t) src + src_off), dst_len);
}

static void _copy_str_to_field(void *dst, const void *src, const size_t dst_len, size_t src_off) {
    memcpy(dst, (void*) ((uintptr_t) src + src_off), dst_len);
}

static int _compare_node_names(const node_desc_t *a, const node_desc_t *b) {
    return strncmp(a->name, b->name, MIN(a->name_len_s + 1, b->name_len_s + 1));
}

static int _read_var_string(const void *catalogue, size_t off, char **target, size_t str_len_s) {
    assert(str_len_s < VAR_STR_BUF_LEN);

    size_t str_len_b = str_len_s + 1;

    //if (str_len_s > 0) {
        char tmp[VAR_STR_BUF_LEN];
        _copy_str_to_field(tmp, catalogue, str_len_s, off);
        tmp[str_len_s] = '\0';

        if ((*target = malloc(str_len_b)) == NULL) {
            arp_set_error("malloc failed");
            return -1;
        }
        memcpy(*target, tmp, str_len_b);
    //} else {
        //*target = "";
    //}

    return 0;
}

static int _parse_package_header(arp_package_meta_t *meta, const unsigned char header_data[PACKAGE_HEADER_LEN]) {
    if (memcmp(header_data, FORMAT_MAGIC, PACKAGE_MAGIC_LEN) != 0) {
        arp_set_error("Package magic is incorrect");
        return -1;
    }

    uint16_t major_version;
    _copy_str_to_field(&major_version, header_data, PACKAGE_VERSION_LEN, PACKAGE_VERSION_OFF);

    if (major_version != 1) {
        arp_set_error("Package version is not supported");
        return -1;
    }

    meta->major_version = major_version;

    _copy_str_to_field(&meta->compression_type, header_data, PACKAGE_COMPRESSION_LEN, PACKAGE_COMPRESSION_OFF);
    meta->compression_type[PACKAGE_COMPRESSION_LEN] = '\0';
    _copy_str_to_field(&meta->package_namespace, header_data, PACKAGE_NAMESPACE_LEN, PACKAGE_NAMESPACE_OFF);
    meta->package_namespace[PACKAGE_NAMESPACE_LEN] = '\0';
    _copy_int_to_field(&meta->total_parts, header_data, PACKAGE_PARTS_LEN, PACKAGE_PARTS_OFF);
    _copy_int_to_field(&meta->cat_off, header_data, PACKAGE_CAT_OFF_LEN, PACKAGE_CAT_OFF_OFF);
    _copy_int_to_field(&meta->cat_len, header_data, PACKAGE_CAT_LEN_LEN, PACKAGE_CAT_LEN_OFF);
    _copy_int_to_field(&meta->node_count, header_data, PACKAGE_CAT_CNT_LEN, PACKAGE_CAT_CNT_OFF);
    _copy_int_to_field(&meta->directory_count, header_data, PACKAGE_DIR_CNT_LEN, PACKAGE_DIR_CNT_OFF);
    _copy_int_to_field(&meta->resource_count, header_data, PACKAGE_RES_CNT_LEN, PACKAGE_RES_CNT_OFF);
    _copy_int_to_field(&meta->body_off, header_data, PACKAGE_BODY_OFF_LEN, PACKAGE_BODY_OFF_OFF);
    _copy_int_to_field(&meta->body_len, header_data, PACKAGE_BODY_LEN_LEN, PACKAGE_BODY_LEN_OFF);

    return 0;
}

static int _validate_package_header(const arp_package_meta_t *meta, const uint64_t pack_size) {
    if (meta->compression_type[0] != '\0'
            && memcmp(meta->compression_type, ARP_COMPRESS_MAGIC_DEFLATE, PACKAGE_COMPRESSION_LEN) != 0) {
        arp_set_error("Package compression type is not supported");
        return EINVAL;
    }

    if (validate_path_component(meta->package_namespace,
            MIN((uint8_t) strlen(meta->package_namespace), PACKAGE_NAMESPACE_LEN)) != 0) {
        return EINVAL;
    }

    if (meta->total_parts < 1 || meta->total_parts > PACKAGE_MAX_PARTS) {
        arp_set_error("Package part count is invalid");
        return EINVAL;
    }

    if (meta->node_count == 0) {
        arp_set_error("Package catalogue is empty");
        return EINVAL;
    }

    if (meta->resource_count == 0) {
        arp_set_error("Package does not contain any resources");
        return EINVAL;
    }

    if (meta->cat_off < PACKAGE_HEADER_LEN) {
        arp_set_error("Package catalogue offset is too small");
        return EINVAL;
    }

    if (meta->body_off < PACKAGE_HEADER_LEN) {
        arp_set_error("Package body offset is too small");
        return EINVAL;
    }

    if (meta->cat_off + meta->cat_len > pack_size) {
        arp_set_error("Package catalogue offset and length are incorrect");
        return EINVAL;
    }

    if (meta->body_off + meta->body_len > pack_size) {
        arp_set_error("Package body offset and length are incorrect");
        return EINVAL;
    }

    if (meta->cat_off < meta->body_off && meta->cat_off + meta->cat_len > meta->body_off) {
        arp_set_error("Package catalogue would overlap body section");
        return EINVAL;
    } else if (meta->body_off < meta->cat_off && meta->body_off + meta->body_len > meta->cat_off) {
        arp_set_error("Body section would overlap package catalogue");
        return EINVAL;
    }

    if (meta->cat_off > SIZE_MAX || meta->cat_len > SIZE_MAX
            || meta->body_off > SIZE_MAX || meta->body_len > SIZE_MAX) {
        //TODO: work around this at some point
        arp_set_error("Package is too large to load on a 32-bit architecture");
        return E2BIG;
    }

    return 0;
}

static void _copy_metadata_to_package(arp_package_t *pack, arp_package_meta_t *meta) {
    pack->major_version = meta->major_version;
    memcpy(pack->compression_type, meta->compression_type, sizeof(pack->compression_type));
    memcpy(pack->package_namespace, meta->package_namespace, sizeof(pack->package_namespace));
    pack->total_parts = meta->total_parts;
    pack->cat_off = meta->cat_off;
    pack->cat_len = meta->cat_len;
    pack->node_count = meta->node_count;
    pack->directory_count = meta->directory_count;
    pack->resource_count = meta->resource_count;
    pack->body_off = meta->body_off;
    pack->body_len = meta->body_len;
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

        arp_set_error("Failed to get absolute path of package file");
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

        arp_set_error("Unexpected file extension for primary package file");
        return -1;
    }

    size_t stem_len_s = file_base_len_s - strlen("." PACKAGE_EXT);
    size_t stem_len_b = stem_len_s + 1;
    char *file_stem = NULL;
    if ((file_stem = malloc(stem_len_b)) == NULL) {
        free(real_path);

        arp_set_error("malloc failed");
        return -1;
    }
    memcpy(file_stem, file_base, stem_len_s);
    file_stem[stem_len_b - 1] = '\0';

    char *parent_dir = NULL;
    size_t parent_dir_len_s = 0;
    size_t parent_dir_len_b = 0;
    if (file_base != real_path) {
        parent_dir_len_s = SUB_PTRS(file_base, real_path);
        parent_dir_len_b = parent_dir_len_s + 1;
        if ((parent_dir = malloc(parent_dir_len_b)) == NULL) {
            free(file_stem);
            free(real_path);

            arp_set_error("malloc failed");
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

            arp_set_error("malloc failed");
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

            arp_set_error("realloc failed");
            return -1;
        }
        file_stem = file_stem_new;

        file_stem[stem_len_b - 1] = '\0';
    }

    if ((pack->part_paths[0] = malloc(real_path_len_b)) == NULL) {
        free(parent_dir);
        free(file_stem);
        free(real_path);

        arp_set_error("malloc failed");
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
            arp_set_error("malloc failed");

            part_err = true;
            break;
        }

        sprintf(part_path, "%s%s.part%03d." PACKAGE_EXT, parent_dir, file_stem, i);

        if ((pack->part_paths[i - 1] = malloc(part_path_len_b)) == NULL) {
            free(part_path);

            arp_set_error("malloc failed");

            part_err = true;
            break;
        }

        memcpy(pack->part_paths[i - 1], part_path, part_path_len_b);

        stat_t part_stat;
        if (stat(part_path, &part_stat) != 0) {
            free(part_path);

            arp_set_error("Failed to stat part file");

            rc = errno;
            part_err = true;
            break;
        }

        if (!S_ISREG(part_stat.st_mode)) {
            free(part_path);

            arp_set_error("Part file must be regular file or symlink to regular file");

            rc = EINVAL;
            part_err = EINVAL;
            break;
        }

        if (part_stat.st_size < PACKAGE_PART_HEADER_LEN) {
            free(part_path);

            arp_set_error("Package part file is too small");
            
            rc = EINVAL;
            part_err = true;
            break;
        }
        
        FILE *part_file = fopen(part_path, "r");

        free(part_path);
        part_path = NULL;

        if (part_file == NULL) {
            if (errno == ENOENT) {
                arp_set_error("Part file for package is missing");
            } else if (errno == EPERM) {
                arp_set_error("Cannot access part file for package");
            } else if (errno == EIO) {
                arp_set_error("I/O error occurred while accessing part file for package");
            } else {
                arp_set_error("Error occurred accesing part file for package");
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

            arp_set_error("Failed to read package part header");
            
            part_err = true;
            break;
        }

        fclose(part_file);

        if (memcmp(part_header, PART_MAGIC, PART_MAGIC_LEN) != 0) {
            arp_set_error("Package part magic is invalid");
            
            rc = EINVAL;
            part_err = true;
            break;
        }

        uint16_t part_index = 0;
        copy_int_as_le(&part_index, offset_ptr(part_header, PART_INDEX_OFF), PART_INDEX_LEN);
        if (part_index != i) {
            arp_set_error("Package part index is incorrect");
            
            rc = EINVAL;
            part_err = true;
            break;
        }
    }

    free(file_stem);
    free(parent_dir);

    return part_err ? rc : 0;
}

static int _parse_package_catalogue(arp_package_t *pack, const void *pack_data_view) {
    if ((pack->all_nodes = calloc(1, pack->node_count * sizeof(void*))) == NULL) {
        arp_set_error("calloc failed");
        return -1;
    }

    unsigned char *catalogue = (unsigned char*) ((uintptr_t) pack_data_view + pack->cat_off);
    
    size_t node_start = 0;
    uint32_t real_node_count = 0;
    uint32_t real_resource_count = 0;
    for (size_t i = 0; i < pack->node_count; i++) {
        if (pack->cat_len - node_start < ND_LEN_LEN) {
            arp_set_error("Catalogue underflow");

            return -1;
        }

        if (real_node_count > UINT32_MAX) {
            arp_set_error("Package contains too many nodes");
            return E2BIG;
        }
        
        real_node_count += 1;
        if (real_node_count > pack->node_count) {
            arp_set_error("Actual node count mismatches header field");
        }

        uint16_t node_desc_len = 0;
        _copy_int_to_field(&node_desc_len, catalogue, ND_LEN_LEN, node_start + ND_LEN_OFF);

        if (node_desc_len < NODE_DESC_BASE_LEN) {
            arp_set_error("Node descriptor is too small");
            return -1;
        } else if (node_desc_len > NODE_DESC_MAX_LEN) {
            arp_set_error("Node descriptor is too large");
            return -1;
        } else if (pack->cat_len - node_start < node_desc_len) {
            arp_set_error("Catalogue underflow");
            return -1;
        }

        node_desc_t *node = NULL;
        if ((node = malloc(sizeof(node_desc_t))) == NULL) {
            arp_set_error("malloc failed");
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
            arp_set_error("Variable string lengths mismatch descriptor length");
            return -1;
        }

        if (i == 0 && node->name_len_s > 0) {
            arp_set_error("Root node name must be empty string");
            return -1;
        }

        if (node->type == PACK_NODE_TYPE_DIRECTORY && node->media_type_len_s > 0) {
            arp_set_error("Directory nodes may not have media types");
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
            arp_set_error("Invalid node type");
            return -1;
        }

        if (node->type == PACK_NODE_TYPE_DIRECTORY) {
            if (node->part_index != 1) {
                arp_set_error("Directory node content must be in primary part");
                return -1;
            }

            if ((node->packed_data_len % 4) != 0) {
                arp_set_error("Directory content length must be divisible by 4");
                return -1;
            }

            if (node->unpacked_data_len > DIRECTORY_CONTENT_MAX_LEN) {
                arp_set_error("Directory contains too many files");
                return -1;
            }
        } else if (node->type == PACK_NODE_TYPE_RESOURCE) {
            if (real_resource_count > UINT32_MAX) {
                arp_set_error("Package contains too many resources");
                return E2BIG;
            }

            real_resource_count += 1;
        }
    }

    if (real_node_count != pack->node_count) {
        arp_set_error("Actual node count mismatches header field");
        return -1;
    }

    if (real_resource_count != pack->resource_count) {
        arp_set_error("Actual resource count mismatches header field");
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
            arp_set_error("Too many directory children to store in binary tree");
            return E2BIG;
        }

        uint32_t *node_children = (uint32_t*) ((uintptr_t) body + node->data_off);

        if (bt_create((size_t) (child_count + 1), &node->children_tree) == NULL) {
            return errno;
        }

        for (size_t j = 0; j < child_count; j++) {
            uint32_t child_index = node_children[j];

            if (child_index == 0 || child_index >= pack->node_count) {
                arp_set_error("Illegal node index in directory");
                return EINVAL;
            }

            bt_insert(&node->children_tree, pack->all_nodes[child_index], (BtInsertCmpFn) _compare_node_names);
        }
    }

    return 0;
}

int arp_load_from_file(const char *path, arp_package_meta_t *out_meta, ArpPackage *out_package) {
    if (out_meta == NULL && out_package == NULL) {
        arp_set_error("At least one of out_meta and out_package must be non-null.");
        return EINVAL;
    }

    stat_t package_file_stat;
    if (stat(path, &package_file_stat) != 0) {
        arp_set_error("Failed to stat package file");
        return EINVAL;
    }

    if (!S_ISREG(package_file_stat.st_mode)) {
        arp_set_error("Source path must point to regular file or symlink to regular file");
        return EINVAL;
    }

    size_t package_file_size = (size_t) package_file_stat.st_size;

    if (package_file_size < PACKAGE_HEADER_LEN) {
        arp_set_error("File is too small to contain package header");
        return -1;
    }

    FILE *package_file = fopen(path, "r");

    if (package_file == NULL) {
        arp_set_error("Failed to open package file");
        return -1;
    }

    unsigned char pack_header[PACKAGE_HEADER_LEN];
    memset(pack_header, 0, PACKAGE_HEADER_LEN);

    if (fread(pack_header, PACKAGE_HEADER_LEN, 1, package_file) != 1) {
        fclose(package_file);

        arp_set_error("Failed to read package header from file");
        return -1;
    }

    arp_package_meta_t meta;

    int rc = UNINIT_U32;
    if ((rc = _parse_package_header(&meta, pack_header)) != 0) {
        fclose(package_file);

        return rc;
    }

    if ((rc = _validate_package_header(&meta, package_file_size)) != 0) {
        fclose(package_file);

        return rc;
    }

    if (out_package == NULL) {
        assert(out_meta != NULL);

        fclose(package_file);

        memcpy(out_meta, &meta, sizeof(arp_package_meta_t));

        return 0;
    }

    // from here down out_package is guaranteed to be non-null

    arp_package_t *pack = NULL;
    if ((pack = calloc(1, sizeof(arp_package_t))) == NULL) {
        fclose(package_file);

        arp_set_error("calloc failed");
        return -1;
    }
    
    _copy_metadata_to_package(pack, &meta);

    pack->in_mem_body = NULL;

    if ((pack->part_paths = calloc(pack->total_parts, sizeof(void*))) == NULL) {
        arp_unload(pack);
        fclose(package_file);

        arp_set_error("calloc failed");
        return -1;
    }

    if ((rc = _verify_parts_exist(pack, path)) != 0) {
        arp_unload(pack);
        fclose(package_file);

        return rc;
    }

    void *pack_data_view = NULL;
    #ifdef _WIN32
    HANDLE win32_pack_file = (HANDLE) _get_osfhandle(_fileno(package_file));

    HANDLE file_mapping = CreateFileMapping(win32_pack_file, NULL, PAGE_READONLY,
            package_file_size >> 32, package_file_size & 0xFFFFFFFF, NULL);

    if (file_mapping == NULL) {
        arp_unload(pack);
        fclose(package_file);

        arp_set_error("Failed to memory-map package file\n");
        return GetLastError();
    }

    if ((pack_data_view = MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, package_file_size)) == NULL) {
        CloseHandle(file_mapping);
        arp_unload(pack);
        fclose(package_file);

        arp_set_error("Failed to map view of package file\n");
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
        arp_unload(pack);

        return rc;
    }

    if (out_meta != NULL) {
        memcpy(out_meta, &meta, sizeof(arp_package_meta_t));
    }
    *out_package = pack;
    return 0;
}

int arp_load_from_memory(const unsigned char *data, size_t package_len, arp_package_meta_t *out_meta, ArpPackage *out_package) {
    if (out_meta == NULL && out_package == NULL) {
        arp_set_error("At least one of out_meta and out_package must be non-null.");
        return EINVAL;
    }

    if (package_len < PACKAGE_HEADER_LEN) {
        arp_set_error("Package is too small to contain package header");
        return -1;
    }

    unsigned char pack_header[PACKAGE_HEADER_LEN];

    memcpy(pack_header, data, PACKAGE_HEADER_LEN);

    arp_package_meta_t meta;

    int rc = UNINIT_U32;
    if ((rc = _parse_package_header(&meta, pack_header)) != 0) {
        return rc;
    }

    if ((rc = _validate_package_header(&meta, package_len)) != 0) {
        return rc;
    }

    if (out_package == NULL) {
        assert(out_meta != NULL);

        memcpy(out_meta, &meta, sizeof(arp_package_meta_t));

        return 0;
    }

    // from here down out_package is guaranteed to be non-null

    arp_package_t *pack = NULL;
    if ((pack = calloc(1, sizeof(arp_package_t))) == NULL) {
        return ENOMEM;
    }
    
    _copy_metadata_to_package(pack, &meta);

    if ((rc = _parse_package_catalogue(pack, data)) != 0) {
        arp_unload(pack);

        return rc;
    }

    if (pack->total_parts > 1) {
        arp_unload(pack);

        arp_set_error("Memory-resident packages may not contain more than 1 part");
        return -1;
    }

    pack->in_mem_body = (const unsigned char *) ((uintptr_t) data + pack->body_off);

    if (out_meta != NULL) {
        memcpy(out_meta, &meta, sizeof(arp_package_meta_t));
    }
    *out_package = pack;
    return 0;
}

static void _unload_node(node_desc_t *node) {
    if (node != NULL) {
        if (node->loaded_data != NULL) {
            arp_resource_t *res = (arp_resource_t*) node->loaded_data;
            if (res->data != NULL) {
                free(res->data);
            }
            free(res);
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

int arp_unload(ArpPackage package) {
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
