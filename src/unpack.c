/*
 * This file is a part of libarp.
 * Copyright (c) 2020, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "libarp/unpack.h"
#include "internal/bt.h"
#include "internal/common_util.h"
#include "internal/crc32c.h"
#include "internal/file_defines.h"
#include "internal/package_defines.h"
#include "internal/unpack_util.h"
#include "internal/util.h"

#include "zlib.h"

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

#define MIN(a, b) (a < b ? a : b)
#define MAX(a, b) (a > b ? a : b)

#define CHUNK_LEN 262144 // 256K

static void _copy_int_to_field(void *dst, const void *src, const size_t dst_len, size_t *src_off) {
    copy_int_as_le(dst, (void*) ((uintptr_t) src + *src_off), dst_len);

    *src_off += dst_len;
}

static void _copy_str_to_field(void *dst, const void *src, const size_t dst_len, size_t *src_off) {
    memcpy(dst, (void*) ((uintptr_t) src + *src_off), dst_len);
    *src_off += dst_len;
}

static int _parse_package_header(argus_package_t *pack, const unsigned char header_data[PACKAGE_HEADER_LEN]) {
    size_t header_off = 0;

    if (memcmp(header_data, FORMAT_MAGIC, PACKAGE_MAGIC_LEN) != 0) {
        libarp_set_error("Package magic is incorrect");
        return -1;
    }
    header_off += PACKAGE_MAGIC_LEN;

    _copy_int_to_field(&pack->major_version, header_data, PACKAGE_VERSION_LEN, &header_off);

    if (pack->major_version != 1) {
        libarp_set_error("Package version is not supported");
        return -1;
    }

    _copy_str_to_field(&pack->compression_type, header_data, PACKAGE_COMPRESSION_LEN, &header_off);
    _copy_str_to_field(&pack->package_namespace, header_data, PACKAGE_NAMESPACE_LEN, &header_off);
    _copy_int_to_field(&pack->total_parts, header_data, PACKAGE_PARTS_LEN, &header_off);
    _copy_int_to_field(&pack->cat_off, header_data, PACKAGE_CAT_OFF_LEN, &header_off);
    _copy_int_to_field(&pack->cat_len, header_data, PACKAGE_CAT_LEN_LEN, &header_off);
    _copy_int_to_field(&pack->node_count, header_data, PACKAGE_CAT_CNT_LEN, &header_off);
    _copy_int_to_field(&pack->body_off, header_data, PACKAGE_BODY_OFF_LEN, &header_off);
    _copy_int_to_field(&pack->body_len, header_data, PACKAGE_BODY_LEN_LEN, &header_off);

    return 0;
}

static int _validate_package_header(const argus_package_t *pack, const size_t pack_size) {
    if (pack->compression_type[0] != '\0'
            && memcmp(pack->compression_type, COMPRESS_MAGIC_DEFLATE, PACKAGE_MAGIC_LEN) != 0) {
        libarp_set_error("Package compression is not supported");
        return -1;
    }

    if (validate_path_component(pack->package_namespace,
            MIN(strlen(pack->package_namespace), PACKAGE_NAMESPACE_LEN))) {
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

static int _validate_part_files(argus_package_t *pack, const char *primary_path) {
    char *real_path;
    #ifdef _WIN32
    real_path = _fullpath(NULL, primary_path, (size_t) -1);
    #else
    real_path = realpath(primary_path, NULL);
    #endif
    if (real_path == NULL) {
        libarp_set_error("Failed to get absolute path of package file");
        return -1;
    }

    const char *file_base;

    #ifdef _WIN32
    if ((file_base = MAX(strrchr(real_path, '\\'), strrchr(real_path, '/'))) != NULL) {
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
    size_t file_base_len_s = strlen(file_base);

    if (memcmp(file_base + file_base_len_s - sizeof("." PACKAGE_EXT), "." PACKAGE_EXT, sizeof("." PACKAGE_EXT)) != 0) {
        libarp_set_error("Unexpected file extension for primary package file");
        return -1;
    }

    size_t stem_len_b = file_base_len_s - sizeof("." PACKAGE_EXT) + 1;
    char *file_stem;
    if ((file_stem = malloc(stem_len_b)) == NULL) {
        libarp_set_error("malloc failed");
        return -1;
    }
    memcpy(file_stem, file_base, stem_len_b - 1);
    file_stem[stem_len_b - 1] = '\0';

    char *parent_dir;
    size_t parent_dir_len_b;
    if (file_base != real_path) {
        parent_dir_len_b = file_base - real_path + 1;
        if ((parent_dir = malloc(parent_dir_len_b)) == NULL) {
            free(file_stem);
            
            libarp_set_error("malloc failed");
            return -1;
        }
        memcpy(parent_dir, real_path, parent_dir_len_b - 1);
        parent_dir[parent_dir_len_b - 1] = '\0';
    } else {
        parent_dir_len_b = 1;
        if ((parent_dir = malloc(parent_dir_len_b)) == NULL) {
            free(file_stem);
            
            libarp_set_error("malloc failed");
            return -1;
        }
        parent_dir[0] = '\0';
    }

    size_t suffix_index = stem_len_b - 1 - sizeof(PACKAGE_PART_1_SUFFIX);
    if (stem_len_b > sizeof(PACKAGE_PART_1_SUFFIX) - 1
            && memcmp(file_base + suffix_index, PACKAGE_PART_1_SUFFIX, sizeof(PACKAGE_PART_1_SUFFIX) - 1) == 0) {
        stem_len_b -= sizeof(PACKAGE_PART_1_SUFFIX);
        char *file_stem_new;
        if ((file_stem_new = realloc(file_stem, stem_len_b)) == NULL) {
            free(parent_dir);
            free(file_stem);

            libarp_set_error("realloc failed");
            return -1;
        }
        file_stem = file_stem_new;
    }

    if ((pack->part_paths[0] = malloc(file_base_len_s + 1)) == NULL) {
        free(parent_dir);
        free(file_stem);

        libarp_set_error("malloc failed");
        return -1;
    }

    memcpy(pack->part_paths[0], file_base, file_base_len_s);
    pack->part_paths[file_base_len_s] = '\0';

    bool part_err = false;
    for (int i = 2; i <= pack->total_parts; i++) {
        char *part_path;
        size_t part_path_len_b = parent_dir_len_b - 1
                + stem_len_b - 1
                + sizeof(".part000") - 1
                + sizeof("." PACKAGE_EXT);
        if ((part_path = malloc(part_path_len_b)) == NULL) {
            libarp_set_error("malloc failed");

            part_err = true;
            break;
        }
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
            
            part_err = true;
            break;
        }

        stat_t part_stat;
        if (fstat(fileno(part_file), &part_stat) != 0) {
            fclose(part_file);

            libarp_set_error("Failed to stat package part file");
            
            part_err = true;
            break;
        }

        if (part_stat.st_size < PACKAGE_PART_HEADER_LEN) {
            fclose(part_file);

            libarp_set_error("Package part file is too small");
            
            part_err = true;
            break;
        }

        unsigned char part_header[PACKAGE_PART_HEADER_LEN];
        if (fread(part_header, PACKAGE_PART_HEADER_LEN, 1, part_file) != 0) {
            fclose(part_file);

            libarp_set_error("Failed to read package part header");
            
            part_err = true;
            break;
        }

        fclose(part_file);

        if (memcmp(part_header, PART_MAGIC, PART_MAGIC_LEN) != 0) {
            libarp_set_error("Package part magic is invalid");
            
            part_err = true;
            break;
        }

        uint16_t part_index = part_header[PART_MAGIC_LEN] | part_header[PART_MAGIC_LEN + 1] << 8;
        if (part_index != i) {
            libarp_set_error("Package part index is incorrect");
            
            part_err = true;
            break;
        }
    }
    
    free(file_stem);
    free(parent_dir);

    return part_err ? -1 : 0;
}

static int _compare_node_names(const node_desc_t *a, const node_desc_t *b) {
    return memcmp(a->name, b->name, MIN(a->name_len_s, b->name_len_s));
}

static int _read_var_string(const void *catalogue, size_t *cur_off, char **target, size_t str_len_s) {
    if (str_len_s > 0) {    
        char tmp[256];
        _copy_str_to_field(tmp, catalogue, str_len_s, cur_off);
        *target[str_len_s] = '\0';

        if ((*target = malloc(str_len_s + 1)) == NULL) {
            libarp_set_error("malloc failed");
            return -1;
        }
        memcpy(*target, tmp, str_len_s + 1);
    } else {
        *target = NULL;
    }

    return 0;
}

static int _parse_package_catalogue(argus_package_t *pack, void *pack_data_view) {
    if ((pack->all_nodes = calloc(1, pack->node_count * sizeof(void*))) == NULL) {
        libarp_set_error("calloc failed");
        return -1;
    }

    unsigned char *catalogue = (unsigned char*) ((uintptr_t) pack_data_view + pack->cat_off);
    
    size_t cur_off = 0;
    for (size_t i = 0; i < pack->node_count; i++) {
        if (pack->cat_len - cur_off < 2) {
            libarp_set_error("Catalogue underflow");
            return -1;
        }

        uint16_t node_desc_len;
        _copy_int_to_field(&node_desc_len, catalogue, 2, &cur_off);

        if (node_desc_len < NODE_DESC_BASE_LEN) {
            libarp_set_error("Node descriptor is too small");
            return -1;
        } else if (node_desc_len > NODE_DESC_MAX_LEN) {
            libarp_set_error("Node descriptor is too large");
            return -1;
        } else if (pack->cat_len - cur_off < node_desc_len - (uint64_t) 2) {
            libarp_set_error("Catalogue underflow");
            return -1;
        }

        size_t desc_len = sizeof(node_desc_t);
        
        if ((pack->all_nodes[i] = (node_desc_t*) malloc(desc_len)) == NULL) {
            libarp_set_error("malloc failed");
            return -1;
        }

        node_desc_t *node = pack->all_nodes[i];

        _copy_int_to_field(&node->type, catalogue, 1, &cur_off);
        _copy_int_to_field(&node->part_index, catalogue, 2, &cur_off);
        _copy_int_to_field(&node->data_off, catalogue, 8, &cur_off);
        _copy_int_to_field(&node->data_len, catalogue, 8, &cur_off);
        _copy_int_to_field(&node->data_uc_len, catalogue, 8, &cur_off);
        _copy_int_to_field(&node->crc, catalogue, 4, &cur_off);
        _copy_int_to_field(&node->name_len_s, catalogue, 1, &cur_off);
        _copy_int_to_field(&node->ext_len_s, catalogue, 1, &cur_off);
        _copy_int_to_field(&node->media_type_len_s, catalogue, 1, &cur_off);

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

        _read_var_string(catalogue, &cur_off, &node->name, node->name_len_s);
        _read_var_string(catalogue, &cur_off, &node->ext, node->ext_len_s);
        _read_var_string(catalogue, &cur_off, &node->media_type, node->media_type_len_s);

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

            if ((node->data_len % 4) != 0) {
                libarp_set_error("Directory content length must be divisible by 4");
                return -1;
            }

            if (node->data_len > DIRECTORY_CONTENT_MAX_LEN) {
                libarp_set_error("Directory contains too many files");
                return -1;
            }
        }
    }

    unsigned char *body = (unsigned char*) ((uintptr_t) pack_data_view + pack->body_off);

    for (uint64_t i = 0; i < pack->node_count; i++) {
        node_desc_t *node = pack->all_nodes[i];
        
        if (node->type != PACK_NODE_TYPE_DIRECTORY) {
            continue;
        }

        uint64_t child_count = node->data_len / 4;
        uint32_t *node_children = (uint32_t*) ((uintptr_t) body + node->data_off);

        if ((node->children_tree = calloc(1, sizeof(bt_node_t) * (child_count + 1))) == NULL) {
            libarp_set_error("calloc failed");
            return -1;
        }

        for (uint64_t j = 0; j < child_count; j++) {
            uint32_t child_index = node_children[j];

            if (child_index == 0 || child_index >= pack->node_count) {
                libarp_set_error("Illegal node index in directory");
                return -1;
            }

            bt_node_t *root = j > 0 ? &node->children_tree[0] : NULL;
            bt_node_t *storage = &node->children_tree[j];
            bt_insert(root, storage, pack->all_nodes[child_index],
                    (int (*)(const void*, const void*)) _compare_node_names);
        }
    }

    return 0;
}

int load_package_from_file(const char *path, ArgusPackage *package) {
    FILE *package_file = fopen(path, "r");

    if (package_file == NULL) {
        fclose(package_file);

        libarp_set_error("Failed to open package file");
        return -1;
    }

    stat_t package_file_stat;
    if (fstat(fileno(package_file), &package_file_stat) != 0) {
        fclose(package_file);

        libarp_set_error("Failed to stat package file");
        return -1;
    }

    size_t package_file_size = package_file_stat.st_size;

    if (package_file_size < PACKAGE_HEADER_LEN) {
        fclose(package_file);

        libarp_set_error("File is too small to contain package header");
        return -1;
    }

    unsigned char pack_header[PACKAGE_HEADER_LEN];
    memset(pack_header, 0, PACKAGE_HEADER_LEN);

    if (fread(pack_header, PACKAGE_HEADER_LEN, 1, package_file) != 1) {
        fclose(package_file);

        libarp_set_error("Failed to read package header from file");
        return -1;
    }

    argus_package_t *pack;
    if ((pack = calloc(1, sizeof(argus_package_t))) == NULL) {
        fclose(package_file);

        libarp_set_error("calloc failed");
        return -1;
    }

    int rc;
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

    if ((pack->part_paths = calloc(1, sizeof(void*) * pack->total_parts)) == NULL) {
        unload_package(pack);
        fclose(package_file);

        libarp_set_error("calloc failed");
        return -1;
    }

    if ((rc = _validate_part_files(pack, path)) != 0) {
        unload_package(pack);
        fclose(package_file);

        return rc;
    }

    void *pack_data_view;
    #ifdef _WIN32
    HANDLE file_mapping = CreateFileMappingW(package_file, NULL, PAGE_READONLY,
            package_file_size >> 32, package_file_size & 0xFFFFFFFF, NULL);
    pack_data_view = MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, package_file_size);
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

int load_package_from_memory(const unsigned char *data, size_t package_len, ArgusPackage *package) {
    if (package_len < PACKAGE_HEADER_LEN) {
        libarp_set_error("Package is too small to contain package header");
        return -1;
    }

    unsigned char pack_header[PACKAGE_HEADER_LEN];

    memcpy(pack_header, data, PACKAGE_HEADER_LEN);

    argus_package_t *pack;
    if ((pack = calloc(1, sizeof(argus_package_t))) == NULL) {
        return ENOMEM;
    }

    int rc;
    if ((rc = _parse_package_header(pack, pack_header)) != 0) {
        unload_package(pack);
        return rc;
    }

    if ((rc = _validate_package_header(pack, package_len)) != 0) {
        unload_package(pack);
        return rc;
    }

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
        
        if (node->children_tree != NULL) {
            free(node->children_tree);
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

int unload_package(ArgusPackage package) {
    argus_package_t *real_pack = (argus_package_t*)package;

    if (real_pack->all_nodes != NULL) {
        for (uint32_t i = 0; i < real_pack->node_count; i++) {
            node_desc_t *node = (real_pack->all_nodes)[i];
            _unload_node(node);
        }

        free(real_pack->all_nodes);
    }

    for (uint16_t i = 0; i < real_pack->total_parts; i++) {
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

static int _cmp_node_names(const void *a, const void *b) {
    node_desc_t *real_a = (node_desc_t*) a;
    node_desc_t *real_b = (node_desc_t*) b;
    return strncmp(real_a->name, real_b->name, MIN(real_a->name_len_s, real_b->name_len_s));
}

static int _cmp_node_name_to_needle(const void *name, const void *node) {
    node_desc_t *real_node = (node_desc_t*) node;
    return strncmp(name, real_node->name, real_node->name_len_s);
}

arp_resource_t *load_resource(const ArgusPackage package, const char *path) {
    argus_package_t *real_pack = (argus_package_t*) package;

    size_t path_len_s = strlen(path);

    char *path_copy = malloc(path_len_s + 1);
    memcpy(path_copy, path, path_len_s + 1);
    char *path_tail = path_copy;
    size_t cursor = 0;
    char *needle;

    if ((needle = strchr(path_tail, NAMESPACE_DELIM)) == NULL) {
        free(path_copy);

        libarp_set_error("Path must contain a namespace");
        return NULL;
    }

    cursor = needle - path_tail;

    size_t namespace_len_s = cursor;
    path_tail[cursor] = '\0';
    if (strlen(real_pack->package_namespace) != namespace_len_s
            || strncmp(path_tail, real_pack->package_namespace, MIN(namespace_len_s, PACKAGE_NAMESPACE_LEN)) != 0) {
        free(path_copy);

        libarp_set_error("Namespace does not match package");
        return NULL;
    }

    path_tail += cursor + 1;

    // start at root
    node_desc_t *cur_node = real_pack->all_nodes[0];

    while ((needle = strchr(path_tail, PACKAGE_PATH_DELIM)) != NULL) {
        cursor = needle - path_tail;

        path_tail[cursor] = '\0';

        bt_node_t *found = bt_find(cur_node->children_tree, path_tail, _cmp_node_names);
        if (found == NULL) {
            free(path_copy);

            libarp_set_error("Resource does not exist at the specified path");
            return NULL;
        }

        cur_node = (node_desc_t*) found->data;

        path_tail += cursor + 1;
    }

    // should be at terminal component now
    bt_node_t *found = bt_find(cur_node->children_tree, path_tail, _cmp_node_name_to_needle);
    if (found == NULL) {
        free(path_copy);

        libarp_set_error("Resource does not exist at the specified path");
        return NULL;
    }

    free(path_copy);

    cur_node = (node_desc_t*) found->data;

    if (cur_node->type == PACK_NODE_TYPE_DIRECTORY) {
        libarp_set_error("Requested path points to directory");
        return NULL;
    }

    if (cur_node->loaded_data != NULL) {
        return (arp_resource_t*) cur_node->loaded_data;
    }

    if (cur_node->part_index > real_pack->total_parts) {
        libarp_set_error("Node part index is invalid");
        return NULL;
    }

    FILE *part_file = fopen(real_pack->part_paths[cur_node->part_index - 1], "r");
    if (part_file == NULL) {
        libarp_set_error("Failed to open part file");
        return NULL;
    }

    stat_t part_stat;
    if (fstat(fileno(part_file), &part_stat) != 0) {
        fclose(part_file);

        libarp_set_error("Failed to stat part file");
        return NULL;
    }

    if ((size_t) part_stat.st_size < PACKAGE_PART_HEADER_LEN + cur_node->data_off + cur_node->data_len) {
        fclose(part_file);

        libarp_set_error("Part file is too small to fit node data");
        return NULL;
    }

    void *raw_data;
    if ((raw_data = malloc(cur_node->data_len)) == NULL) {
        fclose(part_file);

        libarp_set_error("malloc failed");
        return NULL;
    }

    fseek(part_file, PACKAGE_PART_HEADER_LEN + cur_node->data_off, SEEK_SET);

    if ((fread(raw_data, cur_node->data_len, 1, part_file)) != 1) {
        free(raw_data);
        fclose(part_file);

        libarp_set_error("Failed to read from part file");
        return NULL;
    }

    fclose(part_file);

    uint32_t real_crc = crc32c(raw_data, cur_node->data_len);
    if (real_crc != cur_node->crc) {
        free(raw_data);

        libarp_set_error("CRC mismatch");
        return NULL;
    }

    void *final_data;

    if (real_pack->compression_type[0] != '\0') {
        if (strcmp(real_pack->compression_type, COMPRESS_MAGIC_DEFLATE) == 0) {
            int rc;

            z_stream defl_stream;
            defl_stream.zalloc = Z_NULL;
            defl_stream.zfree = Z_NULL;
            defl_stream.opaque = Z_NULL;
            defl_stream.avail_in = 0;
            defl_stream.next_in = Z_NULL;
            
            if ((rc = inflateInit(&defl_stream)) != Z_OK) {
                free(raw_data);

                libarp_set_error("zlib inflateInit failed");
                return NULL;
            }

            void *inflated_data;
            if ((inflated_data = malloc(cur_node->data_uc_len)) == NULL) {
                free(raw_data);

                libarp_set_error("malloc failed");
                return NULL;
            }

            size_t remaining = cur_node->data_len;
            size_t bytes_decompressed = 0;
            void *data_window = raw_data;

            unsigned char dfl_out_buf[CHUNK_LEN];

            while (remaining > 0) {
                size_t to_read = MIN(remaining, CHUNK_LEN);

                defl_stream.avail_in = to_read;
                defl_stream.next_in = data_window;

                remaining -= to_read;
                data_window = (void*) ((uintptr_t) data_window + to_read);

                while (defl_stream.avail_out == 0) {
                    defl_stream.avail_out = CHUNK_LEN;
                    defl_stream.next_out = dfl_out_buf;

                    rc = inflate(&defl_stream, Z_NO_FLUSH);
                    switch (rc) {
                        case Z_STREAM_ERROR:
                        case Z_NEED_DICT:
                        case Z_DATA_ERROR:
                        case Z_MEM_ERROR:
                            inflateEnd(&defl_stream);
                            free(inflated_data);
                            free(raw_data);

                            libarp_set_error("zlib inflate failed");
                            return NULL;
                        case Z_STREAM_END:
                            goto end_inflate_loop; // ew
                    }

                    size_t got_len = CHUNK_LEN - defl_stream.avail_out;

                    if (bytes_decompressed + got_len > cur_node->data_uc_len) {
                        inflateEnd(&defl_stream);
                        free(inflated_data);
                        free(raw_data);

                        libarp_set_error("Decompressed data exceeds expected length");
                        return NULL;
                    }

                    memcpy((void*) ((uintptr_t) inflated_data + bytes_decompressed), dfl_out_buf, got_len);
                    bytes_decompressed += got_len;
                }
            }
            
            end_inflate_loop:
            inflateEnd(&defl_stream);
            free(raw_data);

            if (rc != Z_STREAM_END) {
                free(inflated_data);

                libarp_set_error("DEFLATE stream is incomplete");
                return NULL;
            }

            final_data = inflated_data;
        } else {
            free(raw_data);

            libarp_set_error("Unrecognized compression magic");
            return NULL;
        }
    } else {
        final_data = raw_data;
    }

    arp_resource_t *res;
    if ((res = malloc(sizeof(arp_resource_t))) == NULL) {
        free(final_data);

        libarp_set_error("malloc failed");
        return NULL;
    }

    res->data = final_data;
    res->len = cur_node->data_len;
    res->extra = cur_node;
    cur_node->loaded_data = res;

    return res;
}

void unload_resource(arp_resource_t *resource) {
    if (resource == NULL) {
        return;
    }

    if (resource->data != NULL) {
        free(resource->data);
    }

    ((node_desc_t*) resource->extra)->loaded_data = NULL;

    free(resource);
}
