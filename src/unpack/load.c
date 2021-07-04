#include "arp/util/defines.h"
#include "arp/unpack/load.h"
#include "internal/defines/file.h"
#include "internal/defines/misc.h"
#include "internal/unpack/types.h"
#include "internal/util/common.h"
#include "internal/util/error.h"

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

static int _cmp_node_names(const void *a, const void *b) {
    node_desc_t *real_a = (node_desc_t*) a;
    node_desc_t *real_b = (node_desc_t*) b;
    return strncmp(real_a->name, real_b->name, MIN(real_a->name_len_s, real_b->name_len_s));
}

static int _cmp_node_name_to_needle(const void *name, const void *node) {
    node_desc_t *real_node = (node_desc_t*) node;
    return strncmp(name, real_node->name, real_node->name_len_s);
}

int arp_load_from_file(const char *path, ArpPackage *package) {
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

int arp_load_from_memory(const unsigned char *data, size_t package_len, ArpPackage *package) {
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

    if ((rc = _parse_package_catalogue(pack, data)) != 0) {
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

int arp_get_resource_meta(ConstArpPackage package, const char *path, arp_resource_meta_t *out_meta) {
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
