#include "arp/unpack/resource.h"
#include "arp/unpack/types.h"
#include "arp/util/defines.h"
#include "arp/util/error.h"
#include "internal/unpack/types.h"
#include "internal/unpack/unpack_util.h"
#include "internal/util/common.h"
#include "internal/util/error.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static int _cmp_node_names(const void *a, const void *b) {
    node_desc_t *real_a = (node_desc_t*) a;
    node_desc_t *real_b = (node_desc_t*) b;
    return strncmp(real_a->name, real_b->name, MIN(real_a->name_len_s, real_b->name_len_s));
}

static int _cmp_node_name_to_needle(const void *name, const void *node) {
    node_desc_t *real_node = (node_desc_t*) node;
    return strncmp(name, real_node->name, real_node->name_len_s);
}

static int _cmp_package_ns_to_needle(const void *name, const void *pack) {
    arp_package_t *real_pack = (arp_package_t*) pack;
    return strncmp(name, real_pack->package_namespace, sizeof(real_pack->package_namespace));
}

int arp_find_resource(ConstArpPackage package, const char *path, arp_resource_meta_t *out_meta) {
    const arp_package_t *real_pack = (const arp_package_t*) package;

    size_t path_len_s = strlen(path);

    char *path_copy = NULL;
    if ((path_copy = malloc(path_len_s + 1)) == NULL) {
        arp_set_error("malloc failed");
        return ENOMEM;
    }

    memcpy(path_copy, path, path_len_s + 1);
    char *path_tail = path_copy;
    size_t cursor = 0;
    char *needle = NULL;

    if ((needle = strchr(path_tail, ARP_NAMESPACE_DELIMITER)) == NULL) {
        free(path_copy);

        arp_set_error("Path must contain a namespace");
        return EINVAL;
    }

    cursor = needle - path_tail;

    size_t namespace_len_s = cursor;
    path_tail[cursor] = '\0';
    if (strlen(real_pack->package_namespace) != namespace_len_s
            || strncmp(path_tail, real_pack->package_namespace, MIN(namespace_len_s, PACKAGE_NAMESPACE_LEN)) != 0) {
        free(path_copy);

        arp_set_error("Namespace does not match package");
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

            arp_set_error("Resource does not exist at the specified path");
            return E_ARP_RESOURCE_NOT_FOUND;
        }

        path_tail += cursor + 1;
    }

    // should be at terminal component now
    node = bt_find(&node->children_tree, path_tail, _cmp_node_name_to_needle);
    if (node == NULL) {
        free(path_copy);

        arp_set_error("Resource does not exist at the specified path");
        return E_ARP_RESOURCE_NOT_FOUND;
    }

    free(path_copy);

    if (node->type == PACK_NODE_TYPE_DIRECTORY) {
        arp_set_error("Requested path points to directory");
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

int arp_find_resource_in_set(ConstArpPackageSet set, const char *path, arp_resource_meta_t *out_meta) {
    const arp_package_set_t *real_set = (const arp_package_set_t*) set;

    char path_ns[ARP_NAMESPACE_MAX + 1];
    const char *delim = strchr(path, ARP_NAMESPACE_DELIMITER);
    if (delim == NULL) {
        arp_set_error("Path is invalid");
        return -1;
    }

    size_t ns_len = delim - path;
    memcpy(path_ns, path, ns_len);

    arp_package_t *pack = bt_find(&real_set->tree, path_ns, _cmp_package_ns_to_needle);

    if (pack == NULL) {
        arp_set_error("Resource does not exist at the specified path");
        return E_ARP_RESOURCE_NOT_FOUND;
    }

    return arp_find_resource(pack, path, out_meta);
}

arp_resource_t *arp_load_resource(arp_resource_meta_t *meta) {
    node_desc_t *node = (node_desc_t*) meta->extra;

    if (node->loaded_data != NULL) {
        return (arp_resource_t*) node->loaded_data;
    }

    void *res_data = NULL;
    size_t res_data_len = 0;
    int rc = 0;
    if ((rc = unpack_node_data(node, NULL, &res_data, &res_data_len, NULL)) != 0) {
        errno = rc;
        return NULL;
    }

    arp_resource_t *res = NULL;
    if ((res = malloc(sizeof(arp_resource_t))) == NULL) {
        free(res_data);

        arp_set_error("malloc failed");
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

void arp_unload_resource(arp_resource_t *resource) {
    if (resource == NULL) {
        return;
    }

    if (resource->data != NULL) {
        free(resource->data);
    }

    ((node_desc_t*) resource->meta.extra)->loaded_data = NULL;

    free(resource);
}
