#include "arp/unpack/resource.h"
#include "arp/unpack/types.h"
#include "internal/unpack/types.h"
#include "internal/unpack/unpack_util.h"
#include "internal/util/error.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

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
