/*
 * This file is a part of libarp.
 * Copyright (c) 2020, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "libarp/common.h"
#include "libarp/pack.h"
#include "internal/package.h"
#include "internal/util.h"

#include <stdlib.h>
#include <string.h>

ArpPackingOptions create_v1_packing_options(char *pack_name, char *pack_namespace, size_t max_part_len,
        char *compression_type) {

    size_t name_len = strlen(pack_name);
    size_t namespace_len = strlen(pack_namespace);
    size_t compression_type_len = strlen(compression_type);

    if (name_len == 0) {
        libarp_set_error("Package name must not be empty");
        return NULL;
    }

    if (namespace_len == 0) {
        libarp_set_error("Namespace must not be empty");
        return NULL;
    } else if (namespace_len > PACKAGE_NAMESPACE_LEN) {
        libarp_set_error("Namespace length is too long");
        return NULL;
    }

    if (compression_type_len > PACKAGE_COMPRESSION_LEN) {
        libarp_set_error("Compression type magic is too long");
        return NULL;
    }

    arp_packing_options_t *opts = calloc(1, sizeof(arp_packing_options_t));
    opts->pack_name = malloc(name_len + 1);
    opts->pack_namespace = malloc(PACKAGE_NAMESPACE_LEN + 1);
    opts->compression_type = malloc(PACKAGE_COMPRESSION_LEN + 1);

    memcpy(opts->pack_name, pack_name, name_len + 1);
    memcpy(opts->pack_namespace, pack_name, namespace_len + 1);
    memcpy(opts->compression_type, pack_name, compression_type_len + 1);

    opts->max_part_len = max_part_len;

    return opts;
}

void release_packing_options(ArpPackingOptions opts) {
    if (opts == NULL) {
        return;
    }

    arp_packing_options_t *real_opts = (arp_packing_options_t*) opts;

    if (real_opts->pack_name != NULL) {
        free(real_opts->pack_name);
    }

    if (real_opts->pack_namespace != NULL) {
        free(real_opts->pack_namespace);
    }

    if (real_opts->compression_type != NULL) {
        free(real_opts->compression_type);
    }

    free(real_opts);
}

int create_arp_from_fs(const char *src_path, const char *target_dir, ArpPackingOptions opts) {
    arp_packing_options_t *real_opts = (arp_packing_options_t*) opts;

    //TODO
    return 0;
}
