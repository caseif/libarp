#pragma once

#include "libarp/common.h"

typedef struct ArpPackingOptions {
    char *pack_name;
    char *pack_namespace;
    size_t max_part_len;
    char *compression_type;
} arp_packing_options_t;

arp_packing_options_t *create_v1_packing_options(char *pack_name, char *pack_namespace, size_t max_part_len,
        char *compression_type);

void release_packing_options(arp_packing_options_t *opts);

int create_arp_from_fs(const char *src_path, const char *target_dir, arp_packing_options_t *opts);
