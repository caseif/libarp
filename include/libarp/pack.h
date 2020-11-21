#pragma once

#include "libarp/common.h"

typedef void* ArpPackingOptions;

ArpPackingOptions create_v1_packing_options(char *pack_name, char *pack_namespace, size_t max_part_len,
        char *compression_type);

void release_packing_options(ArpPackingOptions opts);

int create_arp_from_fs(const char *src_path, const char *target_dir, ArpPackingOptions opts);
