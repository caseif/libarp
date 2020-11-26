#pragma once

#include "libarp/pack.h"

#include <stddef.h>

#define FS_NODE_TYPE_DIR 'd'
#define FS_NODE_TYPE_FILE 'f'
#define FS_NODE_TYPE_LINK 'l'

typedef struct ArpPackingOptions {
    char *pack_name;
    char *pack_namespace;
    size_t max_part_len;
    char *compression_type;
    link_behavior_t link_behavior;
} arp_packing_options_t;

typedef struct FsNode {
    unsigned char type;
    char *name;
    struct FsNode **children;
    size_t children_count;
    char *link_target;

    size_t index;
    uint16_t part;
    uint64_t data_len;
    uint64_t data_off;
} fs_node_t;
