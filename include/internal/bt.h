#pragma once

struct BtNode;

typedef struct BtNode {
    struct BtNode *l;
    struct BtNode *r;
    void *data;
} bt_node_t;