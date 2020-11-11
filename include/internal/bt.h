#pragma once

struct BtNode;

typedef struct BtNode {
    struct BtNode *l;
    struct BtNode *r;
    void *data;
} bt_node_t;

bt_node_t *bt_insert(bt_node_t *root, bt_node_t *storage, void *data, int (*cmp_fn)(const void *a, const void *b));

bt_node_t *bt_find(bt_node_t *root, const void *needle, int (*cmp_fn)(const void *needle, const void *node_data));
