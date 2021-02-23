/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include <stddef.h>

struct BtNode;

typedef struct BtNode {
    // this count includes the top-level node itself
    size_t children_count;
    struct BtNode *l;
    struct BtNode *r;
    void *data;
} bt_node_t;

bt_node_t *bt_insert(bt_node_t *root, bt_node_t *storage, void *data, int (*cmp_fn)(const void *a, const void *b));

bt_node_t *bt_find(const bt_node_t *root, const void *needle, int (*cmp_fn)(const void *needle, const void *node_data));
