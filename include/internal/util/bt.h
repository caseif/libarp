/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include "internal/util/stack.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct BtNode;

typedef uint8_t BtNodeColor;
#define BT_BLACK 0
#define BT_RED 1
#define BT_DBL_BLACK 2

typedef struct BtNode {
    // this count includes the top-level node itself
    struct BtNode *l;
    struct BtNode *r;
    struct BtNode *parent;
    void *data;
    BtNodeColor color;
    size_t index;
} bt_node_t;

typedef struct BinaryTree {
    bool initialized;
    size_t capacity;
    size_t count;
    bt_node_t *root;
    bt_node_t *storage;
    bool malloced;

    stack_t it_stack;
} binary_tree_t;

typedef int (*BtInsertCmpFn)(const void *a, const void *b);

typedef int (*BtFindCmpFn)(const void *needle, const void *node_data);

binary_tree_t *bt_create(size_t capacity, binary_tree_t *tree_out);

void bt_free(binary_tree_t *tree);

void bt_insert(binary_tree_t *tree, void *data, BtInsertCmpFn cmp_fn);

bool bt_insert_distinct(binary_tree_t *tree, void *data, BtInsertCmpFn cmp_fn);

void bt_remove(binary_tree_t *tree, const void *needle, BtInsertCmpFn cmp_fn);

void *bt_find(const binary_tree_t *tree, const void *needle, BtFindCmpFn cmp_fn);

void **bt_iterate(binary_tree_t *tree);

void bt_reset_iterator(binary_tree_t *tree);
