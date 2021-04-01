/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/bt.h"
#include "internal/util.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

binary_tree_t *bt_create(size_t capacity, binary_tree_t *tree_out) {
    binary_tree_t *tree = NULL;

    if (tree_out != NULL) {
        tree = tree_out;
        tree->malloced = false;
    } else {
        if ((tree = malloc(sizeof(binary_tree_t))) == NULL) {
            libarp_set_error("malloc failed\n");
            errno = ENOMEM;
            return NULL;
        }

        tree->malloced = true;
    }

    if ((tree->storage = calloc(capacity, sizeof(bt_node_t))) == NULL) {
        if (tree->malloced) {
            free(tree);
        }

        libarp_set_error("calloc failed\n");
        errno = ENOMEM;
        return NULL;
    }

    tree->capacity = capacity;
    tree->count = 0;
    tree->root = NULL;

    return tree;
}

void bt_free(binary_tree_t *tree) {
    free(tree->storage);

    if (tree->malloced) {
        free(tree);
    }
}

//TODO: this creates a degenerate tree
void bt_insert(binary_tree_t *tree, void *data, BtInsertCmpFn cmp_fn) {
    assert(tree->count < tree->capacity);

    bt_node_t *new_node = &tree->storage[tree->count];
    new_node->data = data;
    new_node->l = NULL;
    new_node->r = NULL;

    if (tree->root == NULL) {
        tree->root = new_node;
        new_node->parent = NULL;
    } else {
        bt_node_t *cur = tree->root;

        while (true) {
            bt_node_t **next = NULL;

            int cmp = cmp_fn(data, cur->data);
            if (cmp < 0) {
                next = &cur->l;
            } else {
                next = &cur->r;
            }

            if (*next == NULL) {
                new_node->parent = cur;

                *next = new_node;

                break;
            } else {
                cur = *next;
            }
        }
    }

    tree->count += 1;

    //TODO: balance tree
}

void *bt_find(const binary_tree_t *tree, const void *needle, BtFindCmpFn cmp_fn) {
    bt_node_t *cur = tree->root;

    while (cur != NULL) {
        int cmp = cmp_fn(needle, cur->data);
        if (cmp == 0) {
            return cur->data;
        } else if (cmp < 0) {
            cur = cur->l;
            continue;
        } else if (cmp > 0) {
            cur = cur->r;
            continue;
        }
    }

    return NULL;
}
