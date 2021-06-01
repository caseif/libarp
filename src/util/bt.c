/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/util/bt.h"
#include "internal/util/error.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

//#define#define
static void _bt_rotate_left(binary_tree_t *tree, bt_node_t *root) {
    assert(root->r != NULL);

    bt_node_t *new_root = root->r;

    new_root->parent = root->parent;
    if (new_root->parent != NULL) {
        if (new_root->parent->l == root) {
            new_root->parent->l = new_root;
        } else {
            new_root->parent->r = new_root;
        }
    } else {
        tree->root = new_root;
        new_root->parent = NULL;
    }

    root->r = new_root->l;
    if (root->r != NULL) {
        root->r->parent = root;
    }

    new_root->l = root;
    new_root->l->parent = new_root;
}

static void _bt_rotate_right(binary_tree_t *tree, bt_node_t *root) {
    assert(root->l != NULL);

    bt_node_t *new_root = root->l;

    new_root->parent = root->parent;
    if (new_root->parent != NULL) {
        if (new_root->parent->l == root) {
            new_root->parent->l = new_root;
        } else {
            new_root->parent->r = new_root;
        }
    } else {
        tree->root = new_root;
        new_root->parent = NULL;
    }

    root->l = new_root->r;
    if (root->l != NULL) {
        root->l->parent = root;
    }

    new_root->r = root;
    new_root->r->parent = new_root;
}

static void _bt_balance(binary_tree_t *tree, bt_node_t *target) {
    if (target == tree->root) {
        target->color = BT_BLACK;
        return;
    }

    bt_node_t *parent = target->parent;
    assert(parent != NULL);

    if (parent->color == BT_BLACK) {
        return;
    }

    // parent is red, need to reconcile state

    bt_node_t *grandparent = parent->parent;
    assert(grandparent != NULL);

    bool parent_is_left = parent == grandparent->l;
    bool child_is_left = target == parent->l;
    
    bt_node_t *uncle = parent_is_left ? grandparent->r : grandparent->l;

    if (uncle != NULL && uncle->color == BT_RED) {
        uncle->color = BT_BLACK;
        parent->color = BT_BLACK;
        grandparent->color = BT_RED;

        _bt_balance(tree, grandparent);
    } else {
        if (parent_is_left != child_is_left) {
            if (parent_is_left) {
                _bt_rotate_left(tree, parent);
            } else {
                _bt_rotate_right(tree, parent);
            }

            parent = parent->parent;
        } else {
        }

        if (parent_is_left) {
            _bt_rotate_right(tree, grandparent);
        } else {
            _bt_rotate_left(tree, grandparent);
        }

        BtNodeColor parent_color = parent->color;
        parent->color = grandparent->color;
        grandparent->color = parent_color;

        _bt_balance(tree, parent);
    }
}

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
    stack_create(sizeof(void*), tree->capacity, tree->capacity, &tree->it_stack);

    tree->initialized = true;

    return tree;
}

void bt_free(binary_tree_t *tree) {
    free(tree->storage);
    stack_free(&tree->it_stack);

    if (tree->malloced) {
        free(tree);
    }
}

void bt_insert(binary_tree_t *tree, void *data, BtInsertCmpFn cmp_fn) {
    assert(tree->count < tree->capacity);

    bt_node_t *new_node = &tree->storage[tree->count];
    new_node->data = data;
    new_node->l = NULL;
    new_node->r = NULL;
    new_node->color = BT_RED;

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

    _bt_balance(tree, new_node);
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

void **bt_iterate(binary_tree_t *tree) {
    bt_node_t **next_ptr = stack_pop(&tree->it_stack);

    if (next_ptr == NULL) {
        return NULL;
    } else {
        bt_node_t *next = *next_ptr;

        if (next->l != NULL) {
            stack_push(&tree->it_stack, &next->l);
        }
        if (next->r != NULL) {
            stack_push(&tree->it_stack, &next->r);
        }

        return &next->data;
    }
}

void bt_reset_iterator(binary_tree_t *tree) {
    stack_clear(&tree->it_stack);

    if (tree->root != NULL) {
        stack_push(&tree->it_stack, &tree->root);
    }
}
