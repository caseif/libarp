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
#include <string.h>

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

static void _bt_balance_insertion(binary_tree_t *tree, bt_node_t *target) {
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

        _bt_balance_insertion(tree, grandparent);
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

        _bt_balance_insertion(tree, parent);
    }
}

static void _blacken_node(bt_node_t *target) {
    if (target->color == BT_BLACK) {
        target->color = BT_DBL_BLACK;
    } else if (target->color == BT_RED) {
        target->color = BT_BLACK;
    }
}

static void _bt_balance_deletion(binary_tree_t *tree, bt_node_t *target) {
    if (tree->root == target) {
        target->color = BT_BLACK;
        return;
    }

    bool left_child = target->parent->l == target;

    bt_node_t *sibling = left_child ? target->parent->r : target->parent->l;

    if (sibling == NULL || sibling->color == BT_BLACK) {
        if (sibling != NULL
            && ((sibling->l != NULL && sibling->l->color == BT_RED)
                || (sibling->r != NULL && sibling->r->color == BT_RED))) {
            bool sibling_is_left = !left_child;
            bool left_child_is_red = sibling->l != NULL && sibling->l->color == BT_RED;
            bt_node_t *red_child = left_child_is_red ? sibling->l : sibling->r;

            if (sibling_is_left == left_child_is_red) {
                red_child->color = BT_BLACK;

                if (sibling_is_left) {
                    _bt_rotate_right(tree, target->parent);
                } else {
                    _bt_rotate_left(tree, target->parent);
                }
            } else {
                sibling->color = BT_RED;
                red_child->color = BT_BLACK;

                if (sibling_is_left) {
                    _bt_rotate_left(tree, sibling);
                    _bt_rotate_right(tree, target->parent);
                } else {
                    _bt_rotate_right(tree, sibling);
                    _bt_rotate_left(tree, target->parent);
                }
            }
        } else {
            target->color = BT_BLACK;
            if (sibling != NULL) {
                _blacken_node(sibling);
            }
            _blacken_node(target->parent);

            if (target->parent->color == BT_DBL_BLACK) {
                _bt_balance_deletion(tree, target->parent);
            }
        }
    } else {
        assert(sibling != NULL);

        sibling->color = BT_BLACK;
        target->parent->color = BT_RED;

        if (left_child) {
            _bt_rotate_left(tree, target->parent);
        } else {
            _bt_rotate_right(tree, target->parent);
        }

        _bt_balance_deletion(tree, target);
    }
}

binary_tree_t *bt_create(size_t capacity, binary_tree_t *tree_out) {
    binary_tree_t *tree = NULL;

    if (tree_out != NULL) {
        tree = tree_out;
        tree->malloced = false;
    } else {
        if ((tree = malloc(sizeof(binary_tree_t))) == NULL) {
            arp_set_error("malloc failed\n");
            errno = ENOMEM;
            return NULL;
        }

        tree->malloced = true;
    }

    if ((tree->storage = calloc(capacity, sizeof(bt_node_t))) == NULL) {
        if (tree->malloced) {
            free(tree);
        }

        arp_set_error("calloc failed\n");
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

static bool _bt_insert_impl(binary_tree_t *tree, void *data, BtInsertCmpFn cmp_fn, bool distinct) {
    assert(tree->count < tree->capacity);

    bt_node_t *new_node = &tree->storage[tree->count];
    new_node->data = data;
    new_node->l = NULL;
    new_node->r = NULL;
    new_node->color = BT_RED;
    new_node->index = tree->count;

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
            } else if (cmp > 0) {
                next = &cur->r;
            } else {
                if (distinct) {
                    return false;
                } else {
                    next = &cur->r; // arbitrary, could be left
                }
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

    _bt_balance_insertion(tree, new_node);

    return true;
}

void bt_insert(binary_tree_t *tree, void *data, BtInsertCmpFn cmp_fn) {
    _bt_insert_impl(tree, data, cmp_fn, false);
}

bool bt_insert_distinct(binary_tree_t *tree, void *data, BtInsertCmpFn cmp_fn) {
    return _bt_insert_impl(tree, data, cmp_fn, true);
}

// Deletes a node from a tree's memory.
// WARNING: This does not modify the structure of the tree and should never be
// called directly.
// WARNING: This invalidates all current references to bt_node_t structures,
// which must be re-obtained.
static void _delete_node(binary_tree_t *tree, bt_node_t *node) {
    if (node->index == tree->count - 1) {
        // nothing to do except decrement count since node is already at end of storage
        tree->count -= 1;
        return;
    }

    // need to move node at end of storage to location of deleted node
    bt_node_t *to_move = &(tree->storage[tree->count - 1]);
    memcpy(node, to_move, sizeof(bt_node_t));
    to_move->index = node->index;
}

// Removes a node from the tree's structure, freeing a slot in the tree's
// storage in the process.
static void _remove_node(binary_tree_t *tree, bt_node_t *node) {
    // special case: tree size of 1
    if (node == tree->root && node->l == NULL && node->r == NULL) {
        tree->root = NULL;
        tree->count -= 1;
        return;
    }

    bool left_child = node->parent->l == node;

    bt_node_t *replacement = NULL;

    if (node->l == NULL && node->r == NULL) {
        // node has no children (is leaf)
        if (left_child) {
            node->parent->l = NULL;
        } else {
            node->parent->r = NULL;
        }

        replacement = NULL;
    } else if ((node->l != NULL) ^ (node->r != NULL)) {
        // node has exactly one child
        bt_node_t *child = node->l;
        if (child == NULL) {
            child = node->r;
        }

        node->data = child->data;
        node->l = NULL;
        node->r = NULL;

        replacement = child;
    } else {
        // node has 2 children
        // need to get the successor node
        bt_node_t *successor = node->r;
        while (successor->l != NULL) {
            successor = successor->l;
        }

        if (successor->parent->l == successor) {
            successor->parent->l = NULL;
        } else {
            successor->parent->r = NULL;
        }

        // copy successor node into deleted node
        node->data = successor->data;

        replacement = successor;
    }

    bool red_replacement = replacement != NULL ? replacement->color == BT_RED : false;
    if (node->color == BT_RED || red_replacement) {
        node->color = BT_BLACK;
    } else {
        // both node and replacement are black
        node->color = BT_DBL_BLACK;

        _bt_balance_deletion(tree, node);
    }

    if (replacement != NULL) {
        _delete_node(tree, replacement);
    } else {
        _delete_node(tree, node);
    }
}

void bt_remove(binary_tree_t *tree, const void *needle, BtInsertCmpFn cmp_fn) {
    bt_node_t *node = tree->root;

    while (node != NULL) {
        int cmp = cmp_fn(needle, node->data);
        if (cmp == 0) {
            break;
        } else if (cmp < 0) {
            node = node->l;
            continue;
        } else if (cmp > 0) {
            node = node->r;
            continue;
        }
    }

    // needle is not present in the tree
    if (node == NULL) {
        return;
    }

    _remove_node(tree, node);
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
