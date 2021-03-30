/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/bt.h"

#include <assert.h>
#include <stddef.h>

//TODO: this creates a degenerate tree
bt_node_t *bt_insert(bt_node_t *root, bt_node_t *storage, void *data, int (*cmp_fn)(const void *a, const void *b)) {
    if (root == NULL || root->children_count == 0) {
        assert(root == NULL || root == storage);

        storage->data = data;
        storage->l = NULL;
        storage->r = NULL;
        storage->children_count++;
        return storage;
    }

    int cmp = cmp_fn(data, root->data);
    if (cmp < 0) {
        root->l = bt_insert(root->l, storage, data, cmp_fn);
    } else if (cmp > 0) {
        root->r = bt_insert(root->r, storage, data, cmp_fn);
    }

    root->children_count++;

    return root;
}

bt_node_t *bt_find(const bt_node_t *root, const void *needle, int (*cmp_fn)(const void *needle, const void *node_data)) {
    if (root == NULL) {
        return NULL;
    }

    int cmp = cmp_fn(needle, root->data);
    if (cmp == 0) {
        // this is a major code smell but I don't think it violates the const contract
        return (bt_node_t*) root;
    } else if (cmp < 0) {
        return bt_find(root->l, needle, cmp_fn);
    } else {
        return bt_find(root->r, needle, cmp_fn);
    }
}

void bt_foreach(const bt_node_t *root, bt_foreach_fn fn) {
    if (root->l != NULL) {
        fn(root->l);
        bt_foreach(root->l, fn);
    }

    if (root->r != NULL) {
        fn(root->r);
        bt_foreach(root->r, fn);
    }
}
