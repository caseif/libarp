/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/util/ll.h"

#include <stddef.h>
#include <stdlib.h>

linked_list_t *ll_create(void *initial) {
    linked_list_t *ll = malloc(sizeof(linked_list_t));

    ll->data = initial;
    ll->next = NULL;

    return ll;
}

void ll_free(linked_list_t *ll) {
    linked_list_t *cur = ll;
    while (cur != NULL) {
        linked_list_t *prev = cur;
        cur = cur->next;
        free(prev);
    }
}

void ll_push_back(linked_list_t *ll, void *data) {
    linked_list_t *cur = ll;
    while (cur->next != NULL) {
        cur = cur->next;
    }

    cur->next = ll_create(data);
}

void ll_remove(linked_list_t *ll, void *data) {
    if (ll->data == data) {
        // special case where the list head must be removed
        if (ll->next == NULL) {
            // double-special case where it's a singleton list
            ll->data = NULL;
        } else {
            // otherwise we need to find the last element and make it the first
            linked_list_t *prev = ll;
            linked_list_t *cur = ll->next; // guaranteed to be non-null
            while (cur->next != NULL) {
                cur = cur->next;
            }

            cur->next = prev; // previously null
            cur->data = ll->data;
        }
    }

    // if the head element doesn't match, skip ahead to the second element
    linked_list_t *prev = ll;
    linked_list_t *cur = ll->next;
    while (cur != NULL) {
        if (cur->data == data) {
            prev->next = cur->next;
            free(cur);
        }

        prev = cur;
        cur = cur->next;
    }
}
