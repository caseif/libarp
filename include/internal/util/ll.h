/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

struct LinkedList;

typedef struct LinkedList {
    void *data;
    struct LinkedList *next;
} linked_list_t;

linked_list_t *ll_create(void *initial);
void ll_free(linked_list_t *ll);

void ll_push_back(linked_list_t *ll, void *data);

void ll_remove(linked_list_t *ll, void *data);
