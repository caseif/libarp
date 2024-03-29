/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal/util/common.h"
#include "internal/util/error.h"
#include "internal/util/stack.h"

arp_stack_t *stack_create(size_t el_len, size_t cap_increment, size_t cap_max, arp_stack_t *storage) {
    if (el_len == 0) {
        arp_set_error("Element length must not be 0");
        return NULL;
    }

    if (cap_increment == 0) {
        arp_set_error("Capacity increment must not be 0");
        return NULL;
    }

    if (cap_max == 0) {
        arp_set_error("Max capacity must not be 0");
        return NULL;
    }

    if ((cap_max % cap_increment) != 0) {
        arp_set_error("Max capacity must be multiple of capacity increment");
        return NULL;
    }

    arp_stack_t *stack = NULL;
    if (storage != NULL) {
        stack = storage;
        stack->malloced = false;
    } else {
        if ((stack = (arp_stack_t*) malloc(sizeof(arp_stack_t))) == NULL) {
            arp_set_error("malloc failed");
            return NULL;
        }
        stack->malloced = true;
    }

    if ((stack->data = malloc(el_len * cap_increment)) == NULL) {
        free(stack);

        arp_set_error("malloc failed");
        return NULL;
    }

    stack->el_len = el_len;
    stack->cap_increment = cap_increment;
    stack->cap_max = cap_max;
    stack->index = 0;
    stack->capacity = 0;

    return stack;
}

void stack_free(arp_stack_t *stack) {
    free(stack->data);
    if (stack->malloced) {
        free(stack);
    }
}

int stack_push(arp_stack_t *stack, void *data) {
    if (stack->index == stack->capacity) {
        if (stack->capacity == stack->cap_max) {
            arp_set_error("Stack exceeded max capacity");
            return -1;
        }

        void *new_data = NULL;
        if ((new_data = realloc(stack->data, (stack->capacity + stack->cap_increment) * stack->el_len)) == NULL) {
            arp_set_error("realloc failed");
            return ENOMEM;
        }
        stack->data = new_data;
    }

    memcpy((char*) stack->data + (stack->index * stack->el_len), data, stack->el_len);

    stack->index += 1;

    return 0;
}

void *stack_pop(arp_stack_t *stack) {
    if (stack->index == 0) {
        return NULL;
    }

    stack->index -= 1;

    return (char*) stack->data + (stack->index * stack->el_len);
}

void stack_clear(arp_stack_t *stack) {
    stack->index = 0;
}
