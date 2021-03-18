#pragma once

#include <stddef.h>

typedef struct Stack {
    void *data;
    size_t capacity;
    size_t index;
    size_t el_len;
    size_t cap_increment;
    size_t cap_max;
} stack_t;

stack_t *stack_create(size_t el_len, size_t cap_increment, size_t cap_max);

void stack_free(stack_t *stack);

int stack_push(stack_t *stack, void *data);

void *stack_pop(stack_t *stack);
