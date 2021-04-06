#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct Stack {
    void *data;
    size_t capacity;
    size_t index;
    size_t el_len;
    size_t cap_increment;
    size_t cap_max;
    bool malloced;
} stack_t;

stack_t *stack_create(size_t el_len, size_t cap_increment, size_t cap_max, stack_t *storage);

void stack_free(stack_t *stack);

int stack_push(stack_t *stack, void *data);

void *stack_pop(stack_t *stack);

void stack_clear(stack_t *stack);
