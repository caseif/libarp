#pragma once

#include <stddef.h>
#include <stdint.h>

void copy_int_as_le(void *dst, void *src, size_t len);

int validate_path_component(const char *cmpnt, size_t len_s);

inline void *offset_ptr(void *ptr, size_t off) {
    return (void*) ((uintptr_t) ptr + off);
}
