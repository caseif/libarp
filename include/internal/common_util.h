/*
 * This file is a part of libarp.
 * Copyright (c) 2020, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

void copy_int_as_le(void *dst, void *src, size_t len);

int validate_path_component(const char *cmpnt, size_t len_s);

inline void *offset_ptr(void *ptr, size_t off) {
    return (void*) ((uintptr_t) ptr + off);
}
