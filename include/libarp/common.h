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

typedef void *ArgusPackage;

typedef struct ArpResource {
    void *data;
    size_t len;

    void *extra;
} arp_resource_t;

const char *libarp_get_error(void);
