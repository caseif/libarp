/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include <stddef.h>

#define ERR_MSG_MAX_LEN 4096

typedef void *ArgusPackage;

typedef const void *ConstArgusPackage;

typedef struct ArpResource {
    void *data;
    size_t len;

    void *extra;
} arp_resource_t;

const char *libarp_get_error(void);
