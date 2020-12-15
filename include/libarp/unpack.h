/*
 * This file is a part of libarp.
 * Copyright (c) 2020, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include "libarp/common.h"

#include <stdlib.h>

int load_package_from_file(const char *path, ArgusPackage *package);

int load_package_from_memory(const unsigned char *data, size_t package_len, ArgusPackage *package);

int unload_package(ArgusPackage package);

arp_resource_t *load_resource(const ArgusPackage package, const char *path);

void unload_resource(arp_resource_t *resource);
