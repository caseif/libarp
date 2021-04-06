/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include "libarp/common.h"
#include "libarp/iterator.h"

#include <stdlib.h>

int load_package_from_file(const char *path, ArgusPackage *package);

int load_package_from_memory(const unsigned char *data, size_t package_len, ArgusPackage *package);

int unload_package(ArgusPackage package);

arp_resource_t *load_resource(ConstArgusPackage package, const char *path);

void unload_resource(arp_resource_t *resource);

int unpack_arp_to_fs(ConstArgusPackage package, const char *target_dir);

int list_resources(ConstArgusPackage package, arp_resource_info_t **info_out, size_t *count_out);
