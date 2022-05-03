/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "arp/unpack/types.h"

int arp_unpack_to_fs(ConstArpPackage package, const char *target_dir);

int arp_unpack_resource_to_fs(const arp_resource_meta_t *meta, const char *target_dir);

#ifdef __cplusplus
}
#endif
