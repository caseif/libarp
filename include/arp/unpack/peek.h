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

#include <stdbool.h>

bool arp_is_base_archive(const char *path);

bool arp_is_part_archive(const char *path);

#ifdef __cplusplus
}
#endif
