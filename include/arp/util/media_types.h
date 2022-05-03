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

#include "internal/defines/package.h"

#include <stddef.h>

typedef struct ExtensionMapping {
    char extension[NODE_EXT_MAX_LEN + 1];
    char media_type[NODE_MT_MAX_LEN + 1];
} extension_mapping_t;

extension_mapping_t *arp_get_extension_mappings(size_t *count);

void arp_free_extension_mappings(extension_mapping_t *mappings);

#ifdef __cplusplus
}
#endif
