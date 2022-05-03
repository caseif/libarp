/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include "internal/unpack/types.h"

#include <stddef.h>
#include <stdio.h>

int unpack_node_data(const node_desc_t *node, FILE *out_file,
        void **out_data, size_t *out_data_len, bool *out_malloced, FILE *part);
