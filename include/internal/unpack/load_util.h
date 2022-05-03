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
#include "internal/util/error.h"

#include <stdio.h>

FILE *open_part_file_for_node(const node_desc_t *node);

int setup_part_file_for_node(FILE *part_file, const node_desc_t *node);
