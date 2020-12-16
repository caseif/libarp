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

#include "internal/bt.h"

/**
 * Parses a CSV contained by `buf`. The generated binary tree will contain
 * pointers to data within `buf`, so it must not be freed until the binary tree
 * is no longer needed.
 *
 * This parser is domain-specific and does not support escape characters, quoted
 * strings, comments, or headers. Additionally, it expects exactly one comma per
 * line for a total of two columns.
 * 
 * To deallocate the binary tree, the returned `bt_node_t` as well as the
 * pointer written to `data_buf` must be free'd directly.
 */
bt_node_t *parse_csv(const void *csv_data, size_t len, void **tree_data);

/**
 * Attempts to find the given key in the CSV represented by the passed binary
 * tree and returns its value. If the key is not present, `NULL` is returned
 * instead.
 */
const char *search_csv(const bt_node_t *root, const char *key);
