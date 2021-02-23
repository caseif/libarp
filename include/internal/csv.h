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

#include "internal/bt.h"

typedef struct CsvFile {
    bt_node_t *tree;
    void *data;
} csv_file_t;

/**
 * Parses the CSV resulting from the concatenation of `stock_csv` and
 * `user_csv`. The data is copied to a separate buffer, so the input buffers may
 * be disposed of after this function is called.
 *
 * This parser is extremely domain-specific and does not support escape
 * characters, quoted strings, comments, or headers. Additionally, it expects
 * exactly one comma per line for a total of two columns.
 * 
 * To deallocate the binary tree, `free_csv` must be called.
 */
csv_file_t *parse_csv(const void *stock_csv, size_t stock_len, const void *user_csv, size_t user_len);

/**
 * Attempts to find the given key in the CSV represented by the passed binary
 * tree and returns its value. If the key is not present, `NULL` is returned
 * instead.
 */
const char *search_csv(const csv_file_t *csv, const char *key);

/**
 * Releases the memory occupied by the CSV object.
 */
void free_csv(csv_file_t *csv);
