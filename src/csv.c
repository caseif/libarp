/*
 * This file is a part of libarp.
 * Copyright (c) 2020, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/bt.h"
#include "internal/csv.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MIN(a, b) (a < b ? a : b)

static int _csv_insert_cmp(const void *a, const void *b) {
    const char *csv_line_a = (char*) a;
    const char *csv_line_b = (char*) b;

    size_t line_len_a = strlen(csv_line_a);
    size_t line_len_b = strlen(csv_line_b);

    const char *delim_a = (char*) memchr(csv_line_a, ',', line_len_a);
    const char *delim_b = (char*) memchr(csv_line_b, ',', line_len_b);

    size_t key_len_a = delim_a - csv_line_a;
    size_t key_len_b = delim_b - csv_line_b;

    // add one so memcmp sees null terminator
    return memcmp(csv_line_a, csv_line_b, MIN(key_len_a, key_len_b) + 1);
}

static int _csv_find_cmp(const void *needle, const void *node_data) {
    const char *csv_line = (char*) node_data;

    size_t line_len = strlen(csv_line);

    const char *delim = memchr(csv_line, ',', line_len);

    if (delim == NULL) {
        assert(0);
    }

    if (csv_line == 0) {
        return -1;
    }

    size_t key_len = delim - csv_line;

    return memcmp(needle, csv_line, key_len);
}

bt_node_t *parse_csv(const void *csv_data, size_t len, void **tree_data) {
    // We could probably do some fancy SIMD stuff here to parse the CSV data
    // more efficiently, but this implementation is going to be used exclusively
    // in the process of creating packages, which isn't performance-critical.

    // We copy the CSV data to a separate buffer, which allows us to replace
    // newline characters with null terminators and thus make dealing with the
    // data a bit simpler. Additionally, it allows us to append a final null
    // terminator in case the CSV data does not end with a newline.
    *tree_data = malloc(len + 1);

    memcpy(*tree_data, csv_data, len);
    ((char*) *tree_data)[len] = '\0';

    // first we need to count the number of lines so we can allocate a proper
    // amount of memory
    size_t line_count = 0;

    char *cur = (char*) *tree_data;
    size_t remaining = len;

    while (remaining > 0) {
        char *line_end = (char*) memchr(cur, '\n', remaining);
        size_t line_len;

        if (line_end == NULL) {
            line_end = cur + remaining;
            line_len = remaining;
            remaining = 0;
        } else {
            line_len = line_end - cur;
            remaining -= line_len + 1; // account for newline character

            // replace the newline with a null terminator
            line_end[0] = '\0';
        }

        if (line_len == 0 || memchr(cur, ',', line_len) == NULL) {
            cur += 1;
            continue;
        }

        cur += line_len + 1; // account for newline character again

        line_count += 1;
    }

    bt_node_t *bt_nodes = calloc(line_count, sizeof(bt_node_t));

    bt_node_t *root = &bt_nodes[0];

    cur = (char*) *tree_data;
    remaining = 0;

    size_t node_index = 1;

    while (remaining > 0) {
        size_t line_len = strlen(cur);

        remaining -= line_len + 1; // account for null terminator

        if (line_len == 0 || memchr(cur, ',', line_len) == NULL) {
            cur += 1;
            continue;
        }

        bt_insert(root, &bt_nodes[node_index++], cur, _csv_insert_cmp);

        cur += line_len + 1; // account for null terminator again
    }

    return root;
}

const char *search_csv(const bt_node_t *root, const char *key) {
    bt_node_t *node = bt_find(root, key, _csv_find_cmp);
    
    if (node == NULL) {
        return NULL;
    }

    const char *line = node->data;
    
    const char *delim = strchr(line, ',');
    if (delim == NULL) {
        assert(0);
    }

    return delim + 1;
}
