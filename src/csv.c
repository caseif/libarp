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
#include "internal/util.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
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

csv_file_t *parse_csv(const void *stock_csv, size_t stock_len, const void *user_csv, size_t user_len) {    
    // We could probably do some fancy SIMD stuff here to parse the CSV data
    // more efficiently, but this implementation is going to be used exclusively
    // in the process of creating packages, which isn't performance-critical.

    // We copy the combined CSV data to a separate buffer, which allows us to
    // replace newline characters with null terminators and thus make dealing
    // with the data a bit simpler. Additionally, it allows us to append a final
    // null terminator in case the CSV data does not end with a newline.

    // Concatenating both CSVs into a single buffer instead of merging them
    // after processing them makes things much simpler by avoiding the need for
    // multiple binary trees, which would require more allocations and traversal
    // of one of the trees in order to merge them (which would be a huge pain in
    // the ass).

    size_t total_len = stock_len + 1 + (user_csv != NULL ? (user_len + 1) : 0);

    void *tree_data;
    if ((tree_data = malloc(total_len)) == NULL) {
        libarp_set_error("malloc failed");
        return NULL;
    }

    memcpy(tree_data, stock_csv, stock_len);
    if (user_csv != NULL && user_len > 0) {
        ((char*) tree_data)[stock_len] = '\n';
        memcpy((void*) ((uintptr_t) tree_data + stock_len + 1), user_csv, user_len);
    }

    ((char*) tree_data)[total_len - 1] = '\0';

    // first we need to count the number of lines so we can allocate a proper
    // amount of memory
    size_t line_count = 0;

    char *cur = (char*) tree_data;
    size_t remaining = stock_len;

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

    bt_node_t *bt_nodes;
    if ((bt_nodes = calloc(line_count, sizeof(bt_node_t))) == NULL) {
        free(tree_data);

        libarp_set_error("calloc failed");
        return NULL;
    }

    bt_node_t *root = &bt_nodes[0];

    cur = (char*) tree_data;
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

    csv_file_t *csv;
    if ((csv = malloc(sizeof(csv_file_t))) == NULL) {
        free(bt_nodes);
        free(tree_data);

        libarp_set_error("malloc failed");
        return NULL;
    }
    csv->tree = root;
    csv->data = tree_data;

    return csv;
}

const char *search_csv(const csv_file_t *csv, const char *key) {
    bt_node_t *node = bt_find(csv->tree, key, _csv_find_cmp);
    
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

void free_csv(csv_file_t *csv) {
    free(csv->tree);
    free(csv->data);
}

csv_file_t *merge_csvs(csv_file_t *a, csv_file_t *b) {
    //TODO
}
