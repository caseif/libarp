/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/defines/package.h"
#include "internal/util/bt.h"
#include "internal/util/common.h"
#include "internal/util/csv.h"
#include "internal/util/error.h"
#include "internal/util/util.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int _csv_insert_cmp(const void *a, const void *b) {
    const char *csv_line_a = (char*) a;
    const char *csv_line_b = (char*) b;

    const char *delim_a = strchr(csv_line_a, ',');
    const char *delim_b = strchr(csv_line_b, ',');

    size_t key_len_a = SUB_PTRS(delim_a, csv_line_a);
    size_t key_len_b = SUB_PTRS(delim_b, csv_line_b);

    assert(key_len_a <= NODE_EXT_MAX_LEN);
    assert(key_len_b <= NODE_EXT_MAX_LEN);

    char key_buf_a[NODE_EXT_MAX_LEN + 1];
    char key_buf_b[NODE_EXT_MAX_LEN + 1];

    memcpy(key_buf_a, csv_line_a, key_len_a);
    memcpy(key_buf_b, csv_line_b, key_len_b);
    key_buf_a[key_len_a] = '\0';
    key_buf_b[key_len_b] = '\0';

    int res = strcmp(key_buf_a, key_buf_b);
    return res;
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

    size_t key_len = MIN(SUB_PTRS(delim, csv_line), NODE_EXT_MAX_LEN);

    // copy the key to a buffer so that we can null-terminate it and use strcmp
    char key_buf[NODE_EXT_MAX_LEN + 1];
    memcpy(key_buf, csv_line, key_len);
    key_buf[key_len] = '\0';

    int res = strcmp(needle, key_buf);

    return res;
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

    void *tree_data = NULL;
    if ((tree_data = malloc(total_len)) == NULL) {
        arp_set_error("malloc failed");
        return NULL;
    }

    memcpy(tree_data, stock_csv, stock_len);
    if (user_csv != NULL && user_len > 0) {
        ((char*) tree_data)[stock_len] = '\n';
        memcpy((char*) tree_data + stock_len + 1, user_csv, user_len);
    }

    ((char*) tree_data)[total_len - 1] = '\0';

    // first we need to count the number of lines so we can allocate a proper
    // amount of memory
    size_t line_count = 0;

    char *cur = (char*) tree_data;
    size_t remaining = total_len;

    // this loop basically just replaces all the newlines with null terminators
    while (remaining > 0) {
        char *line_end = (char*) memchr(cur, '\n', remaining);
        size_t line_len = 0;

        if (line_end == NULL) {
            line_len = remaining;
            remaining = 0;
        } else {
            line_len = SUB_PTRS(line_end, cur);
            remaining -= line_len + 1; // account for newline character

            // replace the newline with a null terminator
            line_end[0] = '\0';

            // for Windows, replace the carriage return as well
            if (cur[line_len - 1] == '\r') {
                cur[line_len - 1] = '\0';
            }
        }

        if (line_len == 0 || memchr(cur, ',', line_len) == NULL) {
            cur += 1;
            continue;
        }

        cur += line_len + 1; // account for newline character again

        line_count += 1;
    }

    if (line_count == 0) {
        free(tree_data);

        arp_set_error("No media type mappings are present");
        return NULL;
    }

    csv_file_t *csv = NULL;
    if ((csv = malloc(sizeof(csv_file_t))) == NULL) {
        bt_free(&csv->tree);
        free(tree_data);

        arp_set_error("malloc failed");
        return NULL;
    }

    if (bt_create(line_count, &csv->tree) == NULL) {
        free(tree_data);

        return NULL;
    }

    cur = (char*) tree_data;
    remaining = total_len;

    // this loop actually processes the raw data into a binary tree
    while (remaining > 0) {
        size_t line_len = strlen(cur);

        remaining -= line_len + 1; // account for null terminator

        char *delim = memchr(cur, ',', line_len);
        if (line_len == 0 || delim == NULL || (delim - cur) > NODE_DESC_MAX_LEN) {
            cur += 1;
            continue;
        }

        bt_insert(&csv->tree, cur, _csv_insert_cmp);

        cur += line_len + 1; // account for null terminator again
    }

    csv->data = tree_data;

    return csv;
}

const char *search_csv(const csv_file_t *csv, const char *key) {
    const char *line = bt_find(&csv->tree, key, _csv_find_cmp);
    
    if (line == NULL) {
        return NULL;
    }

    const char *delim = strchr(line, ',');
    if (delim == NULL) {
        assert(0);
    }

    return delim + 1;
}

void free_csv(csv_file_t *csv) {
    bt_free(&csv->tree);
    free(csv->data);
    free(csv);
}
