#include "internal/defines/file.h"
#include "internal/defines/misc.h"
#include "internal/unpack/load_util.h"
#include "internal/unpack/types.h"
#include "internal/util/error.h"

#include <stdio.h>

static int _validate_part_file(FILE *file, const node_desc_t *node) {
    stat_t part_stat;
    if (fstat(fileno(file), &part_stat) != 0) {
        libarp_set_error("Failed to stat part file");
        return -1;
    }

    if ((size_t) part_stat.st_size < PACKAGE_PART_HEADER_LEN + node->data_off + node->packed_data_len) {
        libarp_set_error("Part file is too small to fit node data");
        return -1;
    }

    return 0;
}

static int _seek_to_node(FILE *part_file, const node_desc_t *node) {
    size_t part_body_start = 0;
    if (node->part_index == 1) {
        part_body_start = node->package->body_off;
    } else {
        part_body_start = PACKAGE_PART_HEADER_LEN;
    }

    int rc = UNINIT_U32;
    if ((rc = fseek(part_file, (long) (part_body_start + node->data_off), SEEK_SET)) != 0) {
        libarp_set_error("Failed to seek to node offset");
        return rc;
    }

    return 0;
}

FILE *open_part_file_for_node(const node_desc_t *node) {
    if (node->part_index > node->package->total_parts) {
        libarp_set_error("Node part index is invalid");
        return NULL;
    }

    FILE *part_file = fopen(node->package->part_paths[node->part_index - 1], "rb");
    if (part_file == NULL) {
        libarp_set_error("Failed to open part file for loading");
        return NULL;
    }

    if (_validate_part_file(part_file, node) != 0) {
        fclose(part_file);
        return NULL;
    }

    if (_seek_to_node(part_file, node) != 0) {
        fclose(part_file);
        return NULL;
    }

    return part_file;
}

int setup_part_file_for_node(FILE *part_file, const node_desc_t *node) {
    int rc = UNINIT_U32;

    if ((rc = _validate_part_file(part_file, node)) != 0) {
        return rc;
    }

    if ((rc = _seek_to_node(part_file, node)) != 0) {
        return rc;
    }

    return 0;
}
