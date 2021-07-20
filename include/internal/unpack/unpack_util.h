#pragma once

#include "internal/unpack/types.h"

#include <stddef.h>
#include <stdio.h>

int unpack_node_data(const node_desc_t *node, FILE *out_file,
        void **out_data, size_t *out_data_len, bool *out_malloced, FILE *part);
