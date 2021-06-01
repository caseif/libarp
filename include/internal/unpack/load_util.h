#pragma once

#include "internal/unpack/types.h"
#include "internal/util/error.h"

#include <stdio.h>

FILE *open_part_file_for_node(const node_desc_t *node);

int setup_part_file_for_node(FILE *part_file, const node_desc_t *node);
