#include "arp/util/media_types.h"
#include "internal/defines/package.h"
#include "internal/generated/media_types.csv.h"
#include "internal/util/common.h"
#include "internal/util/csv.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extension_mapping_t *arp_get_extension_mappings(size_t *count) {
    csv_file_t *csv = parse_csv(MEDIA_TYPES_CSV_SRC, MEDIA_TYPES_CSV_LEN, NULL, 0);

    if (csv->tree.count == 0) {
        return NULL;
    }

    extension_mapping_t *mappings = calloc(csv->tree.count, sizeof(extension_mapping_t));

    size_t i = 0;
    void **csv_line_ptr = NULL;
    bt_reset_iterator(&csv->tree);
    while ((csv_line_ptr = bt_iterate(&csv->tree)) != NULL) {
        char *csv_line = (char*) *csv_line_ptr;
        size_t line_len = strlen(csv_line);

        if (line_len == 0) {
            continue;
        }

        const char *delim = memchr(csv_line, ',', line_len);

        if (delim == NULL) {
            assert(0);
        }

        extension_mapping_t *mapping = &mappings[i];
        
        size_t ext_len = delim - csv_line;
        size_t mt_len = line_len - ext_len - 1;



        if (ext_len > sizeof(mapping->extension) - 1 || mt_len > sizeof(mapping->media_type) - 1) {
            continue;
        }

        memcpy(mapping->extension, csv_line, ext_len);
        mapping->extension[ext_len] = '\0';
        memcpy(mapping->media_type, csv_line + ext_len + 1, mt_len);
        mapping->extension[ext_len + 1 + mt_len] = '\0';

        i++;
    }

    size_t real_count = i;

    free_csv(csv);

    *count = real_count;
    return mappings;
}

void arp_free_extension_mappings(extension_mapping_t *mappings) {
    if (mappings == NULL) {
        return;
    }

    free(mappings);
}
