#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "internal/defines/package.h"

#include <stddef.h>

typedef struct ExtensionMapping {
    char extension[NODE_EXT_MAX_LEN + 1];
    char media_type[NODE_MT_MAX_LEN + 1];
} extension_mapping_t;

const extension_mapping_t *arp_get_extension_mappings(size_t *count);

void arp_free_extension_mappings(extension_mapping_t *mappings);

#ifdef __cplusplus
}
#endif
