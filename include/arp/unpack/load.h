#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "arp/unpack/types.h"

#include <stddef.h>

int arp_load_from_file(const char *path, arp_package_meta_t *out_meta, ArpPackage *out_package);

int arp_load_from_memory(const unsigned char *data, size_t package_len, arp_package_meta_t *out_meta, ArpPackage *out_package);

int arp_unload(ArpPackage package);

#ifdef __cplusplus
}
#endif
