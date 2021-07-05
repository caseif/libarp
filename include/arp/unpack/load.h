#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "arp/unpack/types.h"

#include <stddef.h>

int arp_get_resource_meta(ConstArpPackage package, const char *path, arp_resource_meta_t *out_meta);

int arp_load_from_file(const char *path, ArpPackage *package);

int arp_load_from_memory(const unsigned char *data, size_t package_len, ArpPackage *package);

int arp_unload(ArpPackage package);

#ifdef __cplusplus
}
#endif
