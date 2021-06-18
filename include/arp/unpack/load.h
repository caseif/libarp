#pragma once

#include "arp/unpack/types.h"

#include <stddef.h>

int get_resource_meta(ConstArpPackage package, const char *path, arp_resource_meta_t *out_meta);

int load_package_from_file(const char *path, ArpPackage *package);

int load_package_from_memory(const unsigned char *data, size_t package_len, ArpPackage *package);

int unload_package(ArpPackage package);
