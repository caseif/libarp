#pragma once

#include "libarp/unpack/types.h"

#include <stddef.h>

int load_package_from_file(const char *path, ArpPackage *package);

int load_package_from_memory(const unsigned char *data, size_t package_len, ArpPackage *package);

int unload_package(ArpPackage package);
