#pragma once

#include "libarp/common.h"

#include <stdlib.h>

int load_package_from_file(const char *path, ArgusPackage *package);

int load_package_from_memory(const unsigned char *data, size_t package_len, ArgusPackage *package);

int unload_package(ArgusPackage package);

arp_resource_t *load_resource(const ArgusPackage package, const char *path);

void unload_resource(arp_resource_t *resource);
