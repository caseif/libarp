#pragma once

#include "arp/unpack/types.h"

int arp_unpack_to_fs(ConstArpPackage package, const char *target_dir);

int arp_unpack_resource_to_fs(const arp_resource_meta_t *meta, const char *target_dir);
