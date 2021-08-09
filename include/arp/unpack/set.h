#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "arp/unpack/types.h"

ArpPackageSet arp_create_set(void);

int arp_add_to_set(ArpPackageSet set, ArpPackage package);

void arp_remove_from_set(ArpPackageSet set, ArpPackage package);

int arp_unload_set_packages(ArpPackageSet set);

void arp_destroy_set(ArpPackageSet set);

#ifdef __cplusplus
}
#endif
