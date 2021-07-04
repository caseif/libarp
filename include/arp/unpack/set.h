#pragma once

#include "arp/unpack/types.h"

ArpPackageSet arp_create_set(void);

int arp_add_to_set(ArpPackageSet set, ArpPackage package);

void arp_remove_from_set(ArpPackageSet set, ArpPackage package);

void arp_destroy_set(ArpPackageSet set);
