#pragma once

#include "arp/unpack/types.h"

ArpPackageSet create_package_set(void);

int add_package_to_set(ArpPackageSet set, ArpPackage package);

void remove_package_from_set(ArpPackageSet set, ArpPackage package);

void destroy_package_set(ArpPackageSet set);
