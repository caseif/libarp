/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

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
