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

#define ERR_MSG_MAX_LEN 4096

#define E_ARP_RESOURCE_NOT_FOUND 1024

typedef void (* ArpErrorCallback)(const char *);

const char *arp_get_error(void);

void arp_set_error_callback(const ArpErrorCallback callback);

#ifdef __cplusplus
}
#endif
