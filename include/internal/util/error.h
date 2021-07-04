/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#define ERR_MSG_MAX_LEN 4096

#ifdef LIBARP_DEBUG
#define arp_set_error(msg) arp_real_set_error(msg, __FILE__, __LINE__)
#else
#define arp_set_error(msg) arp_real_set_error(msg, "", 0)
#endif

void arp_real_set_error(const char *msg, const char *file, int line);
