/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define ARP_NAMESPACE_MAX 0x30

#define ARP_COMPRESS_TYPE_DEFLATE "deflate"

#define ARP_NAMESPACE_DELIMITER ':'
#define ARP_PATH_DELIMITER '/'

#define PACKAGE_COMPRESSION_LEN 2
#define PACKAGE_NAMESPACE_LEN 0x30

extern int make_iso_compilers_happy;

#ifdef __cplusplus
}
#endif
