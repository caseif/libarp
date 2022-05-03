/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include <stdint.h>

// defines in this header are taken from the ARP specification

#define PACKAGE_EXT "arp"

#define FORMAT_MAGIC "\x1B\x41\x52\x47\x55\x53\x52\x50"

#define ARP_COMPRESS_MAGIC_DEFLATE "df"

#define ENTRY_TYPE_RESOURCE 0
#define ENTRY_TYPE_DIRECTORY 1

#define PACKAGE_HEADER_LEN 0x100
#define PACKAGE_MAGIC_LEN 8
#define PACKAGE_VERSION_LEN 2
#define PACKAGE_PARTS_LEN 2
#define PACKAGE_CAT_OFF_LEN 8
#define PACKAGE_CAT_LEN_LEN 8
#define PACKAGE_CAT_CNT_LEN 4
#define PACKAGE_DIR_CNT_LEN 4
#define PACKAGE_RES_CNT_LEN 4
#define PACKAGE_BODY_OFF_LEN 8
#define PACKAGE_BODY_LEN_LEN 8
#define PACKAGE_RESERVED_1_LEN 0x96

#define PACKAGE_MAGIC_OFF       0x00
#define PACKAGE_VERSION_OFF     0x08
#define PACKAGE_COMPRESSION_OFF 0x0A
#define PACKAGE_NAMESPACE_OFF   0x0C
#define PACKAGE_PARTS_OFF       0x3C
#define PACKAGE_CAT_OFF_OFF     0x3E
#define PACKAGE_CAT_LEN_OFF     0x46
#define PACKAGE_CAT_CNT_OFF     0x4E
#define PACKAGE_DIR_CNT_OFF     0x52
#define PACKAGE_RES_CNT_OFF     0x56
#define PACKAGE_BODY_OFF_OFF    0x5A
#define PACKAGE_BODY_LEN_OFF    0x62
#define PACKAGE_RESERVED_1_OFF  0x6A

#define PART_MAGIC "\x1B\x41\x52\x47\x55\x53\x50\x54"

#define PART_MAGIC_LEN 8
#define PART_INDEX_LEN 2
#define PART_UNUSED_LEN 6

#define PART_MAGIC_OFF 0
#define PART_INDEX_OFF 8
#define PART_UNUSED_OFF 10

#define PACKAGE_PART_HEADER_LEN 0x10

#define PACKAGE_MAX_PARTS 999

#define PACKAGE_MIN_PART_LEN 4096

#define PACKAGE_PART_1_SUFFIX ".part001"

#define ND_LEN_LEN                  2
#define ND_TYPE_LEN                 1
#define ND_PART_LEN                 2
#define ND_DATA_OFF_LEN             8
#define ND_PACKED_DATA_LEN_LEN      8
#define ND_UNPACKED_DATA_LEN_LEN    8
#define ND_CRC_LEN                  4
#define ND_NAME_LEN_LEN             1
#define ND_EXT_LEN_LEN              1
#define ND_MT_LEN_LEN               1

#define ND_LEN_OFF                  0x00
#define ND_TYPE_OFF                 0x02 
#define ND_PART_OFF                 0x03
#define ND_DATA_OFF_OFF             0x05
#define ND_PACKED_DATA_LEN_OFF      0x0D
#define ND_UNPACKED_DATA_LEN_OFF    0x15
#define ND_CRC_OFF                  0x1D
#define ND_NAME_LEN_OFF             0x21
#define ND_EXT_LEN_OFF              0x22
#define ND_MT_LEN_OFF               0x23
#define ND_NAME_OFF                 0x24

#define NODE_DESC_BASE_LEN ND_NAME_OFF

#define NODE_NAME_MAX_LEN 0xFF
#define NODE_EXT_MAX_LEN 0xFF
#define NODE_MT_MAX_LEN 0xFF
#define NODE_DESC_MAX_LEN (NODE_DESC_BASE_LEN + NODE_NAME_MAX_LEN + NODE_EXT_MAX_LEN + NODE_MT_MAX_LEN)

// the length of an index to a node descriptor
// directory nodes contain an array of node descriptor indices in their body
#define NODE_DESC_INDEX_LEN 4

#define PACK_NODE_TYPE_RESOURCE 0
#define PACK_NODE_TYPE_DIRECTORY 1

#define DIRECTORY_CONTENT_MAX_LEN (4294967296 * NODE_DESC_INDEX_LEN) // we need _some_ sane limit

extern int make_iso_compilers_happy;
