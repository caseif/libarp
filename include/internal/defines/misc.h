/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#define USER_MT_FILE_MAX_SIZE 51200

#define FILE_NESTING_LIMIT 64

#ifdef _WIN32
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

#define UNINIT_U32 ((int) 0xDEADBEEF)

extern int make_iso_compilers_happy;
