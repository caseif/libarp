/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include <sys/stat.h>
#include <sys/types.h>

#define WIN32_PATH_DELIMITER '\\'
#define UNIX_PATH_DELIMITER '/'

#define PERM_MASK_RWX_RX_RX 0755

#ifdef _WIN32
    #include <direct.h>
    #include <stdio.h>
    #include <windows.h>

    #define fileno _fileno
    #define fseek _fseeki64
    #define fstat _fstat64
    #define stat _stat64
    #define stat_t struct _stat64

    #define mkdir(p, m) mkdir(p)

    #ifndef S_ISDIR
    #define S_ISDIR(mode) (mode & S_IFDIR)
    #endif
    #ifndef S_ISREG
    #define S_ISREG(mode) (mode & S_IFREG)
    #endif

    #define TEMP_PATH "C:\\Temp"

    #define FS_PATH_DELIMITER WIN32_PATH_DELIMITER

    #define IS_PATH_DELIMITER(c) ((c) == WIN32_PATH_DELIMITER || (c) == UNIX_PATH_DELIMITER)
#else
    #define FS_PATH_DELIMITER UNIX_PATH_DELIMITER

    #define IS_PATH_DELIMITER(c) ((c) == UNIX_PATH_DELIMITER)

    #define stat_t struct stat
#if defined __APPLE__
    #include <mach-o/dyld.h>
    #include <sys/syslimits.h>

    #define TEMP_PATH "/tmp"
#elif defined __linux__
    #include <features.h>
    #include <unistd.h>
    #include <linux/limits.h>

    #define TEMP_PATH "/tmp"
#elif defined __NetBSD__ || defined __DragonFly__
    #include <unistd.h>
    #include <sys/param.h>
    #include <sys/syslimits.h>

    #define TEMP_PATH "/tmp"
#elif defined __FreeBSD__
    #include <sys/sysctl.h>
    #include <sys/syslimits.h>

    #define TEMP_PATH "/tmp"
#else
    #error "This OS is not supported at this time."
#endif
#endif

extern int make_iso_compilers_happy;
