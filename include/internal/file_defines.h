/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
    #include <Windows.h>

    #define fileno _fileno
    #define fseek _fseeki64
    #define fstat _fstat64
    #define stat _stat64
    #define stat_t struct _stat64

    #define S_ISDIR(mode) (mode & S_IFDIR)
    #define S_ISREG(mode) (mode & S_IFREG)

    #define TEMP_PATH "C:\\Temp"
#elif defined __APPLE__
    #include <dirent.h>
    #include <mach-o/dyld.h>
    #include <sys/syslimits.h>

    #define stat_t struct stat

    #define TEMP_PATH "/tmp"
#elif defined __linux__
    #include <dirent.h>
    #include <features.h>
    #include <unistd.h>
    #include <linux/limits.h>

    #define stat_t struct stat

    #define TEMP_PATH "/tmp"
#elif defined __NetBSD__ || defined __DragonFly__
    #include <dirent.h>
    #include <unistd.h>
    #include <sys/param.h>
    #include <sys/syslimits.h>

    #define stat_t struct stat

    #define TEMP_PATH "/tmp"
#elif defined __FreeBSD__
    #include <dirent.h>
    #include <sys/sysctl.h>
    #include <sys/syslimits.h>

    #define stat_t struct stat

    #define TEMP_PATH "/tmp"
#else
    #error "This OS is not supported at this time."
#endif
