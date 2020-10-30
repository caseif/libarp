#pragma once

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <Windows.h>

    #define fileno _fileno
    #define fseek _fseeki64
    #define fstat _fstat64
    #define stat _stat64
    #define stat_t struct _stat64

    #define S_ISDIR(mode) (mode & S_IFDIR)
    #define S_ISREG(mode) (mode & S_IFREG)
#elif defined __APPLE__
    #include <dirent.h>
    #include <mach-o/dyld.h>

    #define stat_t struct stat
#elif defined __linux__
    #include <dirent.h>
    #include <features.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/types.h>

    #ifndef __USE_FILE_OFFSET64
        #define __USE_FILE_OFFSET64
    #endif
    #ifndef __USE_LARGEFILE64
        #define __USE_LARGEFILE64
    #endif
    #ifndef _LARGEFILE64_SOURCE
        #define _LARGEFILE64_SOURCE
    #endif
    #ifndef _FILE_OFFSET_BIT
        #define _FILE_OFFSET_BIT 64
    #endif

    #define stat_t struct stat
#elif defined __NetBSD__ || defined __DragonFly__
    #include <dirent.h>
    #include <unistd.h>

    #define stat_t struct stat
#elif defined __FreeBSD__
    #include <dirent.h>
    #include <sys/sysctl.h>
    #include <sys/types.h>

    #define stat_t struct stat
#else
    #error "This OS is not supported at this time."
#endif
