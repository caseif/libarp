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
#elif defined __APPLE__
    #include <dirent.h>
    #include <mach-o/dyld.h>

    #define stat_t struct stat
#elif defined __linux__
    #include <dirent.h>
    #include <features.h>
    #include <unistd.h>

    #define stat_t struct stat
#elif defined __NetBSD__ || defined __DragonFly__
    #include <dirent.h>
    #include <unistd.h>

    #define stat_t struct stat
#elif defined __FreeBSD__
    #include <dirent.h>
    #include <sys/sysctl.h>

    #define stat_t struct stat
#else
    #error "This OS is not supported at this time."
#endif
