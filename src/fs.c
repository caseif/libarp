/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "internal/fs.h"
#include "internal/util.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dirent.h>
#include <sys/types.h>
#endif

typedef struct DirHandleStruct {
    const char *path;
    #ifdef _WIN32
    HANDLE find_handle;
    WIN32_FIND_DATAA find_data;
    #else
    DIR *dir;
    #endif
} dir_handle_t;

DirHandle open_directory(const char *path) {
    dir_handle_t *handle;
    if ((handle = malloc(sizeof(dir_handle_t))) == NULL) {
        libarp_set_error("malloc failed");
        return NULL;
    }

    #ifdef _WIN32
    char *new_path = NULL;
    size_t new_path_len_b = strlen(path) + 3;
    if (new_path_len_b < strlen(path)) {
        libarp_set_error("Path too long");
        return NULL;
    }

    if ((new_path = malloc(new_path_len_b)) == NULL) {
        free(handle);

        libarp_set_error("malloc failed");
        return NULL;
    }
    strncpy(new_path, path, new_path_len_b);
    new_path[strlen(path)] = '\\';
    new_path[strlen(path) + 1] = '*';
    new_path[strlen(path) + 2] = '\0';
    handle->path = new_path;
    #else
    handle->path = path;
    #endif

    #ifdef _WIN32
    handle->find_handle = NULL;
    #else
    if ((handle->dir = opendir(path)) == NULL) {
        free(handle);

        libarp_set_error("Failed to open directory");
        return NULL;
    }
    #endif

    return handle;
}

const char *read_directory(DirHandle dir) {
    dir_handle_t *real_dir = (dir_handle_t*) dir;

    #ifdef _WIN32
    if (real_dir->find_handle == NULL) {
        if ((real_dir->find_handle = FindFirstFile(real_dir->path, &real_dir->find_data)) == INVALID_HANDLE_VALUE) {
            if (GetLastError() != ERROR_FILE_NOT_FOUND) {
                errno = GetLastError();
                libarp_set_error("FindFirstFile failed");
            }
            return NULL;
        }
    } else {
        if (!FindNextFile(real_dir->find_handle, &real_dir->find_data)) {
            return NULL;
        }
    }

    char *res = real_dir->find_data.cFileName;
    #else
    struct dirent *de = readdir(real_dir->dir);
    if (de == NULL) {
        return NULL;
    }
    
    char *res = de->d_name;
    #endif
    
    if (res[0] == '.' && ((strlen(res) == 1) || (strlen(res) == 2 && res[1] == '.'))) {
        return read_directory(dir);
    }

    return res;
}

void rewind_directory(DirHandle dir) {
    dir_handle_t *real_dir = (dir_handle_t*) dir;

    #ifdef _WIN32
    FindClose(real_dir->find_handle);
    real_dir->find_handle = NULL;
    #else
    rewinddir(real_dir->dir);
    #endif
}

void close_directory(DirHandle dir) {
    dir_handle_t *real_dir = (dir_handle_t*) dir;

    #ifdef _WIN32
    // why does this return 0 on failure -_-
    if (FindClose(real_dir->find_handle) == 0) {
        errno = GetLastError();
        libarp_set_error("Failed to close directory");
    }
    #else
    int rc;
    if ((rc = closedir(real_dir->dir)) != 0) {
        errno = rc;
        libarp_set_error("Failed to close directory");
    }
    #endif

    free(dir);
}
