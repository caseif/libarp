/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "arp/util/error.h"
#include "internal/util/error.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#endif

char err_msg[ERR_MSG_MAX_LEN];

const char *libarp_get_error(void) {
    return err_msg;
}

void libarp_real_set_error(const char *msg, const char *file, int line) {
    size_t msg_len = strlen(msg);

    if (msg_len > sizeof(err_msg) - 1) {
        msg_len = sizeof(err_msg) - 1;
    }

    memcpy(err_msg, msg, msg_len + 1);

    #ifdef LIBARP_DEBUG
    fprintf(stderr, "%s:%d: [libarp] %s\n", file, line, err_msg);
    #endif

    #ifdef LIBARP_DEBUG
    #ifdef _WIN32
    __debugbreak();
    #else
    raise(SIGTRAP);
    #endif
    #else
    fprintf(stderr, "[libarp] %s\n", err_msg);
    #endif
}
