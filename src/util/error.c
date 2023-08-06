/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2022, Max Roncace <mproncace@protonmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#include "arp/util/error.h"
#include "internal/util/error.h"

#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#endif

char g_err_msg[ERR_MSG_MAX_LEN];

static ArpErrorCallback g_err_callback;

const char *arp_get_error(void) {
    return g_err_msg;
}

void arp_set_error_callback(ArpErrorCallback callback) {
    g_err_callback = callback;
}

void arp_real_set_error(const char *msg, const char *file, int line) {
    size_t msg_len = strlen(msg);

    if (msg_len > sizeof(g_err_msg) - 1) {
        msg_len = sizeof(g_err_msg) - 1;
    }

    memcpy(g_err_msg, msg, msg_len + 1);

    if (g_err_callback != NULL) {
        size_t full_msg_len = strlen(g_err_msg + 1);
        char *full_msg;

        #ifdef LIBARP_DEBUG
        full_msg_len += strlen(file) + 1 + (unsigned int) ceil(log10(line)) + 3;
        full_msg = malloc(full_msg_len);
        sprintf(full_msg, "%s:%d : %s", file, line, g_err_msg);
        #else
        (void)(file);
        (void)(line);
        full_msg = malloc(full_msg_len);
        sprintf(full_msg, "%s", err_msg);
        #endif

        g_err_callback(full_msg);

        free(full_msg);
    }
}
