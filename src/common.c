#include <stdio.h>
#include <string.h>

#include "libarp/common.h"
#include "internal/util.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#endif

char err_msg[256];

const char *libarp_get_error(void) {
    return err_msg;
}

void libarp_set_error(const char *msg) {
    size_t msg_len = strlen(msg);

    if (msg_len > sizeof(err_msg) - 1) {
        msg_len = sizeof(err_msg) - 1;
    }

    memcpy(err_msg, msg, msg_len + 1);

    #ifdef _WIN32
    __debugbreak();
    #else
    raise(SIGTRAP);
    #endif
}
