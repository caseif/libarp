#pragma once

#include <stddef.h>

typedef void *ArgusPackage;

typedef struct ArpResource {
    void *data;
    size_t len;

    void *extra;
} arp_resource_t;

const char *libarp_get_error(void);
