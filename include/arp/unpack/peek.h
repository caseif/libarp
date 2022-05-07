#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

bool arp_is_base_archive(const char *path);

bool arp_is_part_archive(const char *path);

#ifdef __cplusplus
}
#endif
