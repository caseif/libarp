#pragma once

#include "libarp/unpack/types.h"

#include <stddef.h>

#define ARP_STREAM_EOF 0xDEADDEAD

typedef void *ArpResourceStream;

ArpResourceStream create_resource_stream(arp_resource_meta_t *meta, size_t chunk_len);

int stream_resource(ArpResourceStream stream, void **out_data, size_t *out_data_len);

void free_resource_stream(ArpResourceStream stream);
