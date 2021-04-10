#pragma once

typedef void *DeflateStream;

DeflateStream compress_deflate_init(const size_t total_input_bytes);

int compress_deflate(DeflateStream stream, void *data, size_t data_len, void **out_data, size_t *out_data_len);

void compress_deflate_finish(DeflateStream stream);

int decompress_deflate(const void *compressed_data, size_t compressed_len, size_t final_len, void **out_data);
