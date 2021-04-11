#pragma once

typedef void *DeflateStream;

DeflateStream compress_deflate_begin(const size_t total_input_bytes);

int compress_deflate(DeflateStream stream, void *data, size_t data_len, void **out_data, size_t *out_data_len);

void compress_deflate_end(DeflateStream stream);

DeflateStream decompress_deflate_begin(const size_t total_input_bytes, const size_t total_output_bytes);

int decompress_deflate(DeflateStream stream, void *in_data, size_t in_data_len, void **out_data, size_t *out_data_len);

void decompress_deflate_end(DeflateStream stream);
