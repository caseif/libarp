#pragma once

int compress_deflate(void);

int decompress_deflate(const void *compressed_data, size_t compressed_len, size_t final_len, void **output_buf);
