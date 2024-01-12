#include <stdint.h>
#include <stdbool.h>

bool get_full_compressed_buffer(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t decompressed_size, uint32_t *compressed_size);
