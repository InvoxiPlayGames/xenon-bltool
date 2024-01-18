#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#ifndef SHOULD_BE_BE
#define BE16(i) ((((i) & 0xFF) << 8 | ((i) >> 8) & 0xFF) & 0xFFFF)
#define BE(i)   (((i) & 0xff) << 24 | ((i) & 0xff00) << 8 | ((i) & 0xff0000) >> 8 | ((i) >> 24) & 0xff)
#define BE64(i) (BE((i) & 0xFFFFFFFF) << 32 | BE(((i) >> 32) & 0xFFFFFFFF))
#else
#define BE16(i) i
#define BE(i) i
#define BE64(i) i
#endif

#ifdef SHOULD_BE_BE
#define LE16(i) ((((i) & 0xFF) << 8 | ((i) >> 8) & 0xFF) & 0xFFFF)
#define LE(i)   (((i) & 0xff) << 24 | ((i) & 0xff00) << 8 | ((i) & 0xff0000) >> 8 | ((i) >> 24) & 0xff)
#define LE64(i) (BE((i) & 0xFFFFFFFF) << 32 | BE(((i) >> 32) & 0xFFFFFFFF))
#else
#define LE16(i) i
#define LE(i) i
#define LE64(i) i
#endif

void hexdump(uint8_t *data, uint32_t size);
bool parse_hex_str(char *str, uint8_t *out_buf, size_t buf_size);
void dump_to_file(char *filename, uint8_t *buf, size_t size);
size_t get_file_size(FILE *fp);
