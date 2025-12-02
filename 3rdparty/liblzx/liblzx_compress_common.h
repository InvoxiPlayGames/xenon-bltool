/*
 * compress_common.h
 *
 * Header for compression code shared by multiple compression formats.
 */

#ifndef _LIBLZX_COMPRESS_COMMON_H
#define _LIBLZX_COMPRESS_COMMON_H

#include "liblzx_types.h"

#define MAX_NUM_SYMS            799        /* LZMS_MAX_NUM_SYMS */
#define MAX_CODEWORD_LEN        16

void
make_canonical_huffman_code(unsigned num_syms, unsigned max_codeword_len,
                            const uint32_t freqs[], uint8_t lens[], uint32_t codewords[]);

#endif /* _LIBLZX_COMPRESS_COMMON_H */
