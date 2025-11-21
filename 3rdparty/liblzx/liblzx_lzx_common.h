/*
 * lzx_common.h
 *
 * Declarations shared between LZX compression and decompression.
 */

#ifndef _LZX_COMMON_H
#define _LZX_COMMON_H

#include "liblzx_lzx_constants.h"
#include "liblzx_types.h"

extern const int32_t lzx_offset_slot_base[LZX_MAX_OFFSET_SLOTS + 1];

extern const uint8_t lzx_extra_offset_bits[LZX_MAX_OFFSET_SLOTS];

unsigned
lzx_get_window_order(size_t max_bufsize);

unsigned
lzx_get_num_main_syms(unsigned window_order);

void
lzx_preprocess(uint8_t *data, uint32_t size, uint32_t chunk_offset, uint32_t e8_file_size);

void
lzx_postprocess(uint8_t *data, uint32_t size, uint32_t chunk_offset, uint32_t e8_file_size);

#endif /* _LZX_COMMON_H */
