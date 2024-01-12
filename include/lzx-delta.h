/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#ifndef XENIA_CPU_LZX_H_
#define XENIA_CPU_LZX_H_

#include <stdint.h>
#include "xenon-bootloader.h"

int lzx_decompress(const void* lzx_data, size_t lzx_len, void* dest,
                   size_t dest_len, uint32_t window_size, void* window_data,
                   size_t window_data_len);

int lzxdelta_apply_patch(bootloader_delta_block* patch, size_t patch_len,
                         uint32_t window_size, void* dest);

#endif  // XENIA_CPU_LZX_H_
