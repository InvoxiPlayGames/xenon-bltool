/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "lzx.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#include <mspack.h>
#include <lzx.h>

#include "utility.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#include "lzx-delta.h"
#include "xenon-bootloader.h"

typedef struct mspack_memory_file_t {
  struct mspack_system sys;
  void* buffer;
  uint32_t buffer_size;
  uint32_t offset;
} mspack_memory_file;

mspack_memory_file* mspack_memory_open(struct mspack_system* sys, void* buffer,
                                       const size_t buffer_size) {
  if (buffer_size >= INT_MAX) {
    return NULL;
  }
  mspack_memory_file* memfile =
      (mspack_memory_file*)calloc(1, sizeof(mspack_memory_file));
  if (!memfile) {
    return NULL;
  }
  memfile->buffer = buffer;
  memfile->buffer_size = (uint32_t)buffer_size;
  memfile->offset = 0;
  return memfile;
}

void mspack_memory_close(mspack_memory_file* file) {
  mspack_memory_file* memfile = (mspack_memory_file*)file;
  free(memfile);
}

int mspack_memory_read(struct mspack_file* file, void* buffer, int chars) {
  mspack_memory_file* memfile = (mspack_memory_file*)file;
  const uint32_t remaining = memfile->buffer_size - memfile->offset;
  const uint32_t total = MIN(chars, remaining);
  memcpy(buffer, (uint8_t*)memfile->buffer + memfile->offset, total);
  memfile->offset += total;
  return (int)total;
}

int mspack_memory_write(struct mspack_file* file, void* buffer, int chars) {
  mspack_memory_file* memfile = (mspack_memory_file*)file;
  const uint32_t remaining = memfile->buffer_size - memfile->offset;
  const uint32_t total = MIN(chars, remaining);
  memcpy((uint8_t*)memfile->buffer + memfile->offset, buffer, total);
  memfile->offset += total;
  return (int)total;
}

void* mspack_memory_alloc(struct mspack_system* sys, size_t chars) {
  return calloc(chars, 1);
}

void mspack_memory_free(void* ptr) { free(ptr); }

void mspack_memory_copy(void* src, void* dest, size_t chars) {
  memcpy(dest, src, chars);
}

struct mspack_system* mspack_memory_sys_create() {
  struct mspack_system* sys = (struct mspack_system*)calloc(1, sizeof(struct mspack_system));
  if (!sys) {
    return NULL;
  }
  sys->read = mspack_memory_read;
  sys->write = mspack_memory_write;
  sys->alloc = mspack_memory_alloc;
  sys->free = mspack_memory_free;
  sys->copy = mspack_memory_copy;
  return sys;
}

void mspack_memory_sys_destroy(struct mspack_system* sys) { free(sys); }

bool bit_scan_forward(uint32_t v, uint32_t* out_first_set_index) {
  int i = __builtin_ffs(v);
  *out_first_set_index = i - 1;
  return i != 0;
}

int lzx_decompress(const void* lzx_data, size_t lzx_len, void* dest,
                   size_t dest_len, uint32_t window_size, void* window_data,
                   size_t window_data_len) {
  int result_code = 1;

  uint32_t window_bits;
  if (!bit_scan_forward(window_size, &window_bits)) {
    return result_code;
  }

  struct mspack_system* sys = mspack_memory_sys_create();
  mspack_memory_file* lzxsrc =
      mspack_memory_open(sys, (void*)lzx_data, lzx_len);
  mspack_memory_file* lzxdst = mspack_memory_open(sys, dest, dest_len);
  struct lzxd_stream* lzxd = lzxd_init(sys, (struct mspack_file*)lzxsrc, (struct mspack_file*)lzxdst,
                                window_bits, 0, 0x8000, (uint32_t)dest_len, 0);

  if (lzxd) {
    if (window_data) {
      // zero the window and then copy window_data to the end of it
      int padding_len = window_size - window_data_len;
      memset(&lzxd->window[0], 0, padding_len);
      memcpy(&lzxd->window[padding_len], window_data, window_data_len);
      // TODO(gibbed): should this be set regardless if source window data is
      // available or not?
      lzxd->ref_data_size = window_size;
    }

    result_code = lzxd_decompress(lzxd, (uint32_t)dest_len);

    lzxd_free(lzxd);
    lzxd = NULL;
  }

  if (lzxsrc) {
    mspack_memory_close(lzxsrc);
    lzxsrc = NULL;
  }

  if (lzxdst) {
    mspack_memory_close(lzxdst);
    lzxdst = NULL;
  }

  if (sys) {
    mspack_memory_sys_destroy(sys);
    sys = NULL;
  }

  return result_code;
}

int lzxdelta_apply_patch(bootloader_delta_block* patch, size_t patch_len,
                         uint32_t window_size, void* dest) {
  uint8_t* patch_end = (char*)patch + patch_len;
  bootloader_delta_block* cur_patch = patch;

  while (patch_end > (uint8_t*)cur_patch) {
    int patch_sz = 0;  // 0 byte patches need us to remove 4 byte from next
                        // patch addr because of patch_data field
    if (BE16(cur_patch->compressed_size) == 0 && BE16(cur_patch->decompressed_size) == 0 &&
        BE(cur_patch->new_addr) == 0 && BE(cur_patch->old_addr) == 0)
      break;
    switch (BE16(cur_patch->compressed_size)) {
      case 0:  // fill with 0
        memset((char*)dest + BE(cur_patch->new_addr), 0,
                    BE16(cur_patch->decompressed_size));
        break;
      case 1:  // copy from old -> new
        memcpy((char*)dest + BE(cur_patch->new_addr),
                    (char*)dest + BE(cur_patch->old_addr),
                    BE16(cur_patch->decompressed_size));
        break;
      default:  // delta patch
        patch_sz =
            BE16(cur_patch->compressed_size);  // -4 because of patch_data field

        int result = lzx_decompress(
            (char*)(cur_patch + 1), BE16(cur_patch->compressed_size),
            (char*)dest + BE(cur_patch->new_addr), BE16(cur_patch->decompressed_size),
            window_size, (char*)dest + BE(cur_patch->old_addr),
            BE16(cur_patch->decompressed_size));

        if (result) {
          return result;
        }
        break;
    }

    cur_patch++;
    cur_patch = (bootloader_delta_block*)(((char*)cur_patch) +
                                        patch_sz);  // TODO: make this less ugly
  }

  return 0;
}
