/*
 * Copyright (C) 2025 Eric Lasota
 * Based on wimlib.  Copyright (C) 2012-2017 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see https://www.gnu.org/licenses/.
 */

#pragma once

#ifndef __LIBLZX_H__
#define __LIBLZX_H__

#include <stddef.h>
#include <stdint.h>

#include "liblzx_error.h"

typedef struct liblzx_internal liblzx_internal_t;
typedef struct liblzx_compress_properties liblzx_compress_properties_t;
typedef struct liblzx_compressor liblzx_compressor_t;
typedef struct liblzx_output_chunk liblzx_output_chunk_t;

typedef void *(*liblzx_alloc_func_t)(void *opaque, size_t size);
typedef void (*liblzx_free_func_t)(void *opaque, void *ptr);

enum liblzx_variant {
        /* LZX variant used by CAB files and LZX DELTA */
        LIBLZX_VARIANT_CAB_DELTA,

        /* LZX variant used by WIM */
        LIBLZX_VARIANT_WIM,
};

typedef enum liblzx_variant liblzx_variant_t;

enum liblzx_constant {
        LIBLZX_CONST_DEFAULT_CHUNK_SIZE = 32768,
        LIBLZX_CONST_DEFAULT_E8_FILE_SIZE = 12 * 1024 * 1024,
        LIBLZX_CONST_MAX_WINDOW_SIZE = 64 * 1024 * 1024,
};

struct liblzx_output_chunk {
        const void *data;
        size_t size;
};

struct liblzx_compress_properties {
        /* LZX variant to use */
        liblzx_variant_t lzx_variant;

        /* Source file size for LZX DELTA.  Ignored for WIM.
         * When using this, use liblzx_compress_add_input to add the source
         * file's data before adding the new file's data.  For compression
         * only, set this to 0.
         */
        size_t delta_source_size;

        /* Compression window size. */
        uint32_t window_size;

        /* Granularity of a chunk.  Should generally be set to
         * LIBLZX_CONST_DEFAULT_CHUNK_SIZE.
         */
        uint32_t chunk_granularity;

        /* Compression level.  Can be set arbitrarily high. */
        uint16_t compression_level;

        /* E8 file size parameter.  For WIM, this is ignored.  For other
         * variants, this value is expected to be user-controllable and
         * is sent outside of the LZX data stream.
         */
        uint32_t e8_file_size;

        /* Memory allocation function. */
        liblzx_alloc_func_t alloc_func;

        /* Memory free function. */
        liblzx_free_func_t free_func;

        /* Userdata parameter to pass to alloc function. */
        void *userdata;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Creates a compressor object and returns a pointer to it. */
liblzx_compressor_t *
liblzx_compress_create(const liblzx_compress_properties_t *props);

/* Destroys a compressor object and releases all resources. */
void
liblzx_compress_destroy(liblzx_compressor_t *stream);

/* Resets a compressor to its initial state. */
void
liblzx_compress_reset(liblzx_compressor_t *stream);

/* Adds input data to the compression stream and returns the number of bytes
 * digested.  The return value will never exceed in_data_size.  If this
 * returns a value smaller than in_data_size, then a compressed block was
 * produced and must be released with liblzx_compress_release_next_block
 * before more data can be added.
 */
size_t
liblzx_compress_add_input(liblzx_compressor_t *stream, const void *in_data,
                          size_t in_data_size);

/* Returns the next compressed chunk.  This doesn't consume the chunk in the
 * process, so repeated calls will keep returning the same chunk.  If no chunk
 * is available, returns NULL.
 */
const liblzx_output_chunk_t *
liblzx_compress_get_next_chunk(const liblzx_compressor_t *stream);

/* Releases the next compressed chunk, allowing compression to continue. */
void
liblzx_compress_release_next_chunk(liblzx_compressor_t *stream);

/* Ends the compression stream. */
void
liblzx_compress_end_input(liblzx_compressor_t *stream);

#ifdef __cplusplus
}
#endif

#endif
