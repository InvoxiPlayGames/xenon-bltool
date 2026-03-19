/*
    command-compress.c - Xbox 360 CE compression
    Copyright 2025 Mate Kukri <x360@mkukri.xyz>

    This file is part of xenon-bltool.

    xenon-bltool is free software: you can redistribute it and/or modify it under the terms of
    the GNU General Public License as published by the Free Software Foundation, version 2 of
    the License.

    xenon-bltool is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with xenon-bltool.
    If not, see <https://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <liblzx.h>

#include "xenon-bootloader.h"
#include "utility.h"

#define CHUNK_SIZE 0x8000

static void *liblzx_alloc(void *opaque, size_t size) {
    return calloc(1, size);
}

static void liblzx_free(void *opaque, void *ptr) {
    free(ptr);
}

static liblzx_compress_properties_t comp_props = {
    .lzx_variant = LIBLZX_VARIANT_CAB_DELTA,
    .delta_source_size = 0,
    .window_size = 0x20000,
    .chunk_granularity = CHUNK_SIZE,
    .compression_level = 70, // <= 34 segfaults, >34 produces output at aligned sizes but cannot decompress it
    .e8_file_size = 0,
    .alloc_func = liblzx_alloc,
    .free_func = liblzx_free,
    .userdata = NULL,
};

static int read_notrunc(const char *path, FILE *fp, void *p, size_t sz)
{
    if (fread(p, sz, 1, fp) == 0) { // return value in items, 1 => read sz, 0 => read nothing or error
        if (ferror(fp)) {
            perror(path);
        } else {
            fprintf(stderr, "%s: truncated\n", path);
        }
        return -1;
    }
    return 0;
}

static int write_notrunc(const char *path, FILE *fp, const void *p, size_t sz)
{
    if (fwrite(p, sz, 1, fp) == 0) {
        if (ferror(fp)) {
            perror(path);
        } else {
            fprintf(stderr, "%s: truncated\n", path);
        }
        return -1;
    }
    return 0;
}

int do_compress_command(int argc, char **argv) {
    int ret = -1;
    FILE *inf = NULL, *outf = NULL;
    liblzx_compressor_t *comp = NULL;
    size_t decompressed_5bl_size, compressed_5bl_size;
    bootloader_header hv_header;
    bootloader_ce_header comp_5bl_header;
    const liblzx_output_chunk_t *chunk;
    char buf[CHUNK_SIZE];

    if (argc < 2) {
        fprintf(stderr, "not enough arguments!\n");
        goto err;
    }

    // Open input file
    inf = fopen(argv[1], "rb");
    if (inf == NULL) {
        perror(argv[1]);
        goto err;
    }
    // Get input file size
    decompressed_5bl_size = get_file_size(inf);
    // Read HV header from decompressed 5BL
    if (read_notrunc(argv[1], inf, &hv_header, sizeof hv_header) < 0)
        goto err;
    if (BE16(hv_header.magic) != 0x4e4e && BE16(hv_header.magic) != 0x5e4e) {
        fprintf(stderr, "invalid HV magic\n");
        goto err;
    }
    // Go back to the start of the input
    if (fseek(inf, 0, SEEK_SET) < 0) {
        perror(argv[1]);
        goto err;
    }

    // Open output file
    outf = fopen(argv[2], "wb");
    if (outf == NULL) {
        perror(argv[2]);
        goto err;
    }
    // Write compressed 5BL header
    comp_5bl_header.header.magic =
        BE16(hv_header.magic) == 0x4e4e ? BE16('C'<<8|'E')
                                        : BE16('S'<<8|'E'); // retail or dev?
    comp_5bl_header.header.version = hv_header.version; // build (copy as be)
    comp_5bl_header.header.pairing = hv_header.pairing; // flags (copy as be)
    comp_5bl_header.header.flags = hv_header.flags; // qfe (copy as be)
    comp_5bl_header.header.entrypoint = 0;
    comp_5bl_header.header.size = 0; // we need to come back and fill this at the end
    memset(comp_5bl_header.key, 0, sizeof comp_5bl_header.key);
    comp_5bl_header.target_address = 0; // always 0?
    comp_5bl_header.uncompressed_size = BE(decompressed_5bl_size);
    comp_5bl_header.unknown = 0; // padding
    if (write_notrunc(argv[2], outf, &comp_5bl_header, sizeof comp_5bl_header) < 0)
        goto err;

    // Create compressor
    comp = liblzx_compress_create(&comp_props);
    if (comp == NULL) {
        fprintf(stderr, "failed to craete liblzx compressor\n");
        goto err;
    }
    // Compress full chunks chunks
    for (;;) {
        size_t read_sz, consumed_sz;

        read_sz = fread(buf, 1, sizeof buf, inf);
        if (read_sz == 0) {
            if (ferror(inf)) { // Error
                perror(argv[1]);
                goto err;
            }
            // EOF
            break;
        }

        do {
            consumed_sz = liblzx_compress_add_input(comp, buf, read_sz);
            if (consumed_sz < read_sz) {
                // Get chunk
                chunk = liblzx_compress_get_next_chunk(comp);
                assert(chunk != NULL); // We only call when we expect a chunk
                printf("Compressed chunk %zx\n", chunk->size);

                // Write chunk header
                bootloader_compression_block comp_block_header = {
                    .compressed_size = BE16(chunk->size),
                    .decompressed_size = BE16(CHUNK_SIZE),
                };
                if (write_notrunc(argv[2], outf, &comp_block_header, sizeof comp_block_header) < 0)
                    goto err;
                // Write chunk data
                if (write_notrunc(argv[2], outf, chunk->data, chunk->size) < 0)
                    goto err;

                // Release chunk
                liblzx_compress_release_next_chunk(comp);

                // Count how much of the decompressed 5BL we consume
                decompressed_5bl_size -= CHUNK_SIZE;
            }
            read_sz -= consumed_sz;
        } while (read_sz > 0);
    }
    // Do final chunk (which might be smaller)
    liblzx_compress_end_input(comp);
    chunk = liblzx_compress_get_next_chunk(comp);
    if (chunk != NULL) {
        printf("Final compressed chunk %zx\n", chunk->size);

        // Write chunk header
        bootloader_compression_block comp_block_header = {
            .compressed_size = BE16(chunk->size),
            .decompressed_size = BE16(decompressed_5bl_size),
        };
        if (write_notrunc(argv[2], outf, &comp_block_header, sizeof comp_block_header) < 0)
            goto err;
        // Write chunk data
        if (write_notrunc(argv[2], outf, chunk->data, chunk->size) < 0)
            goto err;

        liblzx_compress_release_next_chunk(comp);
    }

    // Make sure there is nothing left
    assert(liblzx_compress_get_next_chunk(comp) == NULL);

    // Fixup compressed size
    compressed_5bl_size = ftell(outf);
    if ((long) compressed_5bl_size < 0 || fseek(outf, 0, SEEK_SET) < 0) {
        perror(argv[2]);
        goto err;
    }
    comp_5bl_header.header.size = BE(compressed_5bl_size);
    if (write_notrunc(argv[2], outf, &comp_5bl_header, sizeof comp_5bl_header) < 0)
        goto err;

    ret = 0;
err:
    if (inf != NULL)
        fclose(inf);
    if (outf != NULL)
        fclose(outf);
    if (comp != NULL)
        liblzx_compress_destroy(comp);
    return ret;
}
