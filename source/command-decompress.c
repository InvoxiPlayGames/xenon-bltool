/*
    command-decompress.c - Xbox 360 CE decompression
    Copyright 2024 Emma https://ipg.gay/

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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "xenon-bootloader.h"
#include "ce-handler.h"
#include "utility.h"

int do_decompress_command(int argc, char **argv) {
    if (argc < 2) {
        printf("not enough arguments!\n");
        return -1;
    }

    char *base_path = argv[1];
    char *output_path = argv[2];

    // open, read and close our base file
    FILE *base_file = fopen(base_path, "rb");
    if (base_file == NULL) {
        printf("couldn't open the input file!\n");
        return -1;
    }
    size_t base_size = get_file_size(base_file);
    void *base_buf = malloc(base_size);
    if (base_buf == NULL) {
        printf("failed to allocate buffer for input file.\n");
        return -1;
    }
    fread(base_buf, 1, base_size, base_file);
    fclose(base_file);

    // detect the type of the base kernel file
    uint8_t *base_kernel = (uint8_t *)base_buf;
    uint32_t base_kernel_size = base_size;
    bootloader_header *hdr = (bootloader_header *)base_buf;
    uint16_t header_magic_mask = (BE16(hdr->magic) & 0xFFF);

    // If the header magic bytes are not CE, SE, or S5, this isn't a 5BL binary
    if (header_magic_mask != 0x345 && header_magic_mask != 0x335) {
        printf("input file isn't CE/SE/5BL. (header magic = 0x%x)\n",header_magic_mask);
        free(base_buf);
        return -1;
    }

    bootloader_ce_header *ce_hdr = (bootloader_ce_header *)hdr;
    ce_print_info(base_buf);
    if (!ce_is_decrypted(base_buf)) {
        printf("input CE/5BL file is encrypted.\n");
        free(base_buf);
        return -1;
    }

    // we have to decompress the base kernel
    uint8_t *decompressed_kernel_buf = malloc(BE(ce_hdr->uncompressed_size));
    if (decompressed_kernel_buf == NULL) {
        printf("failed to allocate buffer for decompressed kernel.\n");
        free(base_buf);
        return -1;
    }

    if (!ce_decompress(base_buf, decompressed_kernel_buf)) {
        printf("decompression failed.\n");
        free(base_buf);
        free (decompressed_kernel_buf);
        return -1;
    }

    base_kernel_size = BE(ce_hdr->uncompressed_size);
    base_kernel = decompressed_kernel_buf;
    hdr = (bootloader_header *)decompressed_kernel_buf;

    // save the file
    printf("writing decompressed kernel to '%s'...\n", output_path);
    FILE *out_file = fopen(output_path, "wb+");
    if (out_file == NULL) {
        printf("failed to open output file!\n");
        free(decompressed_kernel_buf);
        return -1;
    }
    fwrite(decompressed_kernel_buf, 1, BE(ce_hdr->uncompressed_size), out_file);
    fclose(out_file);
    free(base_buf);
    free(decompressed_kernel_buf);

    return 0;
}