/*
    ce-handler.c - Handling for Xbox 360 CE/5BL bootloader stages.
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
#include <stdbool.h>
#include <string.h>
#include "utility.h"
#include "excrypt.h"
#include "xenon-bootloader.h"
#include "lzx-delta.h"
#include "compression-handler.h"

bool ce_is_decrypted(uint8_t *ce_data) {
    bootloader_ce_header *hdr = (bootloader_ce_header *)ce_data;
    // this might be a naive assumption, but i've never seen this unknown value be anything but 0.
    return (hdr->unknown == 0x00000000);
}

void ce_print_info(uint8_t *ce_data) {
    bootloader_ce_header *hdr = (bootloader_ce_header *)ce_data;
    char *indicator = ((BE16(hdr->header.magic) & 0xF000) == 0x5000) ? "SE" : "CE";
    printf("%s version: %i\n", indicator, BE16(hdr->header.version));
    printf("%s size: 0x%x\n", indicator, BE(hdr->header.size));
    if (ce_is_decrypted(ce_data)) {
        printf("%s decompressed size: 0x%x\n", indicator, BE(hdr->uncompressed_size));
        printf("%s load address: 0x%llx\n", indicator, BE64(hdr->target_address));
    } else {
        printf("%s is encrypted\n", indicator);
    }
}

void ce_decrypt(uint8_t *ce_data, uint8_t *cd_key) {
    bootloader_ce_header *hdr = (bootloader_ce_header *)ce_data;
    uint8_t ce_key[0x10];
    EXCRYPT_RC4_STATE rc4 = {0};
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    // the key for CE is calculated using the key used to encrypt CD
    ExCryptHmacSha(cd_key, 0x10, hdr->key, sizeof(hdr->key), NULL, 0, NULL, 0, ce_key, sizeof(ce_key));
    ExCryptRc4Key(&rc4, ce_key, sizeof(ce_key));

    // 0x20 = sizeof(bootloader_header), sizeof(hdr->key) - all content after &target_address is encrypted
    ExCryptRc4Ecb(&rc4, (uint8_t *)&hdr->target_address, size_aligned - 0x20);

    // set the key to all 00s so we know it's not encrypted
    memset(hdr->key, 0, sizeof(hdr->key));
}

void ce_calculate_rotsum(uint8_t *ce_data, uint8_t *sha_out) {
    bootloader_ce_header *hdr = (bootloader_ce_header *)ce_data;
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    ExCryptRotSumSha((uint8_t *)hdr, 0x10, (uint8_t *)&hdr->target_address, size_aligned - 0x20, sha_out, 0x14);
}

bool ce_decompress(uint8_t *ce_data, uint8_t *output_buf) {
    bootloader_ce_header *hdr = (bootloader_ce_header *)ce_data;
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    // allocate a buffer to store the compressed output
    uint8_t *compressed_out = malloc(size_aligned);
    memset(compressed_out, 0, size_aligned);
    if (compressed_out == NULL) {
        printf("! error ! failed to allocate compressed output buffer!\n");
        return false;
    }

    uint32_t compressed_size = 0;
    if (!get_full_compressed_buffer((uint8_t *)(hdr + 1), size_aligned, compressed_out,
            BE(hdr->uncompressed_size), &compressed_size)) {
        free(compressed_out);
        return false;
    }

    // decompress the combined compressed input
    int r = lzx_decompress(compressed_out, compressed_size, output_buf, BE(hdr->uncompressed_size), 0x20000, NULL, 0);

    if (r != 0) {
        // newline here since the lzx library doesn't newline
        printf("\n! error ! lzx_decompress returned error code %i\n", r);
        free(compressed_out);
        return false;
    }

    free(compressed_out);

    return true;
}
