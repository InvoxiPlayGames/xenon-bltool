/*
    cg-handler.c - Handling for Xbox 360 CG/7BL bootloader stages.
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

bool cg_is_decrypted(uint8_t *cg_data) {
    bootloader_cg_header *hdr = (bootloader_cg_header *)cg_data;
    // we make sure the size is page aligned.
    return ((BE(hdr->original_size) & 0xFFF) == 0x000);
}

void cg_print_info(uint8_t *cg_data) {
    bootloader_cg_header *hdr = (bootloader_cg_header *)cg_data;
    char *indicator = ((BE16(hdr->header.magic) & 0xF000) == 0x5000) ? "SG" : "CG";
    printf("%s version: %i\n", indicator, BE16(hdr->header.version));
    printf("%s size: 0x%x\n", indicator, BE(hdr->header.size));
    if (cg_is_decrypted(cg_data)) {
        printf("%s base size: 0x%x\n", indicator, BE(hdr->original_size));
        printf("%s base hash: ", indicator);
        hexdump(hdr->original_hash, sizeof(hdr->original_hash));
        printf("%s target size: 0x%x\n", indicator, BE(hdr->new_size));
        printf("%s target hash: ", indicator);
        hexdump(hdr->new_hash, sizeof(hdr->new_hash));
    } else {
        printf("%s is encrypted\n", indicator);
    }
}

void cg_decrypt(uint8_t *cg_data, uint8_t *cg_hmac) {
    bootloader_cg_header *hdr = (bootloader_cg_header *)cg_data;
    uint8_t cg_key[0x10];
    EXCRYPT_RC4_STATE rc4 = {0};
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    // key to decrypt is contained in the CF
    ExCryptHmacSha(cg_hmac, 0x10, hdr->key, sizeof(hdr->key), NULL, 0, NULL, 0, cg_key, sizeof(cg_key));
    ExCryptRc4Key(&rc4, cg_key, sizeof(cg_key));

    // 0x20 = sizeof(bootloader_header), sizeof(hdr->key) - all content after &original_size is encrypted
    ExCryptRc4Ecb(&rc4, (uint8_t *)&hdr->original_size, size_aligned - 0x20);
}

void cg_calculate_rotsum(uint8_t *cg_data, uint8_t *sha_out) {
    bootloader_cg_header *hdr = (bootloader_cg_header *)cg_data;
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    ExCryptRotSumSha((uint8_t *)hdr, 0x10, (uint8_t *)&hdr->original_size, size_aligned - 0x20, sha_out, 0x14);
}

bool cg_apply_patch(uint8_t *cg_data, uint8_t *base_data, uint8_t *output_buf) {
    bootloader_cg_header *hdr = (bootloader_cg_header *)cg_data;
    uint32_t size_of_compressed = BE(hdr->header.size) - sizeof(bootloader_cg_header);

    // validate the integrity of the base kernel
    uint8_t base_kernel_hash[0x14];
    ExCryptSha(base_data, BE(hdr->original_size), NULL, 0, NULL, 0, base_kernel_hash, sizeof(base_kernel_hash));
    if (memcmp(base_kernel_hash, hdr->original_hash, 0x14) != 0) {
        printf("! error ! base kernel hash did not match expected.\n");
        return false;
    }

    // copy the base kernel's data to the output buffer and then decompress into it
    memcpy(output_buf, base_data, BE(hdr->original_size));
    int r = lzxdelta_apply_patch((bootloader_delta_block *)(hdr + 1), size_of_compressed, 0x8000, output_buf);

    if (r != 0) {
        // newline here since the lzx library doesn't newline
        printf("\n! error ! lzxdelta_apply_patch returned error code %i\n", r);
        return false;
    }

    // verify the hash of the resulting kernel
    uint8_t updated_kernel_hash[0x14];
    ExCryptSha(output_buf, BE(hdr->new_size), NULL, 0, NULL, 0, updated_kernel_hash, sizeof(updated_kernel_hash));
    if (memcmp(updated_kernel_hash, hdr->new_hash, 0x14) != 0) {
        printf("! error ! updated kernel hash did not match expected.\n");
        return false;
    }

    return true;
}
