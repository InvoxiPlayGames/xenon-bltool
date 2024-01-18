/*
    cf-handler.c - Handling for Xbox 360 CF/6BL bootloader stages.
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
#include "1bl-keys.h"
#include "utility.h"
#include "excrypt.h"
#include "xenon-bootloader.h"

bool cf_is_decrypted(uint8_t *cf_data) {
    bootloader_cf_header *hdr = (bootloader_cf_header *)cf_data;
    // this might be a naive assumption, but i think this is always all zeros.
    return (hdr->pairing[0] == 0x00);
}

void cf_calculate_rotsum(uint8_t *cf_data, uint8_t *sha_out) {
    bootloader_cf_header *hdr = (bootloader_cf_header *)cf_data;
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    ExCryptRotSumSha((uint8_t *)hdr, 0x20, (uint8_t *)&hdr->cg_hmac, size_aligned - 0x330, sha_out, 0x14);
}

bool cf_verify_signature(uint8_t *cf_data) {
    bootloader_cf_header *hdr = (bootloader_cf_header *)cf_data;
    uint8_t cf_hash[0x14];
    cf_calculate_rotsum(cf_data, cf_hash);

    BOOL result = ExCryptBnQwBeSigVerify(&hdr->signature, cf_hash, (const uint8_t *)"XBOX_ROM_6", (EXCRYPT_RSA *)rsa_1bl);
    return (result == 1);
}

void cf_print_info(uint8_t *cf_data) {
    bootloader_cf_header *hdr = (bootloader_cf_header *)cf_data;
    char *indicator = ((BE16(hdr->header.magic) & 0xF000) == 0x5000) ? "SF" : "CF";
    printf("%s version: %i\n", indicator, BE16(hdr->header.version));
    printf("%s size: 0x%x\n", indicator, BE(hdr->header.size));
    printf("%s entrypoint: 0x%x\n", indicator, BE(hdr->header.entrypoint));
    printf("%s base version: %i\n", indicator, BE16(hdr->base_ver));
    printf("%s target version: %i\n", indicator, BE16(hdr->target_ver));
    printf("%s-G size: 0x%x\n", indicator, BE(hdr->cg_size));
    if (cf_is_decrypted(cf_data)) {
        printf("%s-G key: ", indicator);
        hexdump(hdr->cg_hmac, sizeof(hdr->cg_hmac));
        printf("%s-G checksum: ", indicator);
        hexdump(hdr->cg_hash, sizeof(hdr->cg_hash));
        printf("%s signature: %s\n", indicator, cf_verify_signature(cf_data) ? "signed" : "invalid");
    } else {
        printf("%s is encrypted\n", indicator);
    }
}

void cf_decrypt(uint8_t *cf_data, uint8_t *onebl_key) {
    bootloader_cf_header *hdr = (bootloader_cf_header *)cf_data;
    uint8_t cf_key[0x10];
    EXCRYPT_RC4_STATE rc4 = {0};
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    // the key is the 1bl key
    ExCryptHmacSha(onebl_key, 0x10, hdr->key, sizeof(hdr->key), NULL, 0, NULL, 0, cf_key, sizeof(cf_key));
    ExCryptRc4Key(&rc4, cf_key, sizeof(cf_key));

    // 0x30 = sizeof(bootloader_header), sizeof(hdr->key), and the version info - all content after &pairing is encrypted
    ExCryptRc4Ecb(&rc4, (uint8_t *)&hdr->pairing, size_aligned - 0x30);
}
