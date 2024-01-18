/*
    cd-handler.c - Handling for Xbox 360 CD/4BL bootloader stages.
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

bool cd_is_decrypted(uint8_t *cd_data) {
    bootloader_cd_header *hdr = (bootloader_cd_header *)cd_data;
    // always seen this as 0, no idea what it is
    return (hdr->idk_yet[0] == 0x00);
}

void cd_calculate_rotsum(uint8_t *cd_data, uint8_t *sha_out) {
    bootloader_cd_header *hdr = (bootloader_cd_header *)cd_data;
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    ExCryptRotSumSha((uint8_t *)hdr, 0x10, (uint8_t *)&hdr->idk_yet, size_aligned - 0x120, sha_out, 0x14);
}

void cd_print_info(uint8_t *cd_data) {
    bootloader_cd_header *hdr = (bootloader_cd_header *)cd_data;
    char *indicator = ((BE16(hdr->header.magic) & 0xF000) == 0x5000) ? "SD" : "CD";
    printf("%s version: %i\n", indicator, BE16(hdr->header.version));
    printf("%s size: 0x%x\n", indicator, BE(hdr->header.size));
    printf("%s entrypoint: 0x%x\n", indicator, BE(hdr->header.entrypoint));
    printf("%s cfsalt: %.10s\n", indicator, hdr->cf_salt);
    if (cd_is_decrypted(cd_data)) {
        printf("%s-E hash: ", indicator);
        hexdump(hdr->ce_hash, sizeof(hdr->ce_hash));
    } else {
        printf("%s is encrypted\n", indicator);
    }
}

void cd_decrypt(uint8_t *cd_data, uint8_t *cbb_key, uint8_t *cpu_key) {
    bootloader_cd_header *hdr = (bootloader_cd_header *)cd_data;
    EXCRYPT_RC4_STATE rc4 = {0};
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    // the key is the key used to decrypt CBB
    ExCryptHmacSha(cbb_key, 0x10, hdr->key, sizeof(hdr->key), NULL, 0, NULL, 0, hdr->key, sizeof(hdr->key));

    if (cpu_key != NULL)
        ExCryptHmacSha(cpu_key, 0x10, hdr->key, sizeof(hdr->key), NULL, 0, NULL, 0, hdr->key, sizeof(hdr->key));

    ExCryptRc4Key(&rc4, hdr->key, sizeof(hdr->key));

    // 0x20 = sizeof(bootloader_header), sizeof(hdr->key) - all content after &signature is encrypted
    ExCryptRc4Ecb(&rc4, (uint8_t *)&hdr->signature, size_aligned - 0x20);
}

bool cd_verify_signature_devkit(uint8_t *cd_data, uint8_t *pubkey) {
    bootloader_cd_header *hdr = (bootloader_cd_header *)cd_data;
    uint8_t cd_hash[0x14];
    cd_calculate_rotsum(cd_data, cd_hash);

    BOOL result = ExCryptBnQwBeSigVerify(&hdr->signature, cd_hash, (const uint8_t *)"XBOX_ROM_4", (EXCRYPT_RSA *)pubkey);
    return (result == 1);
}
