/*
    cb-handler.c - Handling for Xbox 360 CB/2BL bootloader stages.
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

bool cb_is_decrypted(uint8_t *cb_data) {
    bootloader_cb_header *hdr = (bootloader_cb_header *)cb_data;
    // this global is the start of a 64-bit address that ignores hrmor
    return (hdr->globals[0x110] == 0x80);
}

void cb_calculate_rotsum(uint8_t *cb_data, uint8_t *sha_out) {
    bootloader_cb_header *hdr = (bootloader_cb_header *)cb_data;
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    ExCryptRotSumSha((uint8_t *)hdr, 0x10, (uint8_t *)&hdr->globals, size_aligned - 0x140, sha_out, 0x14);
}

bool cb_verify_signature(uint8_t *cb_data) {
    bootloader_cb_header *hdr = (bootloader_cb_header *)cb_data;
    uint8_t cb_hash[0x14];
    cb_calculate_rotsum(cb_data, cb_hash);

    BOOL result = ExCryptBnQwBeSigVerify(&hdr->signature, cb_hash, (const uint8_t *)"XBOX_ROM_B", (EXCRYPT_RSA *)rsa_1bl);
    return (result == 1);
}

void cb_print_info(uint8_t *cb_data) {
    bootloader_cb_header *hdr = (bootloader_cb_header *)cb_data;
    char *indicator = ((BE16(hdr->header.magic) & 0xF000) == 0x5000) ? "SB" : "CB";
    // hacky detection for CBA but works, there is no SB_A
    if ((BE16(hdr->header.flags) & 0x800) == 0x800)
        indicator = "CB_A";
    if (hdr->signature.padding[0] == 0)
        indicator = "CB_B";
    printf("%s version: %i\n", indicator, BE16(hdr->header.version));
    printf("%s size: 0x%x\n", indicator, BE(hdr->header.size));
    printf("%s entrypoint: 0x%x\n", indicator, BE(hdr->header.entrypoint));
    if (cb_is_decrypted(cb_data)) {
        printf("%s LDV: %i\n", indicator, hdr->more_globals[1]);
        printf("%s next hash: ", indicator);
        hexdump(hdr->cd_cbb_hash, sizeof(hdr->cd_cbb_hash));
        // detect if we actually have a signature - CB_B doesn't
        if (hdr->signature.padding[0] != 0)
            printf("%s signature: %s\n", indicator, cb_verify_signature(cb_data) ? "signed" : "invalid");
    } else {
        printf("%s is encrypted\n", indicator);
    }
}

void cb_decrypt(uint8_t *cb_data, uint8_t *onebl_key) {
    bootloader_cb_header *hdr = (bootloader_cb_header *)cb_data;
    EXCRYPT_RC4_STATE rc4 = {0};
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    // the key is the key used to decrypt CBA
    ExCryptHmacSha(onebl_key, 0x10, hdr->key, sizeof(hdr->key), NULL, 0, NULL, 0, hdr->key, sizeof(hdr->key));
    ExCryptRc4Key(&rc4, hdr->key, sizeof(hdr->key));

    // 0x20 = sizeof(bootloader_header), sizeof(hdr->key) - all content after &padding_or_args is encrypted
    ExCryptRc4Ecb(&rc4, (uint8_t *)&hdr->padding_or_args, size_aligned - 0x20);
}

void cb_b_decrypt(uint8_t *cb_b_data, uint8_t *cb_a_data, uint8_t *cpu_key) {
    bootloader_cb_header *cb_a_hdr = (bootloader_cb_header *)cb_a_data;
    bootloader_cb_header *cb_b_hdr = (bootloader_cb_header *)cb_b_data;
    EXCRYPT_RC4_STATE rc4 = {0};
    uint32_t size_aligned = BE(cb_b_hdr->header.size) + 0xF & 0xFFFFFFF0;

    // no idea which CB_A started doing this?
    // 9188 doesn't, 6754 and 13182 do
    bootloader_header cb_a_hdr_copy;
    memcpy(&cb_a_hdr_copy, cb_a_data, sizeof(bootloader_header));
    cb_a_hdr_copy.flags = 0;

    // the key is the key used to decrypt CBA
    ExCryptHmacSha(cb_a_hdr->key, 0x10, cb_b_hdr->key, sizeof(cb_b_hdr->key), cpu_key, 0x10, (uint8_t *)&cb_a_hdr_copy, 0x10, cb_b_hdr->key, sizeof(cb_b_hdr->key));
    ExCryptRc4Key(&rc4, cb_b_hdr->key, sizeof(cb_b_hdr->key));

    // 0x20 = sizeof(bootloader_header), sizeof(hdr->key) - all content after &padding_or_args is encrypted
    ExCryptRc4Ecb(&rc4, (uint8_t *)&cb_b_hdr->padding_or_args, size_aligned - 0x20);

    // we don't memset the key to 0, since it's used to decrypt CB_B/CD
    // we do that later
}
