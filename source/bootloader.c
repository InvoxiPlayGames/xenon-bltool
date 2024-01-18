/*
    bootloader.c - General utility functions for all 360 bootloader types.
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

#include <stdbool.h>
#include <stdint.h>
#include "utility.h"
#include "xenon-bootloader.h"

int get_bootloader_type(bootloader_header *bl)
{
    uint16_t bl_magic = BE16(bl->magic);

    // these bootloader types all use first nibble as retail/devkit designation
    switch (bl_magic & 0xFFF) {
        // boot stages
        case 0x341:
            return XENON_BOOTLOADER_1BL;
        case 0x342:
            return XENON_BOOTLOADER_CB;
        case 0x343:
            return XENON_BOOTLOADER_SC;
        case 0x344:
            return XENON_BOOTLOADER_CD;
        case 0x345:
            return XENON_BOOTLOADER_CE;
        case 0x346:
            return XENON_BOOTLOADER_CF;
        case 0x347:
            return XENON_BOOTLOADER_CG;
        // other bl-esque payloads
        case 0xD4D:
            return XENON_BOOTLOADER_XKE;
        case 0xE4E:
            return XENON_BOOTLOADER_HV;
    }

    // fixed magic regardless of devkit or retail
    if (bl_magic == 0xEC4C)
        return XENON_BOOTLOADER_BLUPD;

    // no idea
    return XENON_BOOTLOADER_INVALID;
}

bool is_bootloader_devkit(bootloader_header *bl)
{
    uint16_t bl_magic = BE16(bl->magic);
    return ((bl_magic & 0x1000) == 0x1000);
}

void xke_sc_calculate_rotsum(uint8_t *bl_data, uint8_t *sha_out) {
    bootloader_generic_header *hdr = (bootloader_generic_header *)bl_data;
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    ExCryptRotSumSha((uint8_t *)hdr, 0x10, (uint8_t *)(hdr + 1), size_aligned - sizeof(bootloader_generic_header), sha_out, 0x14);
}

bool xke_sc_verify_signature(uint8_t *bl_data, char *salt, uint8_t *pubkey) {
    bootloader_generic_header *hdr = (bootloader_generic_header *)bl_data;
    uint8_t bl_hash[0x14];
    xke_sc_calculate_rotsum(bl_data, bl_hash);

    BOOL result = ExCryptBnQwBeSigVerify(&hdr->signature, bl_hash, salt, (EXCRYPT_RSA *)pubkey);
    return (result == 1);
}

void xke_sc_decrypt(uint8_t *bl_data, uint8_t *dec_key) {
    bootloader_generic_header *hdr = (bootloader_generic_header *)bl_data;
    EXCRYPT_RC4_STATE rc4 = {0};
    uint32_t size_aligned = BE(hdr->header.size) + 0xF & 0xFFFFFFF0;

    // dec_key is either the header from SB for SC or the 1BL key for XKE payloads
    ExCryptHmacSha(dec_key, 0x10, hdr->key, sizeof(hdr->key), NULL, 0, NULL, 0, hdr->key, sizeof(hdr->key));
    ExCryptRc4Key(&rc4, hdr->key, sizeof(hdr->key));

    // 0x20 = sizeof(bootloader_header), sizeof(hdr->key) - all content after &padding_or_args is encrypted
    ExCryptRc4Ecb(&rc4, (uint8_t *)(hdr + 1), size_aligned - sizeof(bootloader_generic_header));
}
