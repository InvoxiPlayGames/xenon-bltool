/*
    command-blupd.c - Xbox 360 bootloader update parsing
    Copyright 2026 Emma https://ipg.gay/

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
#include "1bl-keys.h"
#include "compression-handler.h"
#include "xenon-bootloader.h"
#include "lzx-delta.h"
#include "utility.h"

int do_blupd_command(int argc, char **argv) {
    if (argc < 1) {
        printf("not enough arguments!\n");
        return -1;
    }

    char *blupd_path = argv[1];
    // open, read and close our bootloader file
    FILE *blupd_file = fopen(blupd_path, "rb");
    if (blupd_file == NULL) {
        printf("couldn't open the input file!\n");
        return -1;
    }
    size_t blupd_size = get_file_size(blupd_file);
    void *blupd_buf = malloc(blupd_size);
    if (blupd_buf == NULL) {
        printf("failed to allocate buffer for input file.\n");
        return -1;
    }
    fread(blupd_buf, 1, blupd_size, blupd_file);
    fclose(blupd_file);

    // detect the type of the base kernel file
    bootloader_header *hdr = (bootloader_header *)blupd_buf;
    int bl_type = get_bootloader_type(hdr);

    if (bl_type != XENON_BOOTLOADER_BLUPD)
    {
        printf("not a bootloader update file...\n");
        free(blupd_buf);
        return -1;
    }

    bootloader_update_header *updhdr = (bootloader_update_header *)blupd_buf;

    // decrypt the bootloader update header
    // TODO: move this all into blupd-handler.c
    ExCryptHmacSha(key_1bl, 0x10, updhdr->key, sizeof(updhdr->key), NULL, 0, NULL, 0, updhdr->key, sizeof(updhdr->key));
    EXCRYPT_RC4_STATE rc4 = {0};
    ExCryptRc4Key(&rc4, updhdr->key, sizeof(updhdr->key));
    ExCryptRc4Ecb(&rc4, (uint8_t *)&updhdr->signature, sizeof(EXCRYPT_SIG) + sizeof(bootloader_update_inner));
    bootloader_update_inner *blupd_info = (bootloader_update_inner *)(updhdr + 1);
    uint8_t rotsum[0x14];
    ExCryptRotSumSha((uint8_t *)updhdr, 0x20, (uint8_t *)blupd_info, sizeof(bootloader_update_inner), rotsum, 0x14);
    if (!ExCryptBnQwBeSigVerify(&updhdr->signature, rotsum, "XBOX_BLUPD", (EXCRYPT_RSA *)rsa_1bl))
    {
        printf("signature invalid!\n");
        free(blupd_buf);
        return -1;
    }
    printf("Bootloader update version: %i\n", BE16(updhdr->header.version));
    printf("Bootloader update format: %i\n", BE(updhdr->update_format));
    if (BE(updhdr->update_format) != 2 && BE(updhdr->update_format) != 1)
    {
        printf("unsupported update format!\n");
        free(blupd_buf);
        return -1;
    }

    // decrypt the two inner parts
    uint8_t *table_buf = (uint8_t *)(blupd_info + 1);
    if ((BE(updhdr->part1_size) % sizeof(bootloader_update_tab_entry)) != 0)
    {
        printf("invalid part1 size!\n");
        free(blupd_buf);
        return -1;
    }
    int num_updates = BE(updhdr->part1_size) / sizeof(bootloader_update_tab_entry);
    // allocate a new buffer to store our table
    bootloader_update_tab_entry *table = malloc(num_updates * sizeof(bootloader_update_tab_entry));
    if (table == NULL)
    {
        printf("failed to allocate space for bootloader update table!\n");
        free(blupd_buf);
        return -1;
    }
    memset(table, 0, num_updates * sizeof(bootloader_update_tab_entry));
    // allocate a new buffer to store our compressed blob
    uint8_t *comp_buf = malloc(BE(updhdr->part2_size));
    if (comp_buf == NULL)
    {
        printf("failed to allocate space for compressed update blob!\n");
        free(blupd_buf);
        free(table);
        return -1;
    }
    memset(comp_buf, 0, BE(updhdr->part2_size));
    // TODO: check the flag (0x2) to see whether it should be encrypted, flag (0x1) to see whether it should be compressed
    EXCRYPT_AES_STATE aes = {0};
    uint8_t null_iv[0x10] = {0};
    ExCryptAesKey(&aes, blupd_info->aes_key);
    ExCryptAesCbc(&aes, (uint8_t *)table_buf, BE(updhdr->part1_size), (uint8_t *)table, null_iv, 0);
    ExCryptAesCbc(&aes, (uint8_t *)table_buf + BE(updhdr->part1_size), BE(updhdr->part2_size), comp_buf, null_iv, 0);
    // verify the checksums
    uint8_t part1_sha[0x14] = {0};
    uint8_t part2_sha_compressed[0x14] = {0};
    ExCryptSha((uint8_t *)table, BE(updhdr->part1_size), NULL, 0, NULL, 0, part1_sha, 0x14);
    ExCryptSha(comp_buf, BE(updhdr->part2_size), NULL, 0, NULL, 0, part2_sha_compressed, 0x14);
    if (memcmp(blupd_info->part1_sha, part1_sha, 0x14) != 0)
    {
        printf("invalid part1 hash!\n");
        free(table);
        free(comp_buf);
        free(blupd_buf);
        return -1;
    }
    if (memcmp(blupd_info->part2_sha_compressed, part2_sha_compressed, 0x14) != 0)
    {
        printf("invalid part2 (compressed) hash!\n");
        free(table);
        free(comp_buf);
        free(blupd_buf);
        return -1;
    }
    // print the table out
    printf("Bootloader update table:\n");
    for (int i = 0; i < num_updates; i++)
    {
        bootloader_update_tab_entry *entry = &table[i];
        printf("- PVR 0x%06x, GPU 0x%04x, ANA 0x%02x, UNK1 0x%02x, UNK2 0x%04x\n", BE16(entry->cpu_pvr) << 8, BE16(entry->xenos_id), entry->ana_id, entry->unk1, entry->unk2);
        if (entry->from_cd != 0)
            printf("  upgrades CB (%i -> %i), CD (%i -> %i)\n", BE16(entry->from_cb), BE16(entry->to_cb), BE16(entry->from_cd), BE16(entry->to_cd));
        else if (entry->from_cb != 0)
            printf("  upgrades CB (%i -> %i), CD (%i)\n", BE16(entry->from_cb), BE16(entry->to_cb), BE16(entry->to_cd));
        else if (entry->to_cb != 0 || entry->to_cd != 0)
            printf("  installs CB (%i), CD (%i)\n", BE16(entry->to_cb), BE16(entry->to_cd));
        else
            printf("  no change\n");
    }
    
    // decompress part2
    uint32_t comp_size = BE(updhdr->part2_size) - sizeof(bootloader_compression_header);
    uint32_t full_size = BE(updhdr->part2_decompressed_size);
    uint8_t *scratch = malloc(comp_size);
    uint8_t *bootloaders = malloc(full_size);
    if (scratch == NULL || bootloaders == NULL)
    {
        printf("failed to allocate space for decompressed update blob!\n");
        free(table);
        free(comp_buf);
        free(blupd_buf);
        return -1;
    }
    memset(bootloaders, 0, full_size);
    // combine the compressed blocks into scratch storage
    if (!get_full_compressed_buffer(comp_buf + sizeof(bootloader_compression_header),
        comp_size,
        scratch,
        full_size, &comp_size))
    {
        printf("failed to combine compressed update blob!\n");
        free(table);
        free(comp_buf);
        free(scratch);
        free(blupd_buf);
        return -1;
    }
    // decompress the combined compressed input
    bootloader_compression_header *comphdr = (bootloader_compression_header *)comp_buf;
    int r = lzx_decompress(scratch, comp_size, bootloaders, full_size, BE(comphdr->window_size), NULL, 0);
    if (r != 0) {
        // newline here since the lzx library doesn't newline
        printf("\nlzx_decompress returned error code %i\n", r);
        free(table);
        free(comp_buf);
        free(scratch);
        free(blupd_buf);
        return -1;
    }
    free(scratch);

    if (BE(updhdr->update_format) == 2)
    {
        // scan for CB_A and CD blocks first if we're a new-style update
        uint8_t *cb_a_buffer = NULL;
        int cb_a_size = 0;
        uint8_t *cd_buffer = NULL;
        int cd_size = 0;
        {
            uint8_t *ptr = bootloaders;
            do
            {
                bootloader_header *hdr = (bootloader_header *)ptr;
                if ((BE16(hdr->magic) & 0xFFF) == 0x342 && (BE16(hdr->flags) & 0x800) == 0x800 && BE16(hdr->version) == 0)
                {
                    cb_a_buffer = ptr + sizeof(bootloader_header);
                    cb_a_size = BE(hdr->size);
                }
                if ((BE16(hdr->magic) & 0xFFF) == 0x344 && BE16(hdr->version) == 0)
                {
                    cd_buffer = ptr + sizeof(bootloader_header);
                    cd_size = BE(hdr->size);
                }
                ptr += sizeof(bootloader_header) + BE(hdr->size);
            } while (ptr < bootloaders + full_size);
        }
        if (cb_a_buffer == NULL || cd_buffer == NULL)
        {
            printf("failed to find CB_A or CD in update block!\n");
            free(table);
            free(comp_buf);
            free(blupd_buf);
            free(bootloaders);
            return -1;
        }
        // now actually enumerate through the updates
        {
            uint8_t *ptr = bootloaders;
            do
            {
                bootloader_header *hdr = (bootloader_header *)ptr;
                // CB_A
                if ((BE16(hdr->magic) & 0xFFF) == 0x342 && (BE16(hdr->flags) & 0x800) == 0x800 && BE16(hdr->version) != 0)
                {
                    char out_filename[256];
                    snprintf(out_filename, sizeof(out_filename), "cba_%i.bin", BE16(hdr->version));
                    // copy the CB_A header on top of the full-size CB_A buffer
                    memcpy(cb_a_buffer, hdr + 1, BE(hdr->size));
                    dump_to_file(out_filename, cb_a_buffer, cb_a_size);
                    printf("saved CB_A %i to '%s'\n", BE16(hdr->version), out_filename);
                }
                // CD
                else if ((BE16(hdr->magic) & 0xFFF) == 0x344 && BE16(hdr->version) != 0)
                {
                    char out_filename[256];
                    snprintf(out_filename, sizeof(out_filename), "cd_%i.bin", BE16(hdr->version));
                    // copy the CD header on top of the full-size CD buffer
                    memcpy(cd_buffer, hdr + 1, BE(hdr->size));
                    dump_to_file(out_filename, cd_buffer, cd_size);
                    printf("saved CD %i to '%s'\n", BE16(hdr->version), out_filename);
                }
                // CB_B
                else if ((BE16(hdr->magic) & 0xFFF) == 0x342 && (BE16(hdr->flags) & 0x800) != 0x800 && BE16(hdr->version) != 0)
                {
                    char out_filename[256];
                    snprintf(out_filename, sizeof(out_filename), "cbb_%i.bin", BE16(hdr->version));
                    dump_to_file(out_filename, (uint8_t *)(hdr + 1), BE(hdr->size));
                    printf("saved CB_B %i to '%s'\n", BE16(hdr->version), out_filename);
                }
                ptr += sizeof(bootloader_header) + BE(hdr->size);
            } while (ptr < bootloaders + full_size);
        }
    }
    else if (BE(updhdr->update_format) == 1)
    {
        {
            uint8_t *ptr = bootloaders;
            do
            {
                bootloader_header *hdr = (bootloader_header *)ptr;
                // CB
                if ((BE16(hdr->magic) & 0xFFF) == 0x342)
                {
                    char out_filename[256];
                    snprintf(out_filename, sizeof(out_filename), "cb_%i.bin", BE16(hdr->version));
                    dump_to_file(out_filename, (uint8_t *)(hdr), BE(hdr->size));
                    printf("saved CB %i to '%s'\n", BE16(hdr->version), out_filename);
                }
                // CD
                else if ((BE16(hdr->magic) & 0xFFF) == 0x344)
                {
                    char out_filename[256];
                    snprintf(out_filename, sizeof(out_filename), "cd_%i.bin", BE16(hdr->version));
                    dump_to_file(out_filename, (uint8_t *)(hdr), BE(hdr->size));
                    printf("saved CD %i to '%s'\n", BE16(hdr->version), out_filename);
                }
                ptr += BE(hdr->size);
            } while (ptr < bootloaders + full_size);
        }
    }

    free(table);
    free(comp_buf);
    free(bootloaders);
    free(blupd_buf);

    return 0;
}
