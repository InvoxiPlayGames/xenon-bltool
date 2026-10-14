/*
    command-nand_extract.c - Extracting bootloader stages from Xbox 360 NAND images.
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

/*
    Note for 18th January 2024: This is unfinished code! It's not accessible in
    bltool-cli. It'll only read one of a certain type of image, because the way
    CB_B/CD is decrypted can vary in certain versions, and devkit / zeropair /
    RGH3 put some more spanners in the works. It'll need a full rewrite with all
    that in mind for it to truly "work".

    Sorry if this ever ends up remaining unfinished forever, just putting it
    out there unfinished so it doesn't go to waste! -Emma
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "1bl-keys.h"
#include "xenon-bootloader.h"
#include "nand.h"
#include "utility.h"
#include "cb-handler.h"
#include "cd-handler.h"
#include "ce-handler.h"
#include "cf-handler.h"
#include "cg-handler.h"

typedef struct _loaded_bl_stage {
    int stage;
    bootloader_header header;
    uint8_t *buffer;
} loaded_bl_stage;

int do_nand_extract_command(int argc, char **argv) {
    if (argc < 1) {
        printf("not enough arguments!\n");
        return -1;
    }

    char *nand_path = argv[1];
    nand_file *nand = open_nand_file_name(nand_path, false);
    if (nand == NULL) {
        printf("couldn't open the nand file!\n");
        return -1;
    }

    uint8_t cpu_key[0x10] = {0};
    bool has_cpu_key = false;
    if (argc < 2) {
        printf("no cpu key provided! stages will not be decrypted\n");
    } else {
        if (!parse_hex_str(argv[2], cpu_key, sizeof(cpu_key)))
            printf("failed to parse CPU key!\n");
        else {
            has_cpu_key = true;
            printf("cpu key: ");
            hexdump(cpu_key, sizeof(cpu_key));
        }
    }

    // read metadata from header
    xenon_nand_header nand_header = {0};
    read_nand_data(nand, 0x0, (uint8_t *)&nand_header, sizeof(xenon_nand_header));
    // TODO: do we want to verify this?

    // some info
    printf("CB offset: 0x%x\n", BE(nand_header.header.entrypoint));
    printf("CF offset: 0x%x\n", BE(nand_header.cf_offset));
    printf("\n");

    loaded_bl_stage loaded_stages[10];
    int num_loaded_stages = 0;
    bootloader_header bl_hdr = {0}; // scratch buffer for next stages

    /*
    // we're starting at the CB entrypoint and enumerating until CE
    uint32_t next_stage_start = BE(nand_header.header.entrypoint);
    for (int i = 0; i < 10; i++) {
        // read the bootloader's header from the next stage address
        read_nand_data(nand, next_stage_start, (uint8_t *)&bl_hdr, sizeof(bootloader_header));
        int bl_type = get_bootloader_type(&bl_hdr);
        
        // TODO: FINISH THIS

        // the next stage will start right after this one
        next_stage_start += (BE(bl_hdr.size) + 0xF & 0xFFFFFFF0);
    }
    */

    // get the size of CB and load it all
    uint32_t cb_start = BE(nand_header.header.entrypoint);
    read_nand_data(nand, cb_start, (uint8_t *)&bl_hdr, sizeof(bootloader_header));
    if (BE(bl_hdr.size) > 0x10000) {
        printf("CB size is too big to be sane\n");
        return -1;
    }
    uint8_t *cb_buf = malloc(BE(bl_hdr.size));
    if (cb_buf == NULL) {
        printf("failed to allocate buffer for CB\n");
        return -1;
    }
    read_nand_data(nand, cb_start, cb_buf, BE(bl_hdr.size));

    bootloader_cb_header *cb_hdr = (bootloader_cb_header *)cb_buf;
    if (!cb_is_decrypted(cb_buf))
        cb_decrypt(cb_buf, key_1bl);
    cb_print_info(cb_buf);

    dump_to_file("extracted_2bl.bin", cb_buf, BE(bl_hdr.size));

    // the next stage starts right after the first - repeats until 5BL/CE
    uint32_t next_stage_start = cb_start + (BE(bl_hdr.size) + 0xF & 0xFFFFFFF0);

    bool has_cb_b = false;
    // detect CB_A and handle next stage as CB_B
    if ((BE16(bl_hdr.flags) & 0x800) == 0x800) {
        // read the header to get the size
        read_nand_data(nand, next_stage_start, (uint8_t *)&bl_hdr, sizeof(bootloader_header));

        uint8_t *cb_b_buf = malloc(BE(bl_hdr.size));
        if (cb_b_buf == NULL) {
            printf("failed to allocate buffer for CB_B\n");
            return -1;
        }
        read_nand_data(nand, next_stage_start, cb_b_buf, BE(bl_hdr.size));

        if (!cb_is_decrypted(cb_b_buf) && has_cpu_key)
            cb_b_decrypt_v2(cb_b_buf, cb_buf, cpu_key);

        cb_print_info(cb_b_buf);

        // validate the rotsumsha
        uint8_t cb_b_sha[0x14];
        cb_calculate_rotsum(cb_b_buf, cb_b_sha);
        if (memcmp(cb_b_sha, cb_hdr->cd_cbb_hash, 0x14) != 0)
            printf("! CB_B does not match RotSumSha in CB_A !\n");

        dump_to_file("extracted_2bl_b.bin", cb_b_buf, BE(bl_hdr.size));

        has_cb_b = true;

        // the CB_B's buffer is what we'll be caring about in the future
        cb_hdr = (bootloader_cb_header *)cb_b_buf;
        next_stage_start += (BE(bl_hdr.size) + 0xF & 0xFFFFFFF0);
    }

    // read the header to get the size
    read_nand_data(nand, next_stage_start, (uint8_t *)&bl_hdr, sizeof(bootloader_header));

    // we have to read SC to get the key for SD, if we have an SC
    bootloader_generic_header sc_hdr = {0};
    bool has_sc = false;
    if ((BE16(bl_hdr.magic)) == 0x5343) {
        has_sc = true;

        // read just the header (we store the key here for later)
        read_nand_data(nand, next_stage_start, (uint8_t *)&sc_hdr, sizeof(bootloader_generic_header));
        printf("SC version: %i\n", BE16(sc_hdr.header.version));
        printf("SC size: 0x%x\n", BE(sc_hdr.header.size));

        uint8_t *sc_buf = malloc(BE(sc_hdr.header.size));
        if (sc_buf == NULL) {
            printf("failed to allocate buffer for SC\n");
            return -1;
        }
        read_nand_data(nand, next_stage_start, sc_buf, BE(sc_hdr.header.size));

        if (cb_is_decrypted(cb_buf))
        {
            xke_sc_decrypt(sc_buf, cb_hdr->sc_key);
            if (xke_sc_verify_signature(sc_buf, cb_hdr->sc_salt, (uint8_t *)&cb_hdr->devkit_pubkey))
                printf("SC signature: signed\n");
            else
                printf("SC signature: unsigned\n");
            memcpy(sc_hdr.key, sc_buf + 0x10, 0x10);//could be prettier...
            dump_to_file("extracted_3bl.bin", sc_buf, BE(sc_hdr.header.size));
        }

        free(sc_buf);

        // read in the SD
        next_stage_start += (BE(bl_hdr.size) + 0xF & 0xFFFFFFF0);
        read_nand_data(nand, next_stage_start, (uint8_t *)&bl_hdr, sizeof(bootloader_header));
    }
    
    uint8_t *cd_buf = malloc(BE(bl_hdr.size));
    if (cd_buf == NULL) {
        printf("failed to allocate buffer for CD\n");
        return -1;
    }
    memset(cd_buf, 0, BE(bl_hdr.size));
    read_nand_data(nand, next_stage_start, cd_buf, BE(bl_hdr.size));

    bootloader_cd_header *cd_hdr = (bootloader_cd_header *)cd_buf;

    if (!cd_is_decrypted(cd_buf) && (has_cpu_key || has_sc))
        cd_decrypt(cd_buf, has_sc ? sc_hdr.key : cb_hdr->key, (has_cb_b || has_sc) ? NULL : cpu_key);

    cd_print_info(cd_buf);

    if (cd_is_decrypted(cd_buf))
    {
        // validate the rotsumsha
        if (!(BE16(cd_hdr->header.magic) & 0x1000))
        {
            uint8_t cd_sha[0x14];
            cd_calculate_rotsum(cd_buf, cd_sha);
            if (memcmp(cd_sha, cb_hdr->cd_cbb_hash, 0x14) != 0)
                printf("! CD does not match RotSumSha in CB !\n");
        }
        else // devkits use RSA for 4BL
        {
            if (cd_verify_signature_devkit(cd_buf, (uint8_t *)&cb_hdr->devkit_pubkey))
                printf("SD signature: signed\n");
            else
                printf("SD signature: invalid\n");
        }

    }

    dump_to_file("extracted_4bl.bin", cd_buf, BE(bl_hdr.size));

    // read in CE
    next_stage_start += (BE(bl_hdr.size) + 0xF & 0xFFFFFFF0);
    read_nand_data(nand, next_stage_start, (uint8_t *)&bl_hdr, sizeof(bootloader_header));
    
    uint8_t *ce_buf = malloc(BE(bl_hdr.size));
    if (ce_buf == NULL) {
        printf("failed to allocate buffer for CE\n");
        return -1;
    }
    memset(ce_buf, 0, BE(bl_hdr.size));
    read_nand_data(nand, next_stage_start, ce_buf, BE(bl_hdr.size));

    bootloader_ce_header *ce_hdr = (bootloader_ce_header *)ce_buf;
    if (!ce_is_decrypted(ce_buf))
        ce_decrypt(ce_buf, cd_hdr->key);
    ce_print_info(ce_buf);

    dump_to_file("extracted_5bl.bin", ce_buf, BE(bl_hdr.size));

    free(cb_buf);
    free(cd_buf);
    free(ce_buf);

    close_nand_file(nand);
    return 0;
}
