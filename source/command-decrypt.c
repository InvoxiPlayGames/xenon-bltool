/*
    command-decrypt.c - Xbox 360 generic bootloader decryption
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
#include "xenon-bootloader.h"
#include "utility.h"

int do_decrypt_command(int argc, char **argv) {
    if (argc < 2) {
        printf("not enough arguments!\n");
        return -1;
    }

    char *bl_path = argv[1];
    char *output_path = argv[2];
    // TODO: argument to provide either a chain of encrypted stages to derive the key
    //       or just providing a root key

    // open, read and close our bootloader file
    FILE *bl_file = fopen(bl_path, "rb");
    if (bl_file == NULL) {
        printf("couldn't open the input file!\n");
        return -1;
    }
    size_t bl_size = get_file_size(bl_file);
    void *bl_buf = malloc(bl_size);
    if (bl_buf == NULL) {
        printf("failed to allocate buffer for input file.\n");
        return -1;
    }
    fread(bl_buf, 1, bl_size, bl_file);
    fclose(bl_file);

    // detect the type of the bootloader file
    bootloader_header *hdr = (bootloader_header *)bl_buf;
    int bl_type = get_bootloader_type(hdr);

    switch (bl_type)
    {
        case XENON_BOOTLOADER_XKE:
            {
                xke_sc_decrypt(bl_buf, key_1bl);
                if (!xke_sc_verify_signature(bl_buf, "XBOX_EX_01", rsa_1bl))
                {
                    printf("! warning ! signature is invalid, maybe it didn't decrypt properly?\n");
                }
                else
                {
                    printf("decrypted successfully!\n");
                }
            }
            break;
        default:
            printf("input file isn't supported by this command\n");
            free(bl_buf);
            return -1;
    }

    // save the file
    printf("writing decrypted stage to '%s'...\n", output_path);
    FILE *out_file = fopen(output_path, "wb+");
    if (out_file == NULL) {
        printf("failed to open output file!\n");
        free(bl_buf);
        return -1;
    }
    fwrite(bl_buf, 1, bl_size, out_file);
    fclose(out_file);
    free(bl_buf);

    return 0;
}
