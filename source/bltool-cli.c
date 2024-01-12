/*
    bltool-cli.c - The xenon-bltool command line interface.
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "1bl-keys.h"
#include "ce-handler.h"
#include "cg-handler.h"
#include "cf-handler.h"
#include "xenon-bootloader.h"

void hexdump(uint8_t *data, uint32_t size) {
    for (uint32_t i = 0; i < size; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// shitty hack to get a file size
// idk how to do it properly
size_t get_file_size(FILE *fp) {
    fseek(fp, 0, SEEK_END);
    size_t fs = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    return fs;
}

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
    if ((BE16(hdr->magic) & 0xFFF) != 0x345) {
        printf("input file isn't CE/5BL.\n");
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

    // free the original basefile buffer, we don't need the CE anymore
    free(base_buf);

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
    free(decompressed_kernel_buf);

    return 0;
}

int do_xboxupd_command(int argc, char **argv) {
    if (argc < 3) {
        printf("not enough arguments!\n");
        return -1;
    }

    char *xboxupd_path = argv[1];
    char *base_path = argv[2];
    char *output_path = argv[3];

    // open, read and close our base file
    FILE *base_file = fopen(base_path, "rb");
    if (base_file == NULL) {
        printf("couldn't open the base file!\n");
        return -1;
    }
    size_t base_size = get_file_size(base_file);
    void *base_buf = malloc(base_size);
    if (base_buf == NULL) {
        printf("failed to allocate buffer for basefile.\n");
        return -1;
    }
    fread(base_buf, 1, base_size, base_file);
    fclose(base_file);

    // detect the type of the base kernel file
    uint8_t *base_kernel = (uint8_t *)base_buf;
    uint32_t base_kernel_size = base_size;
    bootloader_header *hdr = (bootloader_header *)base_buf;
    if ((BE16(hdr->magic) & 0xFFF) == 0xE4E) {
        printf("base file is raw HV %i with size 0x%x\n", BE16(hdr->version), base_kernel_size);
    } else if ((BE16(hdr->magic) & 0xFFF) == 0x345) {
        bootloader_ce_header *ce_hdr = (bootloader_ce_header *)hdr;
        ce_print_info(base_buf);
        if (!ce_is_decrypted(base_buf)) {
            printf("base CE/5BL file is encrypted.\n");
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

        // free the original basefile buffer, we don't need the CE anymore
        free(base_buf);

        printf("base file is decompressed HV %i\n", BE16(hdr->version));
    } else {
        printf("unknown base file format. (%04x)\n", BE16(hdr->magic));
        free(base_buf);
        return -1;
    }

    // load the xboxupd.bin file
    FILE *xboxupd_file = fopen(xboxupd_path, "rb");
    if (xboxupd_file == NULL) {
        printf("couldn't open the xboxupd.bin file!\n");
        free(base_kernel);
        return -1;
    }
    size_t xboxupd_size = get_file_size(xboxupd_file);
    uint8_t *xboxupd_buf = malloc(xboxupd_size);
    if (xboxupd_buf == NULL) {
        printf("failed to allocate buffer for xboxupd.bin.\n");
        free(base_kernel);
        return -1;
    }
    fread(xboxupd_buf, 1, xboxupd_size, xboxupd_file);
    fclose(xboxupd_file);

    // TODO(Emma): allow just a decrypted CG (or CG with key) without CF

    // make sure we have both the CF and CG stages in the file
    bootloader_cf_header *cf_hdr = (bootloader_cf_header *)xboxupd_buf;
    if ((BE16(cf_hdr->header.magic) & 0xFFF) != 0x346) {
        printf("CF header not found. invalid xboxupd.bin?\n");
        free(base_kernel);
        free(xboxupd_buf);
        return -1;
    }
    // some basic size sanity checking
    if (xboxupd_size < ( BE(cf_hdr->header.size) + BE(cf_hdr->cg_size) )) {
        printf("input xboxupd.bin file too small for CF+CG. invalid file?\n");
        free(base_kernel);
        free(xboxupd_buf);
        return -1;
    }
    // and try to decrypt the CF
    if (!cf_is_decrypted((uint8_t *)cf_hdr)) {
        cf_decrypt((uint8_t *)cf_hdr, key_1bl);
    }
    if (!cf_is_decrypted((uint8_t *)cf_hdr)) {
        printf("failed to decrypt CF\n");
        free(base_kernel);
        free(xboxupd_buf);
        return -1;
    }
    cf_print_info((uint8_t *)cf_hdr);

    if (BE16(cf_hdr->base_ver) != BE16(hdr->version)) {
        printf("mismatching base kernel version %i (CF expects %i)\n", BE16(hdr->version), BE16(cf_hdr->base_ver));
        free(base_kernel);
        free(xboxupd_buf);
        return -1;
    }

    // load the CG as well
    bootloader_cg_header *cg_hdr = (bootloader_cg_header *)(xboxupd_buf + BE(cf_hdr->header.size));
    if ((BE16(cg_hdr->header.magic) & 0xFFF) != 0x347) {
        printf("CG header not found. invalid xboxupd.bin?\n");
        free(base_kernel);
        free(xboxupd_buf);
        return -1;
    }
    // and try to decrypt that, too
    // maybe cg_is_decrypted should be replaced with a rotsum check against CF?
    if (!cg_is_decrypted((uint8_t *)cg_hdr)) {
        cg_decrypt((uint8_t *)cg_hdr, cf_hdr->cg_hmac);
    }
    if (!cg_is_decrypted((uint8_t *)cg_hdr)) {
        printf("failed to decrypt CG\n");
        free(base_kernel);
        free(xboxupd_buf);
        return -1;
    }

    uint8_t cg_rotsum[0x14];
    cg_calculate_rotsum((uint8_t *)cg_hdr, cg_rotsum);
    if (memcmp(cg_rotsum, cf_hdr->cg_hash, 0x14) != 0) {
        printf("CG checksum does not match CF header\n");
        free(base_kernel);
        free(xboxupd_buf);
        return -1;
    }
    cg_print_info((uint8_t *)cg_hdr);

    // patch the kernel
    uint8_t *patched_kernel = malloc(BE(cg_hdr->new_size));
    if (patched_kernel == NULL) {
        printf("failed to allocate memory for new kernel.\n");
        free(base_kernel);
        free(xboxupd_buf);
        return -1;
    }
    if (!cg_apply_patch((uint8_t *)cg_hdr, base_kernel, patched_kernel)) {
        printf("failed to apply the kernel patch.\n");
        free(base_kernel);
        free(xboxupd_buf);
        free(patched_kernel);
        return -1;
    }
    
    // free these now since we won't need them later
    free(base_kernel);
    free(xboxupd_buf);

    // save the file
    printf("writing patched kernel to '%s'...\n", output_path);
    FILE *out_file = fopen(output_path, "wb+");
    if (out_file == NULL) {
        printf("failed to open output file!\n");
        free(patched_kernel);
        return -1;
    }
    fwrite(patched_kernel, 1, BE(cg_hdr->new_size), out_file);
    fclose(out_file);
    free(patched_kernel);

    return 0;
}

typedef int(*command_handler_t)(int argc, char **argv);
typedef struct _command_verb {
    char *verb;
    char *description;
    int required_args;
    char *argument_example;
    command_handler_t handler;
} command_verb;

static const command_verb verbs[] = {
    { "decompress", "Decompresses a CE/SE (5BL) bootloader.", 2, "[path to CE] [output path]", do_decompress_command },
    { "xboxupd", "Applies an xboxupd.bin (CF+CG) patch to a base kernel or CE.", 3, "[path to xboxupd.bin] [path to CE/base] [output_path]", do_xboxupd_command },
};
static const int total_verbs = 2;

int main(int argc, char **argv) {
    printf("xenon-bltool - https://github.com/InvoxiPlayGames/xenon-bltool\n\n");

    if (argc < 2) {
        printf("This program is free software licensed under version 2 of the GNU General\nPublic License. It comes with absolutely NO WARRANTY of any kind.\n\n");
print_usage:
        printf("usage: %s [verb] [arguments]\n\n", argv[0]);
        printf("available verbs:\n");
        for (int i = 0; i < total_verbs; i++) {
            command_verb *verb = &verbs[i];
            printf("    %s - %s\n", verb->verb, verb->description);
            printf("      %s %s %s\n", argv[0], verb->verb, verb->argument_example);
        }
        return -1;
    }

    command_verb *chosen_verb = NULL;
    for (int i = 0; i < total_verbs; i++) {
        if (strcasecmp(verbs[i].verb, argv[1]) == 0)
            chosen_verb = &verbs[i];
    }

    if (chosen_verb == NULL) {
        printf("invalid command!\n");
        goto print_usage;
    }

    // "push along" the argc/argv, so the handlers only get their verb name
    argv++;
    argc--;
    return chosen_verb->handler(argc - 1, argv);
}
