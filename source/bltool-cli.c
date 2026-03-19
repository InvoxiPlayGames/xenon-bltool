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
#include <ctype.h>
#include <string.h>
#include "commands.h"

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
    { "nand_extract", "Extracts CB, CB_B and CD stages from a NAND image. (UNFINISHED!)", 2, "[path to nand.bin] [cpu key]", do_nand_extract_command },
    { "compress", "Compresds a CE/SE (5BL) bootloader.", 2, "[decompressed CE] [compressed CE]", do_compress_command },
};
int total_verbs = sizeof(verbs) / sizeof(verbs[0]);

int main(int argc, char **argv) {
    printf("xenon-bltool - https://github.com/InvoxiPlayGames/xenon-bltool\n\n");

    if (argc < 2) {
        printf("This program is free software licensed under version 2 of the GNU General\nPublic License. It comes with absolutely NO WARRANTY of any kind.\n\n");
print_usage:
        printf("usage: %s [verb] [arguments]\n\n", argv[0]);
        printf("available verbs:\n");
        for (int i = 0; i < total_verbs; i++) {
            const command_verb *verb = &verbs[i];
            printf("    %s - %s\n", verb->verb, verb->description);
            printf("      %s %s %s\n", argv[0], verb->verb, verb->argument_example);
        }
        return -1;
    }

    const command_verb *chosen_verb = NULL;
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
