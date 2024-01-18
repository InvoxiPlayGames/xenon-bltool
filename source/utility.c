/*
    utility.c - Utility and helper functions for I/O and such.
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
#include <ctype.h>

void hexdump(uint8_t *data, uint32_t size) {
    for (uint32_t i = 0; i < size; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void dump_to_file(char *filename, uint8_t *buf, size_t size) {
    FILE *fp = fopen(filename, "wb+");
    if (fp == NULL)
        return;
    fwrite(buf, 1, size, fp);
    fclose(fp);
}

bool parse_hex_str(char *str, uint8_t *out_buf, size_t buf_size) {
    // length check - make sure our input is the same size as our buffer is
    if (strlen(str) != (buf_size * 2))
        return false;
    for (int i = 0; i < (buf_size * 2); i += 2) {
        uint8_t nibble_1 = toupper(str[i]);
        uint8_t nibble_2 = toupper(str[i+1]);
        // this feels wrong, do it for the first nibble
        if (nibble_1 >= '0' && nibble_1 <= '9')
            nibble_1 = nibble_1 - '0';
        else if (nibble_1 >= 'A' && nibble_1 <= 'F')
            nibble_1 = nibble_1 - 'A' + 0xA;
        else return false;
        // and then the next...
        if (nibble_2 >= '0' && nibble_2 <= '9')
            nibble_2 = nibble_2 - '0';
        else if (nibble_2 >= 'A' && nibble_2 <= 'F')
            nibble_2 = nibble_2 - 'A' + 0xA;
        else return false;
        // then OR them together
        out_buf[i/2] = (nibble_1 << 4) | nibble_2;
    }
    return true;
}

// shitty hack to get a file size
// idk how to do it properly
size_t get_file_size(FILE *fp) {
    fseek(fp, 0, SEEK_END);
    size_t fs = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    return fs;
}
