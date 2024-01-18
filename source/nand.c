/*
    nand.c - Helper functions for interfacing with NAND images.
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

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "nand-ecc.h"
#include "nand.h"
#include "utility.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

// TODO: if create is set don't do checks
nand_file *open_nand_file(FILE *fp, bool create) {
    // basic sanity check
    if (fp == NULL)
        return NULL;

    // detect the filesize
    fseek(fp, 0, SEEK_END);
    int file_size = ftell(fp);

    // some sort of "sanity check".
    // might get rid of this soon depending on 
    if (file_size < 0x1000000) {
        printf("input nand file too small!\n");
        return NULL;
    }

    // read the header to make sure it's a valid image, and try to figure some things out
    uint8_t page_and_ecc[NAND_PAGE_FULL];
    uint8_t calc_ecc[0x4];
    fseek(fp, 0, SEEK_SET);
    fread(page_and_ecc, 1, NAND_PAGE_FULL, fp);

    xenon_nand_header *hdr = (xenon_nand_header *)page_and_ecc;
    if (BE16(hdr->header.magic) != 0xFF4F) {
        printf("invalid file magic!\n");
        return NULL;
    }

    // as far as i can tell there's no good way to detect
    // this is entirely temporary and a "for the future" thing
    // TODO!
    int nand_type = NAND_TYPE_UNECC;
    if (page_and_ecc[NAND_PAGE_SIZE] == 0xFF)
        nand_type = NAND_TYPE_BIGBLOCK;
    else if (page_and_ecc[NAND_PAGE_SIZE + 0x5] == 0xFF)
        nand_type = NAND_TYPE_SMALLBLOCK;

    calculate_nand_ecc(page_and_ecc, &(page_and_ecc[NAND_PAGE_SIZE]), calc_ecc);
    // calc_ecc should match ecc[0xC]

    nand_file *file_obj = malloc(sizeof(nand_file));
    file_obj->type = nand_type;
    file_obj->fp = fp;
    // both of these are TODOs
    file_obj->console = CONSOLE_UNKNOWN;
    file_obj->size = STORAGE_SIZE_16MB;

    return file_obj;
}

nand_file *open_nand_file_name(char *name, bool create) {
    FILE *fp = fopen(name, "rb"); // TODO: should be wb, and wb+ for create
    if (fp == NULL) {
        printf("failed to open file!\n");
        return NULL;
    }
    nand_file *opened = open_nand_file(fp, create);
    if (opened != NULL)
        opened->close_file = true;
    return opened;
}

void read_nand_data(nand_file *file, uint32_t offset, uint8_t *data, size_t len) {
    if (file == NULL || file->fp == NULL)
        return;

    // for these types, we can just read directly from the file at the offset given
    if (file->type == NAND_TYPE_UNECC ||
        file->type == NAND_TYPE_CORONA) {
        fseek(file->fp, offset, SEEK_SET);
        fread(data, 1, len, file->fp);
        return;
    }

    // otherwise, we have to read each page individually and extract the data
    // TODO: do we want to verify ECC data for the pages read and warn if they're bad?
    //       also bad block handling would be a requirement in the future
    //       the goal is to match what the NAND controller at 0xC8000000 is doing

    // seek to the page we're trying to read
    int page_to_read = (offset / NAND_PAGE_SIZE);
    uint32_t page_file_offset = page_to_read * NAND_PAGE_FULL;
    fseek(file->fp, page_file_offset, SEEK_SET);

    // read whole pages, but only copy the bytes we need
    int num_pages = (len / NAND_PAGE_SIZE) + 1;
    uint32_t bytes_remaining = len;
    uint32_t offset_in_page = (offset % NAND_PAGE_SIZE);
    if (offset_in_page > 0)
        num_pages++;

    for (int i = 0; i < num_pages; i++) {
        // read the whole NAND page including ECC data
        uint8_t page_read[NAND_PAGE_FULL];
        if (fread(page_read, NAND_PAGE_FULL, 1, file->fp) != 1)
            break;
        
        // copy the remaining number of bytes to the output buffer
        int copybytes = MIN(bytes_remaining, NAND_PAGE_SIZE - offset_in_page);
        memcpy(data, page_read + offset_in_page, copybytes);
        bytes_remaining -= copybytes;
        data += copybytes;

        // offset_in_page is solely for the first page read when unaligned
        offset_in_page = 0;
    }
}

void close_nand_file(nand_file *file) {
    if (file == NULL)
        return;
    if (file->close_file)
        fclose(file->fp);
    free(file);
}
