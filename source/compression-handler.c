/*
    compression-handler.c - Utility file for working with compressed Xbox 360 bootloaders.
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
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "xenon-bootloader.h"

/*
    Our lzx_decompress from memory function (taken from Xenia) requires a
    contiguous buffer of compressed data. CE/SE and the extender bootloader blob
    are both compressed in a way that defines the compressed block size and
    decompressed block size (almost always 0x8000).
    This function takes those compressed blocks and puts them all together.
*/
bool get_full_compressed_buffer(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t decompressed_size, uint32_t *compressed_size) {
    uint32_t decompressed_size_parsed = 0;
    uint32_t compressed_size_parsed = 0;

    // loop until we've parsed enough blocks to match the compressed size
    while (decompressed_size_parsed < decompressed_size) {
        bootloader_compression_block *block = (bootloader_compression_block *)in_buf;

        // update the amount of data we've parsed
        decompressed_size_parsed += BE16(block->decompressed_size);
        compressed_size_parsed += BE16(block->compressed_size);

        // some sanity check to make sure we aren't going to overflow or anything
        if (compressed_size_parsed >= in_size) {
            printf("! error ! compressed size larger than output size\n");
            return false;
        }
        memcpy(out_buf, (uint8_t *)(block + 1), BE16(block->compressed_size));

        // progress the input and output buffers
        in_buf += sizeof(bootloader_compression_block) + BE16(block->compressed_size);
        out_buf += BE16(block->compressed_size);
    }

    // make sure we've got the expected amount of decompressed data
    if (decompressed_size_parsed > decompressed_size) {
        printf("! error ! decompressed size larger than expected\n");
        return false;
    }

    if (compressed_size != NULL)
        *compressed_size = compressed_size_parsed;

    return true;
}