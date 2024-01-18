#include <stdint.h>
#include "utility.h"

// Reference:
// - https://github.com/Free60Project/libxenon/blob/master/libxenon/drivers/xenon_nand/xenon_sfcx.c
// - https://free60.org/System-Software/NAND_File_System/

void calculate_nand_ecc(uint8_t page[0x200], uint8_t spare[0x10], uint8_t ecc[0x4]) {
    uint32_t v = 0, val = 0;
    uint32_t *data = (uint32_t *)page;

    for (int i = 0; i < 0x1066; i++) {
        if (i == 0x1000)
            data = (uint32_t *)spare;
        if (!(i & 31))
            v = ~LE(*data++);

       val ^= v & 1;
       v>>=1;
       if (val & 1)
           val ^= 0x6954559;
        val >>= 1;
    }
    val = ~val;

    ecc[0] = (val << 6) & 0xC0;
    ecc[1] = (val >> 2) & 0xFF;
    ecc[2] = (val >> 10) & 0xFF;
    ecc[3] = (val >> 18) & 0xFF;
}
