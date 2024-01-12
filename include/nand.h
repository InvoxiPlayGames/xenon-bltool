#include <stdint.h>
#include "xenon-bootloader.h"

typedef struct _xenon_nand_header {
    bootloader_header header; // entrypoint leads to CB
    char copyright[0x40];
    uint8_t unused[0x10];
    uint32_t kv_size;
    uint32_t cf_offset;
    int16_t patch_slots;
    uint16_t kv_version;
    uint32_t kv_addr;
    uint32_t patch_size;
    uint32_t smc_config_offset;
    uint32_t smc_boot_size;
    uint32_t smc_boot_offset;
} xenon_nand_header;
