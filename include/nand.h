#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include "xenon-bootloader.h"

#define NAND_PAGE_SIZE 0x200
#define NAND_META_SIZE 0x10
#define NAND_PAGE_FULL (NAND_PAGE_SIZE + NAND_META_SIZE)

#define NAND_KV_VERSION 0x0712

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

typedef enum _nand_type {
    NAND_TYPE_SMALLBLOCK, // Small 16MB/64MB NANDs on pre-Jasper
    NAND_TYPE_SMALLBLOCK_V2, // Small 16MB/64MB NANDs on Jasper and later
    NAND_TYPE_BIGBLOCK, // Large 256MB/512MB NANDs on Jasper
    NAND_TYPE_UNECC, // NAND image lacks ECC data, and isn't Corona
    NAND_TYPE_CORONA, // NAND image is Corona. lolhynix

    NAND_TYPE_UNKNOWN = -1
} nand_type;

typedef enum _storage_size {
    STORAGE_SIZE_16MB,
    STORAGE_SIZE_64MB,
    STORAGE_SIZE_256MB,
    STORAGE_SIZE_512MB,
    STORAGE_SIZE_4GB
} storage_size;

typedef enum _console_type {
    CONSOLE_XENON,
    CONSOLE_ELPIS, // runs 7xxx series bootloaders
    CONSOLE_FALCON,
    CONSOLE_JASPER,
    CONSOLE_TRINITY,
    CONSOLE_CORONA_16MB,
    CONSOLE_CORONA_4GB,
    CONSOLE_WINCHESTER,

    CONSOLE_UNKNOWN = -1
} console_type;

typedef struct _nand_file {
    FILE *fp;
    int type;
    int size;
    int console;
    bool close_file;
} nand_file;

nand_file *open_nand_file(FILE *fp, bool create);
nand_file *open_nand_file_name(char *name, bool create);

void read_nand_data(nand_file *file, uint32_t offset, uint8_t *data, size_t len);

void close_nand_file(nand_file *file);
