#ifndef XENON_BOOTLOADER_H_
#define XENON_BOOTLOADER_H_

#include <stdint.h>
#include "excrypt.h"

typedef enum _xenon_bl_type {
    XENON_BOOTLOADER_1BL,
    XENON_BOOTLOADER_CB,
    XENON_BOOTLOADER_SC,
    XENON_BOOTLOADER_CD,
    XENON_BOOTLOADER_CE,
    XENON_BOOTLOADER_CF,
    XENON_BOOTLOADER_CG,

    // not bootloaders but same structure
    XENON_BOOTLOADER_HV = 0x10,
    XENON_BOOTLOADER_XKE,
    XENON_BOOTLOADER_BLUPD,

    XENON_BOOTLOADER_INVALID = -1
} xenon_bl_type;

typedef struct _onebl_globals {
    EXCRYPT_RSAPUB_2048 ms_pubkey;
    uint64_t addr_post;
    uint64_t addr_61008; // what periph is this
    uint64_t addr_pcie;
    uint64_t addr_e1000000; // what is this too
    uint64_t addr_nand;
    uint64_t addr_base;
    uint64_t addr_sram;
    uint8_t onebl_key[0x10];
    char cb_salt[10];
} onebl_globals;

typedef struct _bootloader_header {
    uint16_t magic;
    uint16_t version;
    uint16_t pairing;
    uint16_t flags;
    uint32_t entrypoint;
    uint32_t size;
} bootloader_header;

typedef struct _bootloader_1bl_header {
    bootloader_header header;
    char copyright[0x80];
    uint8_t padding[0x6C];
    uint32_t globals_addr;
} bootloader_1bl_header;

// used by SC/3BL, XKE, etc
typedef struct _bootloader_generic_header {
    bootloader_header header;
    uint8_t key[0x10];
    EXCRYPT_SIG signature;
} bootloader_generic_header;

typedef struct _bootloader_cb_header {
    bootloader_header header;
    uint8_t key[0x10];
    uint64_t padding_or_args[4];
    EXCRYPT_SIG signature;
    uint8_t globals[0x25C]; // find out whats in here...
    uint8_t cd_cbb_hash[0x14]; // CB_A has CB_B hash, CB_B has CD hash
    uint8_t more_globals[0x10]; // and here as well...
} bootloader_cb_header;

typedef struct _bootloader_cd_header {
    bootloader_header header;
    uint8_t key[0x10];
    uint8_t idk_yet[0x220]; // possibly unused?
    char cf_salt[10];
    uint16_t unused;
    uint8_t ce_hash[0x14];
} bootloader_cd_header;

typedef struct _bootloader_ce_header {
    bootloader_header header;
    uint8_t key[0x10];
    uint64_t target_address;
    uint32_t uncompressed_size;
    uint32_t unknown; // think this is unused
} bootloader_ce_header;

typedef struct _bootloader_cf_header {
    bootloader_header header;
    uint16_t base_ver;
    uint16_t base_flags; // unsure
    uint16_t target_ver;
    uint16_t target_flags; // unsure
    uint32_t unknown; // think this is unused
    uint32_t cg_size;
    uint8_t key[0x10];
    uint8_t pairing[0x200];
    EXCRYPT_SIG signature;
    uint8_t cg_hmac[0x10];
    uint8_t cg_hash[0x14];
} bootloader_cf_header;

typedef struct _bootloader_cg_header {
    bootloader_header header;
    uint8_t key[0x10];
    uint32_t original_size;
    uint8_t original_hash[0x14];
    uint32_t new_size;
    uint8_t new_hash[0x14];
} bootloader_cg_header;

typedef struct _bootloader_update_header {
    bootloader_header header;
    uint32_t update_format;
    uint32_t part2_size;
    uint32_t part1_size;
    uint32_t part2_decompressed_size;
    uint8_t key[0x10];
    EXCRYPT_SIG signature;
} bootloader_update_header;

typedef struct _bootloader_update_inner {
    uint8_t aes_key[0x10];
    uint32_t some_flags; // unsure?
    uint8_t part2_sha_compressed[0x14];
    uint8_t part1_sha[0x14];
    uint8_t part2_sha[0x14];
} bootloader_update_inner;

typedef struct _bootloader_compression_header {
    uint32_t window_size;
    uint32_t block_size;
    uint32_t compressed_size;
    uint32_t decompressed_size;
} bootloader_compression_header;

typedef struct _bootloader_compression_block {
    uint16_t compressed_size;
    uint16_t decompressed_size;
} bootloader_compression_block;

typedef struct _bootloader_delta_block {
    uint32_t old_addr;
    uint32_t new_addr;
    uint16_t decompressed_size;
    uint16_t compressed_size;
} bootloader_delta_block;

#endif
