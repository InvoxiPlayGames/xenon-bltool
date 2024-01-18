// Reference: https://free60.org/System-Software/NAND_File_System/
// these all need checking before i want to rely on using them for anything
#include <stdint.h>

// ECC spare data used on 1st gen NAND controllers
typedef struct _ecc_data_v1 {
    // uint16_t block_id : 12;
    uint8_t block_id_1;
    uint8_t block_id_0 : 4;

    uint8_t fs_unused : 4;
    uint8_t fs_sequence_0;
    uint8_t fs_sequence_1;
    uint8_t fs_sequence_2;
    uint8_t bad_block;
    uint8_t fs_sequence_3;

    // uint16_t fs_size;
    uint8_t fs_size_1;
    uint8_t fs_size_0;

    uint8_t fs_page_count;
    uint8_t fs_unused_2[2];
    uint8_t fs_block_type : 6;

    // 14-bit ECC data
    uint8_t ecc3 : 2;
    uint8_t ecc2;
    uint8_t ecc1;
    uint8_t ecc0;
} ecc_data_v1;

// ECC spare data used on 2nd gen NAND controllers (16/64MB)
typedef struct _ecc_data_v2_sb {
    uint8_t fs_sequence_0;

    // uint16_t block_id : 12;
    uint8_t block_id_1;
    uint8_t block_id_0 : 4;

    uint8_t fs_unused : 4;
    uint8_t fs_sequence_1;
    uint8_t fs_sequence_2;
    uint8_t bad_block;
    uint8_t fs_sequence_3;

    // uint16_t fs_size;
    uint8_t fs_size_1;
    uint8_t fs_size_0;

    uint8_t fs_page_count;
    uint8_t fs_unused_2[2];
    uint8_t fs_block_type : 6;

    // 14-bit ECC data
    uint8_t ecc3 : 2;
    uint8_t ecc2;
    uint8_t ecc1;
    uint8_t ecc0;
} ecc_data_v2_sb;

// ECC spare data used on 2nd gen NAND controllers (256/512MB)
typedef struct _ecc_data_v2_bb {
    uint8_t bad_block;
    
    // uint16_t block_id : 12;
    uint8_t block_id_1;
    uint8_t block_id_0 : 4;

    uint8_t fs_unused : 4;
    uint8_t fs_sequence_2;
    uint8_t fs_sequence_1;
    uint8_t fs_sequence_0;
    uint8_t fs_unused_2;

    // uint16_t fs_size;
    uint8_t fs_size_1;
    uint8_t fs_size_0;

    uint8_t fs_page_count;
    uint8_t fs_unused_3[2];
    uint8_t fs_block_type : 6;

    // 14-bit ECC data
    uint8_t ecc3 : 2;
    uint8_t ecc2;
    uint8_t ecc1;
    uint8_t ecc0;
} ecc_data_v2_bb;

void calculate_nand_ecc(uint8_t page[0x200], uint8_t spare[0x10], uint8_t ecc[0x4]);
