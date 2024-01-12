#include <stdint.h>
#include <stdbool.h>

bool cg_is_decrypted(uint8_t *cf_data);
void cg_print_info(uint8_t *cf_data);
void cg_decrypt(uint8_t *cf_data, uint8_t *cpu_or_1bl_key);
void cg_calculate_rotsum(uint8_t *cf_data, uint8_t *sha_out);

bool cg_apply_patch(uint8_t *cg_data, uint8_t *base_data, uint8_t *output_buf);
