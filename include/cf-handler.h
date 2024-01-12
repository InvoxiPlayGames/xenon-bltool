#include <stdint.h>
#include <stdbool.h>

bool cf_is_decrypted(uint8_t *cf_data);
void cf_print_info(uint8_t *cf_data);
void cf_decrypt(uint8_t *cf_data, uint8_t *cpu_or_1bl_key);
void cf_calculate_rotsum(uint8_t *cf_data, uint8_t *sha_out);
bool cf_verify_signature(uint8_t *cf_data);
