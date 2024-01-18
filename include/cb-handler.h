#include <stdint.h>
#include <stdbool.h>

bool cb_is_decrypted(uint8_t *cb_data);
void cb_print_info(uint8_t *cb_data);
void cb_decrypt(uint8_t *cb_data, uint8_t *cba_or_1bl_key);
void cb_b_decrypt(uint8_t *cb_b_data, uint8_t *cb_a_data, uint8_t *cpu_key);
void cb_calculate_rotsum(uint8_t *cb_data, uint8_t *sha_out);
bool cb_verify_signature(uint8_t *cb_data);
