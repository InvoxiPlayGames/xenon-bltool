#include <stdint.h>
#include <stdbool.h>

bool cd_is_decrypted(uint8_t *cd_data);
void cd_print_info(uint8_t *cd_data);
void cd_decrypt(uint8_t *cd_data, uint8_t *cbb_key, uint8_t *cpu_key);
void cd_calculate_rotsum(uint8_t *cd_data, uint8_t *sha_out);
