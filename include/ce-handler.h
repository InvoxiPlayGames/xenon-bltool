#include <stdint.h>
#include <stdbool.h>

bool ce_is_decrypted(uint8_t *ce_data);
void ce_print_info(uint8_t *ce_data);
void ce_decrypt(uint8_t *ce_data, uint8_t *cd_key);
void ce_calculate_rotsum(uint8_t *ce_data, uint8_t *sha_out);

bool ce_decompress(uint8_t *ce_data, uint8_t *output_buf);
