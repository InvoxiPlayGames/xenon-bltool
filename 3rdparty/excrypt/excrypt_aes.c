#include <string.h>

#include "excrypt.h"

// reference rijndael implementation, from http://www.efgh.com/software/rijndael.htm
#include "rijndael.h"

// function signature shared between reference impl. and our AESNI versions
typedef void(*rijndaelCrypt_fn)(const unsigned long*, int, const unsigned char*, unsigned char*);

rijndaelCrypt_fn AesEnc = rijndaelEncrypt;
rijndaelCrypt_fn AesDec = rijndaelDecrypt;

void ExCryptAesKey(EXCRYPT_AES_STATE* state, const uint8_t* key)
{
  rijndaelSetupEncrypt((unsigned long*)state->keytabenc, key, 128);
  memcpy(state->keytabdec, state->keytabenc, sizeof(state->keytabdec));
  rijndaelSetupDecrypt((unsigned long*)state->keytabdec, key, 128);
}

void ExCryptAesEcb(const EXCRYPT_AES_STATE* state, const uint8_t* input, uint8_t* output, uint8_t encrypt)
{
  if (encrypt)
  {
    AesEnc((unsigned long*)state->keytabenc, 10, input, output);
  }
  else
  {
    AesDec((unsigned long*)state->keytabdec, 10, input, output);
  }
}

void xorWithIv(const uint8_t* input, uint8_t* output, const uint8_t* iv)
{
  for (uint32_t i = 0; i < AES_BLOCKLEN; i++)
  {
    output[i] = input[i] ^ iv[i];
  }
}

void rijndaelCbcEncrypt(const unsigned long* rk, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed)
{
  uint8_t* iv = feed;
  for (uint32_t i = 0; i < input_size; i += AES_BLOCKLEN)
  {
    xorWithIv(input, output, iv);
    AesEnc(rk, 10, output, output);
    iv = output;
    output += AES_BLOCKLEN;
    input += AES_BLOCKLEN;
  }
  // store IV in feed param for next call
  memcpy(feed, iv, AES_BLOCKLEN);
}

void rijndaelCbcDecrypt(const unsigned long* rk, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed)
{
  const uint8_t* iv = feed;
  for (uint32_t i = 0; i < input_size; i += AES_BLOCKLEN)
  {
    AesDec(rk, 10, input, output);
    xorWithIv(output, output, iv);
    iv = input;
    output += AES_BLOCKLEN;
    input += AES_BLOCKLEN;
  }
  // store IV in feed param for next call
  memcpy(feed, iv, AES_BLOCKLEN);
}

void ExCryptAesCbc(const EXCRYPT_AES_STATE* state, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed, uint8_t encrypt)
{
  if (encrypt)
  {
    rijndaelCbcEncrypt((unsigned long*)state->keytabenc, input, input_size, output, feed);
  }
  else
  {
    rijndaelCbcDecrypt((unsigned long*)state->keytabdec, input, input_size, output, feed);
  }
}

unsigned long* aesschedule_dectable(EXCRYPT_AES_SCHEDULE* state)
{
  return (unsigned long*)&state->keytab[state->num_rounds + 1]; // dec table starts at last entry of enc table
}

void ExCryptAesCreateKeySchedule(const uint8_t* key, uint32_t key_size, EXCRYPT_AES_SCHEDULE* state)
{
  if (key_size != 0x10 && key_size != 0x18 && key_size != 0x20)
  {
    return; // invalid key size, must be 128/192/256 bits
  }

  state->num_rounds = (key_size >> 2) + 5; // seems to be nr - 1 ?

  rijndaelSetupEncrypt((unsigned long*)state->keytab, key, key_size * 8);
  memcpy(aesschedule_dectable(state), state->keytab, (state->num_rounds + 2) * 0x10);
  rijndaelSetupDecrypt(aesschedule_dectable(state), key, key_size * 8);
}

void ExCryptAesCbcEncrypt(EXCRYPT_AES_SCHEDULE* state, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed)
{
  uint8_t* iv = feed;
  for (uint32_t i = 0; i < input_size; i += AES_BLOCKLEN)
  {
    xorWithIv(input, output, iv);
    rijndaelEncrypt((unsigned long*)state->keytab, state->num_rounds + 1, output, output);
    iv = output;
    output += AES_BLOCKLEN;
    input += AES_BLOCKLEN;
  }
  // store IV in feed param for next call
  memcpy(feed, iv, AES_BLOCKLEN);
}

void ExCryptAesCbcDecrypt(EXCRYPT_AES_SCHEDULE* state, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed)
{
  const uint8_t* iv = feed;
  for (uint32_t i = 0; i < input_size; i += AES_BLOCKLEN)
  {
    rijndaelDecrypt(aesschedule_dectable(state), state->num_rounds + 1, input, output);
    xorWithIv(output, output, iv);
    iv = input;
    output += AES_BLOCKLEN;
    input += AES_BLOCKLEN;
  }
  // store IV in feed param for next call
  memcpy(feed, iv, AES_BLOCKLEN);
}

void ExCryptAesEncryptOne(EXCRYPT_AES_SCHEDULE* state, const uint8_t* input, uint8_t* output)
{
  uint8_t feed[0x10];
  memset(feed, 0, 0x10);

  ExCryptAesCbcEncrypt(state, input, 0x10, output, feed);
}

void ExCryptAesDecryptOne(EXCRYPT_AES_SCHEDULE* state, const uint8_t* input, uint8_t* output)
{
  uint8_t feed[0x10];
  memset(feed, 0, 0x10);

  ExCryptAesCbcDecrypt(state, input, 0x10, output, feed);
}
