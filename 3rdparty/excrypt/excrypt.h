#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>

#define U8V(data) ((uint8_t)(data) & 0xFF)
#define ROTL8(data, bits) (U8V((data) << (bits)) | ((data) >> (8 - (bits))))

#define U16V(data) ((uint16_t)(data) & 0xFFFF)
#define ROTL16(data, bits) (U16V((data) << (bits)) | ((data) >> (16 - (bits))))

#define U32V(data) ((uint32_t)(data) & 0xFFFFFFFF)
#define ROTL32(data, bits) (U32V((data) << (bits)) | ((data) >> (32 - (bits))))

#define ROTL64(data, bits) (((data) << (bits)) | ((data) >> (64 - (bits))))

#ifndef SHOULD_BE_BE
#define BE16(i) ((((i) & 0xFF) << 8 | ((i) >> 8) & 0xFF) & 0xFFFF)
#define BE(i)   (((i) & 0xff) << 24 | ((i) & 0xff00) << 8 | ((i) & 0xff0000) >> 8 | ((i) >> 24) & 0xff)
#define BE64(i) (BE((i) & 0xFFFFFFFF) << 32 | BE(((i) >> 32) & 0xFFFFFFFF))
#else
#define BE16(i) i
#define BE(i) i
#define BE64(i) i
#endif

typedef int BOOL;

#include "excrypt_aes.h"
#include "excrypt_bn.h"
#include "excrypt_des.h"
#include "excrypt_ecc.h"
#include "excrypt_md5.h"
#include "excrypt_mem.h"
#include "excrypt_parve.h"
#include "excrypt_rc4.h"
#include "excrypt_rotsum.h"
#include "excrypt_sha.h"
#include "excrypt_sha2.h"
#include "exkeys.h"
#ifdef __cplusplus
}
#endif
