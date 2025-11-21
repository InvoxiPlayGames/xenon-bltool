#ifndef _LIBLZX_TYPES_H
#define _LIBLZX_TYPES_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include "liblzx_compiler.h"

/* Unsigned little endian types of exact size */
typedef uint16_t _bitwise_attr le16_t;
typedef uint32_t _bitwise_attr le32_t;
typedef uint64_t _bitwise_attr le64_t;

/* Unsigned big endian types of exact size */
typedef uint16_t _bitwise_attr be16_t;
typedef uint32_t _bitwise_attr be32_t;
typedef uint64_t _bitwise_attr be64_t;

/* A pointer to 'utf16lechar' indicates a UTF-16LE encoded string */
typedef le16_t utf16lechar;

/*
 * Type of a machine word.  'unsigned long' would be logical, but that is only
 * 32 bits on x86_64 Windows.  The same applies to 'uint_fast32_t'.  So the best
 * we can do without a bunch of #ifdefs appears to be 'size_t'.
 */
typedef size_t machine_word_t;

#define WORDBYTES        sizeof(machine_word_t)
#define WORDBITS         (8 * WORDBYTES)

#endif /* _LIBLZX_TYPES_H */
