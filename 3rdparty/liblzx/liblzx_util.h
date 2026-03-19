/*
 * util.h - utility functions and macros
 */
#ifndef _LIBLZX_UTIL_H
#define _LIBLZX_UTIL_H

#include "liblzx_compiler.h"
#include "liblzx_types.h"

/****************
 * General macros
 *****************/

/* Calculate 'n / d', but round up instead of down.  */
#define DIV_ROUND_UP(n, d)        (((n) + (d) - 1) / (d))

/* Get the number of elements of an array type.  */
#define ARRAY_LEN(array)        (sizeof(array) / sizeof((array)[0]))

#endif /* _LIBLZX_UTIL_H */
