/*
 * bitops.h - inline functions for bit manipulation
 *
 * Copyright (C) 2025 Eric Lasota
 * Based on wimlib.  Copyright 2022 Eric Biggers
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _LIBLZX_BITOPS_H
#define _LIBLZX_BITOPS_H

#include "liblzx_compiler.h"
#include "liblzx_types.h"

#if LIBLZX_IS_MSVC_COMPILER
#include <intrin.h>
#endif

/*
 * Bit Scan Reverse (BSR) - find the 0-based index (relative to the least
 * significant bit) of the *most* significant 1 bit in the input value.  The
 * input value must be nonzero!
 */

static attrib_forceinline unsigned
bsr32(uint32_t v)
{
#if LIBLZX_IS_MSVC_COMPILER
        unsigned long result;
        _BitScanReverse(&result, v);
        return result;
#else
        return 31 - __builtin_clz(v);
#endif
}

static attrib_forceinline unsigned
bsr64(uint64_t v)
{
#if LIBLZX_IS_MSVC_COMPILER
#  ifdef _M_AMD64
        unsigned long result;
        _BitScanReverse64(&result, v);
        return result;
#  else
        unsigned long index;
        if (_BitScanReverse(&index, v >> 32))
                return index + 32;

        _BitScanReverse(&index, v & 0xffffffffu);

        return index;
#  endif
#else
        return 63 - __builtin_clzll(v);
#endif
}

static attrib_forceinline unsigned
bsrw(machine_word_t v)
{
        STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);
        if (WORDBITS == 32)
                return bsr32((uint32_t)v);
        else
                return bsr64(v);
}

/*
 * Bit Scan Forward (BSF) - find the 0-based index (relative to the least
 * significant bit) of the *least* significant 1 bit in the input value.  The
 * input value must be nonzero!
 */

static attrib_forceinline unsigned
bsf32(uint32_t v)
{
#if LIBLZX_IS_MSVC_COMPILER
        unsigned long result;
        _BitScanForward(&result, v);
        return result;
#else
        return __builtin_ctz(v);
#endif
}

static attrib_forceinline unsigned
bsf64(uint64_t v)
{
#if LIBLZX_IS_MSVC_COMPILER
#  ifdef _M_AMD64
        unsigned long result;
        _BitScanForward64(&result, v);
        return result;
#  else
        unsigned long index;
        if (_BitScanForward(&index, v & 0xffffffffu))
                return index;

        if (_BitScanForward(&index, v >> 32))
                index += 32;

        return -1;
#  endif
#else
        return __builtin_ctzll(v);
#endif
}

static attrib_forceinline unsigned
bsfw(machine_word_t v)
{
        STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);
        if (WORDBITS == 32)
                return bsf32(v);
        else
                return bsf64(v);
}

/* Return the log base 2 of 'n', rounded up to the nearest integer. */
static attrib_forceinline unsigned
ilog2_ceil(size_t n)
{
        if (n <= 1)
                return 0;
        return 1 + bsrw(n - 1);
}

/* Round 'n' up to the nearest power of 2 */
static attrib_forceinline size_t
roundup_pow_of_2(size_t n)
{
        return (size_t)1 << ilog2_ceil(n);
}

#endif /* _LIBLZX_BITOPS_H */
