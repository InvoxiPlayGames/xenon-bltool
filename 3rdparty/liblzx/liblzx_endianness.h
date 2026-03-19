/*
 * endianness.h - macros and inline functions for endianness conversion
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

#ifndef _LIBLZX_ENDIANNESS_H
#define _LIBLZX_ENDIANNESS_H

#include "liblzx_compiler.h"
#include "liblzx_types.h"

#if LIBLZX_IS_MSVC_COMPILER
#include <intrin.h>
#endif

#ifdef HAVE_SYS_ENDIAN_H
   /* Needed on NetBSD to stop system bswap macros from messing things up */
#  include <sys/endian.h>
#  undef bswap16
#  undef bswap32
#  undef bswap64
#endif

/* Watch out for conflict with ntfs-3g/endians.h ... */
#ifndef _NTFS_ENDIANS_H

#define bswap16_const(n)                        \
        ((((uint16_t)(n) & 0x00FF) << 8)        |       \
         (((uint16_t)(n) & 0xFF00) >> 8))

#define bswap32_const(n)                                \
        ((((uint32_t)(n) & 0x000000FF) << 24)   |       \
         (((uint32_t)(n) & 0x0000FF00) << 8)    |       \
         (((uint32_t)(n) & 0x00FF0000) >> 8)    |       \
         (((uint32_t)(n) & 0xFF000000) >> 24))

#define bswap64_const(n)                                \
        ((((uint64_t)(n) & 0x00000000000000FF) << 56)   |       \
         (((uint64_t)(n) & 0x000000000000FF00) << 40)   |       \
         (((uint64_t)(n) & 0x0000000000FF0000) << 24)   |       \
         (((uint64_t)(n) & 0x00000000FF000000) << 8)    |       \
         (((uint64_t)(n) & 0x000000FF00000000) >> 8)    |       \
         (((uint64_t)(n) & 0x0000FF0000000000) >> 24)   |       \
         (((uint64_t)(n) & 0x00FF000000000000) >> 40)   |       \
         (((uint64_t)(n) & 0xFF00000000000000) >> 56))

static attrib_forceinline uint16_t do_bswap16(uint16_t n)
{
#if LIBLZX_IS_MSVC_COMPILER
        return _byteswap_ushort(n);
#elif GCC_PREREQ(4, 8) || __has_builtin(__builtin_bswap16)
        return __builtin_bswap16(n);
#else
        return bswap16_const(n);
#endif
}

static attrib_forceinline uint32_t do_bswap32(uint32_t n)
{
#if LIBLZX_IS_MSVC_COMPILER
        return _byteswap_ulong(n);
#elif GCC_PREREQ(4, 3) || __has_builtin(__builtin_bswap32)
        return __builtin_bswap32(n);
#else
        return bswap32_const(n);
#endif
}

static attrib_forceinline uint64_t do_bswap64(uint64_t n)
{
#if LIBLZX_IS_MSVC_COMPILER
        return _byteswap_uint64(n);
#elif GCC_PREREQ(4, 3) || __has_builtin(__builtin_bswap64)
        return __builtin_bswap64(n);
#else
        return bswap64_const(n);
#endif
}

#define bswap16(n) (__builtin_constant_p(n) ? bswap16_const(n) : do_bswap16(n))
#define bswap32(n) (__builtin_constant_p(n) ? bswap32_const(n) : do_bswap32(n))
#define bswap64(n) (__builtin_constant_p(n) ? bswap64_const(n) : do_bswap64(n))

#if CPU_IS_BIG_ENDIAN()
#  define cpu_to_le16(n) ((_force_attr le16_t)bswap16(n))
#  define cpu_to_le32(n) ((_force_attr le32_t)bswap32(n))
#  define cpu_to_le64(n) ((_force_attr le64_t)bswap64(n))
#  define le16_to_cpu(n) bswap16((_force_attr uint16_t)(le16_t)(n))
#  define le32_to_cpu(n) bswap32((_force_attr uint32_t)(le32_t)(n))
#  define le64_to_cpu(n) bswap64((_force_attr uint64_t)(le64_t)(n))
#  define cpu_to_be16(n) ((_force_attr be16_t)(uint16_t)(n))
#  define cpu_to_be32(n) ((_force_attr be32_t)(uint32_t)(n))
#  define cpu_to_be64(n) ((_force_attr be64_t)(uint64_t)(n))
#  define be16_to_cpu(n) ((_force_attr uint16_t)(be16_t)(n))
#  define be32_to_cpu(n) ((_force_attr uint32_t)(be32_t)(n))
#  define be64_to_cpu(n) ((_force_attr uint64_t)(be64_t)(n))
#else
#  define cpu_to_le16(n) ((_force_attr le16_t)(uint16_t)(n))
#  define cpu_to_le32(n) ((_force_attr le32_t)(uint32_t)(n))
#  define cpu_to_le64(n) ((_force_attr le64_t)(uint64_t)(n))
#  define le16_to_cpu(n) ((_force_attr uint16_t)(le16_t)(n))
#  define le32_to_cpu(n) ((_force_attr uint32_t)(le32_t)(n))
#  define le64_to_cpu(n) ((_force_attr uint64_t)(le64_t)(n))
#  define cpu_to_be16(n) ((_force_attr be16_t)bswap16(n))
#  define cpu_to_be32(n) ((_force_attr be32_t)bswap32(n))
#  define cpu_to_be64(n) ((_force_attr be64_t)bswap64(n))
#  define be16_to_cpu(n) bswap16((_force_attr uint16_t)(be16_t)(n))
#  define be32_to_cpu(n) bswap32((_force_attr uint32_t)(be32_t)(n))
#  define be64_to_cpu(n) bswap64((_force_attr uint64_t)(be64_t)(n))
#endif

#endif /* _NTFS_ENDIANS_H */
#endif /* _LIBLZX_ENDIANNESS_H */
