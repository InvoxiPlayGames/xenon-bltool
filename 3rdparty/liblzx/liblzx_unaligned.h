/*
 * unaligned.h - inline functions for unaligned memory accesses
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

#ifndef _LIBLZX_UNALIGNED_H
#define _LIBLZX_UNALIGNED_H

#include <string.h>

#include "liblzx_compiler.h"
#include "liblzx_endianness.h"
#include "liblzx_types.h"

#define DEFINE_UNALIGNED_TYPE(name, type)                        \
static attrib_forceinline type                                   \
load_##name##_unaligned(const void *p)                           \
{                                                                \
        type v;                                                  \
        memcpy(&v, p, sizeof(v));                                \
        return v;                                                \
}                                                                \
                                                                 \
static attrib_forceinline void                                   \
store_##name##_unaligned(type v, void *p)                        \
{                                                                \
        memcpy(p, &v, sizeof(v));                                \
}

DEFINE_UNALIGNED_TYPE(u16, uint16_t);
DEFINE_UNALIGNED_TYPE(u32, uint32_t);
DEFINE_UNALIGNED_TYPE(u64, uint64_t);
DEFINE_UNALIGNED_TYPE(le16, le16_t);
DEFINE_UNALIGNED_TYPE(le32, le32_t);
DEFINE_UNALIGNED_TYPE(le64, le64_t);
DEFINE_UNALIGNED_TYPE(be16, be16_t);
DEFINE_UNALIGNED_TYPE(be32, be32_t);
DEFINE_UNALIGNED_TYPE(be64, be64_t);
DEFINE_UNALIGNED_TYPE(size_t, size_t);
DEFINE_UNALIGNED_TYPE(machine_word_t, machine_word_t);

#define load_word_unaligned        load_machine_word_t_unaligned
#define store_word_unaligned        store_machine_word_t_unaligned

static attrib_forceinline uint16_t
get_unaligned_le16(const uint8_t *p)
{
        if (UNALIGNED_ACCESS_IS_FAST)
                return le16_to_cpu(load_le16_unaligned(p));
        else
                return ((uint16_t)p[1] << 8) | p[0];
}

static attrib_forceinline uint32_t
get_unaligned_le32(const uint8_t *p)
{
        if (UNALIGNED_ACCESS_IS_FAST)
                return le32_to_cpu(load_le32_unaligned(p));
        else
                return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
                        ((uint32_t)p[1] << 8) | p[0];
}

static attrib_forceinline uint32_t
get_unaligned_be32(const uint8_t *p)
{
        if (UNALIGNED_ACCESS_IS_FAST)
                return be32_to_cpu(load_be32_unaligned(p));
        else
                return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                        ((uint32_t)p[2] << 8) | p[3];
}

static attrib_forceinline void
put_unaligned_le16(uint16_t v, uint8_t *p)
{
        if (UNALIGNED_ACCESS_IS_FAST) {
                store_le16_unaligned(cpu_to_le16(v), p);
        } else {
                p[0] = (uint8_t)(v >> 0);
                p[1] = (uint8_t)(v >> 8);
        }
}

static attrib_forceinline void
put_unaligned_le32(uint32_t v, uint8_t *p)
{
        if (UNALIGNED_ACCESS_IS_FAST) {
                store_le32_unaligned(cpu_to_le32(v), p);
        } else {
                p[0] = (uint8_t)(v >> 0);
                p[1] = (uint8_t)(v >> 8);
                p[2] = (uint8_t)(v >> 16);
                p[3] = (uint8_t)(v >> 24);
        }
}

static attrib_forceinline void
put_unaligned_be32(uint32_t v, uint8_t *p)
{
        if (UNALIGNED_ACCESS_IS_FAST) {
                store_be32_unaligned(cpu_to_be32(v), p);
        } else {
                p[0] = (uint8_t)(v >> 24);
                p[1] = (uint8_t)(v >> 16);
                p[2] = (uint8_t)(v >> 8);
                p[3] = (uint8_t)(v >> 0);
        }
}

#endif /* _LIBLZX_UNALIGNED_H */
