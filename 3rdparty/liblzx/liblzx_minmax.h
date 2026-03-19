/*
 * compiler.h
 *
 * Compiler-specific definitions.
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
#ifndef _LIBLZX_MINMAX_H
#define _LIBLZX_MINMAX_H

#include "liblzx_compiler.h"
#include "liblzx_types.h"

/* Get the minimum of two variables, without multiple evaluation.  */
static attrib_forceinline double
min_double(double a, double b)
{
        return (a < b) ? a : b;
}

static attrib_forceinline float
min_float(float a, float b)
{
        return (a < b) ? a : b;
}

static attrib_forceinline unsigned
min_uint(unsigned a, unsigned b)
{
        return (a < b) ? a : b;
}

static attrib_forceinline unsigned
min_u32(unsigned a, unsigned b)
{
        return (a < b) ? a : b;
}

static attrib_forceinline size_t
min_size(size_t a, size_t b)
{
        return (a < b) ? a : b;
}

static attrib_forceinline intmax_t
min_int(int a, int b)
{
        return (a < b) ? a : b;
}

static attrib_forceinline void *
min_ptr(void *a, void *b)
{
        return (a < b) ? a : b;
}

static attrib_forceinline const void *
min_constptr(const void *a, const void *b)
{
        return (a < b) ? a : b;
}

/* Get the maximum of two variables, without multiple evaluation.  */
static attrib_forceinline double
max_float(double a, double b)
{
        return (a > b) ? a : b;
}

static attrib_forceinline unsigned
max_uint(unsigned a, unsigned b)
{
        return (a > b) ? a : b;
}

static attrib_forceinline uint32_t
max_u32(uint32_t a, uint32_t b)
{
        return (a > b) ? a : b;
}

static attrib_forceinline uint64_t
max_u64(uint64_t a, uint64_t b)
{
        return (a > b) ? a : b;
}

static attrib_forceinline void *
max_ptr(void *a, void *b)
{
        return (a > b) ? a : b;
}

static attrib_forceinline const void *
max_constptr(const void *a, const void *b)
{
        return (a > b) ? a : b;
}

#endif
