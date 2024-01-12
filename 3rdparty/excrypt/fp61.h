#pragma once

// Code to extract high part of 64 bit integer multiplication
// from: https://github.com/catid/fp61/blob/master/fp61.h

# define CAT_MUL128(r_hi, r_lo, x, y)                   \
    {                                                   \
        unsigned __int128 w = (unsigned __int128)x * y; \
        r_lo = (uint64_t)w;                             \
        r_hi = (uint64_t)(w >> 64);                     \
    }
