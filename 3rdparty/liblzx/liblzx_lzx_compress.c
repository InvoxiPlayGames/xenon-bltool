/*
 * lzx_compress.c
 *
 * A compressor for the LZX compression format, as used in WIM archives.
 */

/*
 * Copyright (C) 2025 Eric Lasota
 * Based on wimlib.  Copyright (C) 2012-2017 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see https://www.gnu.org/licenses/.
 */


/*
 * This file contains a compressor for the LZX ("Lempel-Ziv eXtended")
 * compression format, as used in the WIM (Windows IMaging) file format.
 *
 * Two different LZX-compatible algorithms are implemented: "near-optimal" and
 * "lazy".  "Near-optimal" is significantly slower than "lazy", but results in a
 * better compression ratio.  The "near-optimal" algorithm is used at the
 * default compression level.
 *
 * This file may need some slight modifications to be used outside of the WIM
 * format.  In particular, in other situations the LZX block header might be
 * slightly different, and sliding window support might be required.
 *
 * LZX is a compression format derived from DEFLATE, the format used by zlib and
 * gzip.  Both LZX and DEFLATE use LZ77 matching and Huffman coding.  Certain
 * details are quite similar, such as the method for storing Huffman codes.
 * However, the main differences are:
 *
 * - LZX preprocesses the data to attempt to make x86 machine code slightly more
 *   compressible before attempting to compress it further.
 *
 * - LZX uses a "main" alphabet which combines literals and matches, with the
 *   match symbols containing a "length header" (giving all or part of the match
 *   length) and an "offset slot" (giving, roughly speaking, the order of
 *   magnitude of the match offset).
 *
 * - LZX does not have static Huffman blocks (that is, the kind with preset
 *   Huffman codes); however it does have two types of dynamic Huffman blocks
 *   ("verbatim" and "aligned").
 *
 * - LZX has a minimum match length of 2 rather than 3.  Length 2 matches can be
 *   useful, but generally only if the compressor is smart about choosing them.
 *
 * - In LZX, offset slots 0 through 2 actually represent entries in an LRU queue
 *   of match offsets.  This is very useful for certain types of files, such as
 *   binary files that have repeating records.
 */

/******************************************************************************/
/*                            General parameters                              */
/*----------------------------------------------------------------------------*/

/*
 * The compressor uses the faster algorithm at levels <= MAX_FAST_LEVEL.  It
 * uses the slower algorithm at levels > MAX_FAST_LEVEL.
 */
#define MAX_FAST_LEVEL                                34

/*
 * The compressor-side limits on the codeword lengths (in bits) for each Huffman
 * code.  To make outputting bits slightly faster, some of these limits are
 * lower than the limits defined by the LZX format.  This does not significantly
 * affect the compression ratio.
 */
#define MAIN_CODEWORD_LIMIT                        16
#define LENGTH_CODEWORD_LIMIT                        12
#define ALIGNED_CODEWORD_LIMIT                        7
#define PRE_CODEWORD_LIMIT                        7

/******************************************************************************/
/*                         Block splitting parameters                         */
/*----------------------------------------------------------------------------*/

/*
 * The compressor always outputs blocks of at least this size in bytes, except
 * for the last block which may need to be smaller.
 */
#define MIN_BLOCK_SIZE                                6500

/*
 * The compressor attempts to end a block when it reaches this size in bytes.
 * The final size might be slightly larger due to matches extending beyond the
 * end of the block.  Specifically:
 *
 *  - The near-optimal compressor may choose a match of up to LZX_MAX_MATCH_LEN
 *    bytes starting at position 'SOFT_MAX_BLOCK_SIZE - 1'.
 *
 *  - The lazy compressor may choose a sequence of literals starting at position
 *    'SOFT_MAX_BLOCK_SIZE - 1' when it sees a sequence of increasingly better
 *    matches.  The final match may be up to LZX_MAX_MATCH_LEN bytes.  The
 *    length of the literal sequence is approximately limited by the "nice match
 *    length" parameter.
 */
#define SOFT_MAX_BLOCK_SIZE                        100000

/*
 * The number of observed items (matches and literals) that represents
 * sufficient data for the compressor to decide whether the current block should
 * be ended or not.
 */
#define NUM_OBSERVATIONS_PER_BLOCK_CHECK        400


/******************************************************************************/
/*                      Parameters for slower algorithm                       */
/*----------------------------------------------------------------------------*/

/*
 * The log base 2 of the number of entries in the hash table for finding length
 * 2 matches.  This could be as high as 16, but using a smaller hash table
 * speeds up compression due to reduced cache pressure.
 */
#define BT_MATCHFINDER_HASH2_ORDER                12

/*
 * The number of lz_match structures in the match cache, excluding the extra
 * "overflow" entries.  This value should be high enough so that nearly the
 * time, all matches found in a given block can fit in the match cache.
 * However, fallback behavior (immediately terminating the block) on cache
 * overflow is still required.
 */
#define CACHE_LENGTH                                (SOFT_MAX_BLOCK_SIZE * 5)

/*
 * An upper bound on the number of matches that can ever be saved in the match
 * cache for a single position.  Since each match we save for a single position
 * has a distinct length, we can use the number of possible match lengths in LZX
 * as this bound.  This bound is guaranteed to be valid in all cases, although
 * if 'nice_match_length < LZX_MAX_MATCH_LEN', then it will never actually be
 * reached.
 */
#define MAX_MATCHES_PER_POS                        LZX_NUM_LENS

/*
 * A scaling factor that makes it possible to consider fractional bit costs.  A
 * single bit has a cost of BIT_COST.
 *
 * Note: this is only useful as a statistical trick for when the true costs are
 * unknown.  Ultimately, each token in LZX requires a whole number of bits to
 * output.
 */
#define BIT_COST_BITS                                6
#define BIT_COST                                (1 << BIT_COST_BITS)

/*
 * Should the compressor take into account the costs of aligned offset symbols
 * instead of assuming that all are equally likely?
 */
#define CONSIDER_ALIGNED_COSTS                        1

/*
 * Should the "minimum" cost path search algorithm consider "gap" matches, where
 * a normal match is followed by a literal, then by a match with the same
 * offset?  This is one specific, somewhat common situation in which the true
 * minimum cost path is often different from the path found by looking only one
 * edge ahead.
 */
#define CONSIDER_GAP_MATCHES                        1

/******************************************************************************/
/*                                  Includes                                  */
/*----------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "liblzx_compress_common.h"
#include "liblzx_error.h"
#include "liblzx_lzx_common.h"
#include "liblzx_minmax.h"
#include "liblzx_unaligned.h"
#include "liblzx_util.h"
#include "liblzx.h"

#include <alloca.h>

#include <assert.h>

#include <malloc.h>

/* Note: BT_MATCHFINDER_HASH2_ORDER must be defined before including
 * bt_matchfinder.h. */

/* Matchfinders with 16-bit positions */
#define mf_pos_t        uint16_t
#define MF_SUFFIX        _16
#define MF_INVALID_POS        (0xFFFFu)
#include "liblzx_bt_matchfinder.h"
#include "liblzx_hc_matchfinder.h"

/* Matchfinders with 32-bit positions */
#undef mf_pos_t
#undef MF_SUFFIX
#undef MF_INVALID_POS
#define mf_pos_t        uint32_t
#define MF_SUFFIX        _32
#define MF_INVALID_POS        (0xFFFFFFFFu)
#include "liblzx_bt_matchfinder.h"
#include "liblzx_hc_matchfinder.h"

#undef mf_pos_t
#undef MF_SUFFIX
#undef MF_INVALID_POS

/******************************************************************************/
/*                            Compressor structure                            */
/*----------------------------------------------------------------------------*/

/* Codewords for the Huffman codes */
struct lzx_codewords {
        uint32_t main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
        uint32_t len[LZX_LENCODE_NUM_SYMBOLS];
        uint32_t aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/*
 * Codeword lengths, in bits, for the Huffman codes.
 *
 * A codeword length of 0 means the corresponding codeword has zero frequency.
 *
 * The main and length codes each have one extra entry for use as a sentinel.
 * See lzx_write_compressed_code().
 */
struct lzx_lens {
        uint8_t main[LZX_MAINCODE_MAX_NUM_SYMBOLS + 1];
        uint8_t len[LZX_LENCODE_NUM_SYMBOLS + 1];
        uint8_t aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Codewords and lengths for the Huffman codes */
struct lzx_codes {
        struct lzx_codewords codewords;
        struct lzx_lens lens;
};

/* Symbol frequency counters for the Huffman-encoded alphabets */
struct lzx_freqs {
        uint32_t main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
        uint32_t len[LZX_LENCODE_NUM_SYMBOLS];
        uint32_t aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Block split statistics.  See the "Block splitting algorithm" section later in
 * this file for details. */
#define NUM_LITERAL_OBSERVATION_TYPES 8
#define NUM_MATCH_OBSERVATION_TYPES 2
#define NUM_OBSERVATION_TYPES (NUM_LITERAL_OBSERVATION_TYPES + \
                               NUM_MATCH_OBSERVATION_TYPES)
struct lzx_block_split_stats {
        uint32_t new_observations[NUM_OBSERVATION_TYPES];
        uint32_t observations[NUM_OBSERVATION_TYPES];
        uint32_t num_new_observations;
        uint32_t num_observations;
};

/*
 * Represents a run of literals followed by a match or end-of-block.  This
 * structure is needed to temporarily store items chosen by the compressor,
 * since items cannot be written until all items for the block have been chosen
 * and the block's Huffman codes have been computed.
 */
struct attrib_aligned(8) lzx_sequence {

        /*
         * Bits 9..31: the number of literals in this run.  This may be 0 and
         * can be at most about SOFT_MAX_BLOCK_LENGTH.  The literals are not
         * stored explicitly in this structure; instead, they are read directly
         * from the uncompressed data.
         *
         * Bits 0..8: the length of the match which follows the literals, or 0
         * if this literal run was the last in the block, so there is no match
         * which follows it.  This can be at most LZX_MAX_MATCH_LEN.
         */
        uint32_t litrunlen_and_matchlen;
#define SEQ_MATCHLEN_BITS        9
#define SEQ_MATCHLEN_MASK        (((uint32_t)1 << SEQ_MATCHLEN_BITS) - 1)

        /*
         * If 'matchlen' doesn't indicate end-of-block, then this contains:
         *
         * Bits 10..31: either the offset plus LZX_OFFSET_ADJUSTMENT or a recent
         * offset code, depending on the offset slot encoded in the main symbol.
         *
         * Bits 0..9: the main symbol.
         */
        uint32_t adjusted_offset_and_mainsym;
#define SEQ_MAINSYM_BITS        10
#define SEQ_MAINSYM_MASK        (((uint32_t)1 << SEQ_MAINSYM_BITS) - 1)
};

/*
 * This structure represents a byte position in the input buffer and a node in
 * the graph of possible match/literal choices.
 *
 * Logically, each incoming edge to this node is labeled with a literal or a
 * match that can be taken to reach this position from an earlier position; and
 * each outgoing edge from this node is labeled with a literal or a match that
 * can be taken to advance from this position to a later position.
 */
struct attrib_aligned(8) lzx_optimum_node {

        /* The cost, in bits, of the lowest-cost path that has been found to
         * reach this position.  This can change as progressively lower cost
         * paths are found to reach this position.  */
        uint32_t cost;

        /*
         * The best arrival to this node, i.e. the match or literal that was
         * used to arrive to this position at the given 'cost'.  This can change
         * as progressively lower cost paths are found to reach this position.
         *
         * For non-gap matches, this variable is divided into two bitfields
         * whose meanings depend on the item type:
         *
         * Literals:
         *        Low bits are 0, high bits are the literal.
         *
         * Explicit offset matches:
         *        Low bits are the match length, high bits are the offset plus
         *        LZX_OFFSET_ADJUSTMENT.
         *
         * Repeat offset matches:
         *        Low bits are the match length, high bits are the queue index.
         *
         * For gap matches, identified by OPTIMUM_GAP_MATCH set, special
         * behavior applies --- see the code.
         */
        uint32_t item;
#define OPTIMUM_OFFSET_SHIFT        SEQ_MATCHLEN_BITS
#define OPTIMUM_LEN_MASK        SEQ_MATCHLEN_MASK
#if CONSIDER_GAP_MATCHES
#  define OPTIMUM_GAP_MATCH 0x80000000
#endif

};

/* The cost model for near-optimal parsing */
struct lzx_costs {

        /*
         * 'match_cost[offset_slot][len - LZX_MIN_MATCH_LEN]' is the cost of a
         * length 'len' match which has an offset belonging to 'offset_slot'.
         * The cost includes the main symbol, the length symbol if required, and
         * the extra offset bits if any, excluding any entropy-coded bits
         * (aligned offset bits).  It does *not* include the cost of the aligned
         * offset symbol which may be required.
         */
        uint16_t match_cost[LZX_MAX_OFFSET_SLOTS][LZX_NUM_LENS];

        /* Cost of each symbol in the main code */
        uint32_t main[LZX_MAINCODE_MAX_NUM_SYMBOLS];

        /* Cost of each symbol in the length code */
        uint32_t len[LZX_LENCODE_NUM_SYMBOLS];

#if CONSIDER_ALIGNED_COSTS
        /* Cost of each symbol in the aligned offset code */
        uint32_t aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
#endif
};

struct lzx_output_bitstream;

/* The main LZX compressor structure */
struct liblzx_compressor {

        /* The LZX variant to use */
        enum liblzx_variant variant;

        /* Output chunk */
        liblzx_output_chunk_t out_chunk;

        /* True if a flush was requested*/
        bool flushing;

        /* Memory allocation function */
        liblzx_alloc_func_t alloc_func;

        /* Memory free function */
        liblzx_free_func_t free_func;

        /* Memory allocation userdata */
        void *alloc_userdata;

        /* True if the compressor is outputting the first block */
        bool first_block;

        /* E8 preprocessor file size */
        uint32_t e8_file_size;

        /* E8 preprocessor chunk offset */
        uint32_t e8_chunk_offset;

        /* The buffer for preprocessed input data, if not using destructive
         * compression */
        void *in_buffer;

        /* The buffer for output data */
        void *out_buffer;

        /* Capacity of in_buffer */
        uint32_t in_buffer_capacity;

        /* Capacity of out_buffer */
        uint32_t out_buffer_capacity;

        /* Number of prefix bytes currently in in_buffer */
        uint32_t in_prefix_size;

        /* Number of bytes currently in in_buffer */
        uint32_t in_used;

        /* Maximum size of a chunk */
        uint32_t chunk_size;

        /* Pointer to the reset() implementation chosen at allocation time */
        void (*reset)(struct liblzx_compressor *);

        /* Pointer to the compress() implementation chosen at allocation time */
        void (*impl)(struct liblzx_compressor *, const uint8_t *, size_t, size_t,
                     struct lzx_output_bitstream *);

        /* Pointer to the cul() implementation chosen at allocation time */
        void (*cull)(struct liblzx_compressor *, size_t);

        /* The window size. */
        uint32_t window_size;

        /* The log base 2 of the window size for match offset encoding purposes.
         * This will be >= LZX_MIN_WINDOW_ORDER and <= LZX_MAX_WINDOW_ORDER. */
        unsigned window_order;

        /* The number of symbols in the main alphabet.  This depends on the
         * window order, since the window order determines the maximum possible
         * match offset. */
        unsigned num_main_syms;

        /* The "nice" match length: if a match of this length is found, then it
         * is chosen immediately without further consideration. */
        unsigned nice_match_length;

        /* The maximum search depth: at most this many potential matches are
         * considered at each position. */
        unsigned max_search_depth;

        /* The number of optimization passes per block */
        unsigned num_optim_passes;

        /* The symbol frequency counters for the current block */
        struct lzx_freqs freqs;

        /* Block split statistics for the current block */
        struct lzx_block_split_stats split_stats;

        /* The Huffman codes for the current and previous blocks.  The one with
         * index 'codes_index' is for the current block, and the other one is
         * for the previous block. */
        struct lzx_codes codes[2];
        unsigned codes_index;

        /* The matches and literals that the compressor has chosen for the
         * current block.  The required length of this array is limited by the
         * maximum number of matches that can ever be chosen for a single block,
         * plus one for the special entry at the end. */
        struct lzx_sequence chosen_sequences[
                       DIV_ROUND_UP(SOFT_MAX_BLOCK_SIZE, LZX_MIN_MATCH_LEN) + 1];

        /* Least-recently-used match queue */
        uint32_t lru_queue[LZX_NUM_RECENT_OFFSETS];

        /* Next hashes */
        uint32_t next_hashes[2];

        /* Tables for mapping adjusted offsets to offset slots */
        uint8_t offset_slot_tab_1[32768]; /* offset slots [0, 29] */
        uint8_t offset_slot_tab_2[128]; /* offset slots [30, 49] */

        union {
                /* Data for lzx_compress_lazy() */
                struct {
                        /* Hash chains matchfinder (MUST BE LAST!!!) */
                        union {
                                struct hc_matchfinder_16 hc_mf_16;
                                struct hc_matchfinder_32 hc_mf_32;
                        };
                };

                /* Data for lzx_compress_near_optimal() */
                struct {
                        /*
                         * Array of nodes, one per position, for running the
                         * minimum-cost path algorithm.
                         *
                         * This array must be large enough to accommodate the
                         * worst-case number of nodes, which occurs if the
                         * compressor finds a match of length LZX_MAX_MATCH_LEN
                         * at position 'SOFT_MAX_BLOCK_SIZE - 1', producing a
                         * block of size 'SOFT_MAX_BLOCK_SIZE - 1 +
                         * LZX_MAX_MATCH_LEN'.  Add one for the end-of-block
                         * node.
                         */
                        struct lzx_optimum_node optimum_nodes[
                                                    SOFT_MAX_BLOCK_SIZE - 1 +
                                                    LZX_MAX_MATCH_LEN + 1];

                        /* The cost model for the current optimization pass */
                        struct lzx_costs costs;

                        /*
                         * Cached matches for the current block.  This array
                         * contains the matches that were found at each position
                         * in the block.  Specifically, for each position, there
                         * is a special 'struct lz_match' whose 'length' field
                         * contains the number of matches that were found at
                         * that position; this is followed by the matches
                         * themselves, if any, sorted by strictly increasing
                         * length.
                         *
                         * Note: in rare cases, there will be a very high number
                         * of matches in the block and this array will overflow.
                         * If this happens, we force the end of the current
                         * block.  CACHE_LENGTH is the length at which we
                         * actually check for overflow.  The extra slots beyond
                         * this are enough to absorb the worst case overflow,
                         * which occurs if starting at &match_cache[CACHE_LENGTH
                         * - 1], we write the match count header, then write
                         * MAX_MATCHES_PER_POS matches, then skip searching for
                         * matches at 'LZX_MAX_MATCH_LEN - 1' positions and
                         * write the match count header for each.
                         */
                        struct lz_match match_cache[CACHE_LENGTH +
                                                    MAX_MATCHES_PER_POS +
                                                    LZX_MAX_MATCH_LEN - 1];

                        /* Binary trees matchfinder (MUST BE LAST!!!) */
                        union {
                                struct bt_matchfinder_16 bt_mf_16;
                                struct bt_matchfinder_32 bt_mf_32;
                        };
                };
        };
};

/******************************************************************************/
/*                            Matchfinder utilities                           */
/*----------------------------------------------------------------------------*/

/*
 * Will a matchfinder using 16-bit positions be sufficient for compressing
 * buffers of up to the specified size?  The limit could be 65536 bytes, but we
 * also want to optimize out the use of offset_slot_tab_2 in the 16-bit case.
 * This requires that the limit be no more than the length of offset_slot_tab_1
 * (currently 32768).
 */
static attrib_forceinline bool
lzx_is_16_bit(size_t max_bufsize)
{
        STATIC_ASSERT(ARRAY_LEN(((struct liblzx_compressor *)0)->offset_slot_tab_1) == 32768);
        return max_bufsize <= 32768;
}

/*
 * Return the offset slot for the specified adjusted match offset.
 */
static attrib_forceinline unsigned
lzx_get_offset_slot(struct liblzx_compressor *c, uint32_t adjusted_offset,
                    bool is_16_bit)
{
        if (__builtin_constant_p(adjusted_offset) &&
            adjusted_offset < LZX_NUM_RECENT_OFFSETS)
                return adjusted_offset;
        if (is_16_bit || adjusted_offset < ARRAY_LEN(c->offset_slot_tab_1))
                return c->offset_slot_tab_1[adjusted_offset];

        assert((adjusted_offset >> 14) < ARRAY_LEN(c->offset_slot_tab_2));

        return c->offset_slot_tab_2[adjusted_offset >> 14];
}

/*
 * For a match that has the specified length and adjusted offset, tally its main
 * symbol, and if needed its length symbol; then return its main symbol.
 */
static attrib_forceinline unsigned
lzx_tally_main_and_lensyms(struct liblzx_compressor *c, unsigned length,
                           uint32_t adjusted_offset, bool is_16_bit)
{
        unsigned mainsym;

        if (length >= LZX_MIN_SECONDARY_LEN) {
                /* Length symbol needed */
                c->freqs.len[length - LZX_MIN_SECONDARY_LEN]++;
                mainsym = LZX_NUM_CHARS + LZX_NUM_PRIMARY_LENS;
        } else {
                /* No length symbol needed */
                mainsym = LZX_NUM_CHARS + length - LZX_MIN_MATCH_LEN;
        }

        mainsym += LZX_NUM_LEN_HEADERS *
                   lzx_get_offset_slot(c, adjusted_offset, is_16_bit);
        c->freqs.main[mainsym]++;
        return mainsym;
}

/*
 * The following macros call either the 16-bit or the 32-bit version of a
 * matchfinder function based on the value of 'is_16_bit', which will be known
 * at compilation time.
 */

#define CALL_HC_MF(is_16_bit, c, funcname, ...)                                      \
        ((is_16_bit) ? CONCAT(funcname, _16)(&(c)->hc_mf_16, ##__VA_ARGS__) : \
                       CONCAT(funcname, _32)(&(c)->hc_mf_32, ##__VA_ARGS__));

#define CALL_BT_MF(is_16_bit, c, funcname, ...)                                      \
        ((is_16_bit) ? CONCAT(funcname, _16)(&(c)->bt_mf_16, ##__VA_ARGS__) : \
                       CONCAT(funcname, _32)(&(c)->bt_mf_32, ##__VA_ARGS__));

/******************************************************************************/
/*                             Output bitstream                               */
/*----------------------------------------------------------------------------*/

/*
 * The LZX bitstream is encoded as a sequence of little endian 16-bit coding
 * units.  Bits are ordered from most significant to least significant within
 * each coding unit.
 */

/*
 * Structure to keep track of the current state of sending bits to the
 * compressed output buffer.
 */
struct lzx_output_bitstream {

        /* Bits that haven't yet been written to the output buffer */
        machine_word_t bitbuf;

        /* Number of bits currently held in @bitbuf */
        machine_word_t bitcount;

        /* Pointer to the start of the output buffer */
        uint8_t *start;

        /* Pointer to the position in the output buffer at which the next coding
         * unit should be written */
        uint8_t *next;

        /* Pointer to just past the end of the output buffer, rounded down by
         * one byte if needed to make 'end - start' a multiple of 2 */
        uint8_t *end;
};

/* Can the specified number of bits always be added to 'bitbuf' after all
 * pending 16-bit coding units have been flushed?  */
#define CAN_BUFFER(n)        ((n) <= WORDBITS - 15)

/* Initialize the output bitstream to write to the specified buffer. */
static void
lzx_init_output(struct lzx_output_bitstream *os, void *buffer, size_t size)
{
        os->bitbuf = 0;
        os->bitcount = 0;
        os->start = buffer;
        os->next = buffer;
        os->end = (uint8_t *)buffer + (size & ~1);
}

/*
 * Add some bits to the bitbuffer variable of the output bitstream.  The caller
 * must make sure there is enough room.
 */
static attrib_forceinline void
lzx_add_bits(struct lzx_output_bitstream *os, uint32_t bits, unsigned num_bits)
{
        os->bitbuf = (os->bitbuf << num_bits) | bits;
        os->bitcount += num_bits;
}

/*
 * Flush bits from the bitbuffer variable to the output buffer.  'max_num_bits'
 * specifies the maximum number of bits that may have been added since the last
 * flush.
 */
static attrib_forceinline void
lzx_flush_bits(struct lzx_output_bitstream *os, unsigned max_num_bits)
{
        /* Masking the number of bits to shift is only needed to avoid undefined
         * behavior; we don't actually care about the results of bad shifts.  On
         * x86, the explicit masking generates no extra code.  */
        const uint32_t shift_mask = WORDBITS - 1;

        if (os->end - os->next < 6)
                return;
        put_unaligned_le16(os->bitbuf >> ((os->bitcount - 16) &
                                            shift_mask), os->next + 0);
        if (max_num_bits > 16)
                put_unaligned_le16(os->bitbuf >> ((os->bitcount - 32) &
                                                shift_mask), os->next + 2);
        if (max_num_bits > 32)
                put_unaligned_le16(os->bitbuf >> ((os->bitcount - 48) &
                                                shift_mask), os->next + 4);
        os->next += (os->bitcount >> 4) << 1;
        os->bitcount &= 15;
}

/* Add at most 16 bits to the bitbuffer and flush it.  */
static attrib_forceinline void
lzx_write_bits(struct lzx_output_bitstream *os, uint32_t bits, unsigned num_bits)
{
        lzx_add_bits(os, bits, num_bits);
        lzx_flush_bits(os, 16);
}

/*
 * Flush the last coding unit to the output buffer if needed.  Return the total
 * number of bytes written to the output buffer, or 0 if an overflow occurred.
 */
static size_t
lzx_flush_output(struct lzx_output_bitstream *os)
{
        if (os->end - os->next < 6)
                return 0;

        if (os->bitcount != 0) {
                put_unaligned_le16(os->bitbuf << (16 - os->bitcount), os->next);
                os->next += 2;
        }

        return os->next - os->start;
}

/******************************************************************************/
/*                           Preparing Huffman codes                          */
/*----------------------------------------------------------------------------*/

/*
 * Build the Huffman codes.  This takes as input the frequency tables for each
 * code and produces as output a set of tables that map symbols to codewords and
 * codeword lengths.
 */
static void
lzx_build_huffman_codes(struct liblzx_compressor *c)
{
        const struct lzx_freqs *freqs = &c->freqs;
        struct lzx_codes *codes = &c->codes[c->codes_index];

        STATIC_ASSERT_STMT(MAIN_CODEWORD_LIMIT >= 9 &&
                      MAIN_CODEWORD_LIMIT <= LZX_MAX_MAIN_CODEWORD_LEN);
        make_canonical_huffman_code(c->num_main_syms,
                                    MAIN_CODEWORD_LIMIT,
                                    freqs->main,
                                    codes->lens.main,
                                    codes->codewords.main);

        STATIC_ASSERT_STMT(LENGTH_CODEWORD_LIMIT >= 8 &&
                      LENGTH_CODEWORD_LIMIT <= LZX_MAX_LEN_CODEWORD_LEN);
        make_canonical_huffman_code(LZX_LENCODE_NUM_SYMBOLS,
                                    LENGTH_CODEWORD_LIMIT,
                                    freqs->len,
                                    codes->lens.len,
                                    codes->codewords.len);

        STATIC_ASSERT_STMT(
            ALIGNED_CODEWORD_LIMIT >= LZX_NUM_ALIGNED_OFFSET_BITS &&
                      ALIGNED_CODEWORD_LIMIT <= LZX_MAX_ALIGNED_CODEWORD_LEN);
        make_canonical_huffman_code(LZX_ALIGNEDCODE_NUM_SYMBOLS,
                                    ALIGNED_CODEWORD_LIMIT,
                                    freqs->aligned,
                                    codes->lens.aligned,
                                    codes->codewords.aligned);
}

/* Reset the symbol frequencies for the current block. */
static void
lzx_reset_symbol_frequencies(struct liblzx_compressor *c)
{
        memset(&c->freqs, 0, sizeof(c->freqs));
}

static unsigned
lzx_compute_precode_items(const uint8_t * restrict lens,
                          const uint8_t * restrict prev_lens,
                          uint32_t * restrict precode_freqs,
                          unsigned * restrict precode_items)
{
        unsigned *itemptr;
        unsigned run_start;
        unsigned run_end;
        unsigned extra_bits;
        int delta;
        uint8_t len;

        itemptr = precode_items;
        run_start = 0;

        while (!((len = lens[run_start]) & 0x80)) {

                /* len = the length being repeated  */

                /* Find the next run of codeword lengths.  */

                run_end = run_start + 1;

                /* Fast case for a single length.  */
                if (likely(len != lens[run_end])) {
                        delta = prev_lens[run_start] - len;
                        if (delta < 0)
                                delta += 17;
                        precode_freqs[delta]++;
                        *itemptr++ = delta;
                        run_start++;
                        continue;
                }

                /* Extend the run.  */
                do {
                        run_end++;
                } while (len == lens[run_end]);

                if (len == 0) {
                        /* Run of zeroes.  */

                        /* Symbol 18: RLE 20 to 51 zeroes at a time.  */
                        while ((run_end - run_start) >= 20) {
                                extra_bits =
                                    min_uint((run_end - run_start) - 20, 0x1F);
                                precode_freqs[18]++;
                                *itemptr++ = 18 | (extra_bits << 5);
                                run_start += 20 + extra_bits;
                        }

                        /* Symbol 17: RLE 4 to 19 zeroes at a time.  */
                        if ((run_end - run_start) >= 4) {
                                extra_bits =
                                    min_uint((run_end - run_start) - 4, 0xF);
                                precode_freqs[17]++;
                                *itemptr++ = 17 | (extra_bits << 5);
                                run_start += 4 + extra_bits;
                        }
                } else {

                        /* A run of nonzero lengths. */

                        /* Symbol 19: RLE 4 to 5 of any length at a time.  */
                        while ((run_end - run_start) >= 4) {
                                extra_bits = (run_end - run_start) > 4;
                                delta = prev_lens[run_start] - len;
                                if (delta < 0)
                                        delta += 17;
                                precode_freqs[19]++;
                                precode_freqs[delta]++;
                                *itemptr++ = 19 | (extra_bits << 5) | (delta << 6);
                                run_start += 4 + extra_bits;
                        }
                }

                /* Output any remaining lengths without RLE.  */
                while (run_start != run_end) {
                        delta = prev_lens[run_start] - len;
                        if (delta < 0)
                                delta += 17;
                        precode_freqs[delta]++;
                        *itemptr++ = delta;
                        run_start++;
                }
        }

        return itemptr - precode_items;
}

/******************************************************************************/
/*                          Outputting compressed data                        */
/*----------------------------------------------------------------------------*/

/*
 * Output a Huffman code in the compressed form used in LZX.
 *
 * The Huffman code is represented in the output as a logical series of codeword
 * lengths from which the Huffman code, which must be in canonical form, can be
 * reconstructed.
 *
 * The codeword lengths are themselves compressed using a separate Huffman code,
 * the "precode", which contains a symbol for each possible codeword length in
 * the larger code as well as several special symbols to represent repeated
 * codeword lengths (a form of run-length encoding).  The precode is itself
 * constructed in canonical form, and its codeword lengths are represented
 * literally in 20 4-bit fields that immediately precede the compressed codeword
 * lengths of the larger code.
 *
 * Furthermore, the codeword lengths of the larger code are actually represented
 * as deltas from the codeword lengths of the corresponding code in the previous
 * block.
 *
 * @os:
 *        Bitstream to which to write the compressed Huffman code.
 * @lens:
 *        The codeword lengths, indexed by symbol, in the Huffman code.
 * @prev_lens:
 *        The codeword lengths, indexed by symbol, in the corresponding Huffman
 *        code in the previous block, or all zeroes if this is the first block.
 * @num_lens:
 *        The number of symbols in the Huffman code.
 */
static void
lzx_write_compressed_code(struct lzx_output_bitstream *os,
                          const uint8_t * restrict lens,
                          const uint8_t * restrict prev_lens,
                          unsigned num_lens)
{
        uint32_t precode_freqs[LZX_PRECODE_NUM_SYMBOLS];
        uint8_t precode_lens[LZX_PRECODE_NUM_SYMBOLS];
        uint32_t precode_codewords[LZX_PRECODE_NUM_SYMBOLS];
        unsigned *precode_items = (unsigned *)alloca(sizeof(unsigned) * num_lens);
        unsigned num_precode_items;
        unsigned precode_item;
        unsigned precode_sym;
        unsigned i;
        uint8_t saved = lens[num_lens];
        *(uint8_t *)(lens + num_lens) = 0x80;

        for (i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++)
                precode_freqs[i] = 0;

        /* Compute the "items" (RLE / literal tokens and extra bits) with which
         * the codeword lengths in the larger code will be output.  */
        num_precode_items = lzx_compute_precode_items(lens,
                                                      prev_lens,
                                                      precode_freqs,
                                                      precode_items);

        /* Build the precode.  */
        STATIC_ASSERT_STMT(PRE_CODEWORD_LIMIT >= 5 &&
                      PRE_CODEWORD_LIMIT <= LZX_MAX_PRE_CODEWORD_LEN);
        make_canonical_huffman_code(LZX_PRECODE_NUM_SYMBOLS, PRE_CODEWORD_LIMIT,
                                    precode_freqs, precode_lens,
                                    precode_codewords);

        /* Output the lengths of the codewords in the precode.  */
        for (i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++)
                lzx_write_bits(os, precode_lens[i], LZX_PRECODE_ELEMENT_SIZE);

        /* Output the encoded lengths of the codewords in the larger code.  */
        for (i = 0; i < num_precode_items; i++) {
                precode_item = precode_items[i];
                precode_sym = precode_item & 0x1F;
                lzx_add_bits(os, precode_codewords[precode_sym],
                             precode_lens[precode_sym]);
                if (precode_sym >= 17) {
                        if (precode_sym == 17) {
                                lzx_add_bits(os, precode_item >> 5, 4);
                        } else if (precode_sym == 18) {
                                lzx_add_bits(os, precode_item >> 5, 5);
                        } else {
                                lzx_add_bits(os, (precode_item >> 5) & 1, 1);
                                precode_sym = precode_item >> 6;
                                lzx_add_bits(os, precode_codewords[precode_sym],
                                             precode_lens[precode_sym]);
                        }
                }
                STATIC_ASSERT_STMT(CAN_BUFFER(2 * PRE_CODEWORD_LIMIT + 1));
                lzx_flush_bits(os, 2 * PRE_CODEWORD_LIMIT + 1);
        }

        *(uint8_t *)(lens + num_lens) = saved;
}

/*
 * Write all matches and literal bytes (which were precomputed) in an LZX
 * compressed block to the output bitstream in the final compressed
 * representation.
 *
 * @os
 *        The output bitstream.
 * @block_type
 *        The chosen type of the LZX compressed block (LZX_BLOCKTYPE_ALIGNED or
 *        LZX_BLOCKTYPE_VERBATIM).
 * @block_data
 *        The uncompressed data of the block.
 * @sequences
 *        The matches and literals to output, given as a series of sequences.
 * @codes
 *        The main, length, and aligned offset Huffman codes for the block.
 */
static void
lzx_write_sequences(struct lzx_output_bitstream *os, int block_type,
                    const uint8_t *block_data, const struct lzx_sequence sequences[],
                    const struct lzx_codes *codes)
{
        const struct lzx_sequence *seq = sequences;
        unsigned min_aligned_offset_slot;

        if (block_type == LZX_BLOCKTYPE_ALIGNED)
                min_aligned_offset_slot = LZX_MIN_ALIGNED_OFFSET_SLOT;
        else
                min_aligned_offset_slot = LZX_MAX_OFFSET_SLOTS;

        for (;;) {
                /* Output the next sequence.  */

                uint32_t litrunlen = seq->litrunlen_and_matchlen >> SEQ_MATCHLEN_BITS;
                unsigned matchlen = seq->litrunlen_and_matchlen & SEQ_MATCHLEN_MASK;
                STATIC_ASSERT((uint32_t)~SEQ_MATCHLEN_MASK >> SEQ_MATCHLEN_BITS >=
                              SOFT_MAX_BLOCK_SIZE);
                uint32_t adjusted_offset;
                unsigned main_symbol;
                unsigned offset_slot;
                unsigned num_extra_bits;
                uint32_t extra_bits;

                /* Output the literal run of the sequence.  */

                if (litrunlen) {  /* Is the literal run nonempty?  */

                        /* Verify optimization is enabled on 64-bit  */
                        STATIC_ASSERT(WORDBITS < 64 ||
                                      CAN_BUFFER(3 * MAIN_CODEWORD_LIMIT));

                        if (CAN_BUFFER(3 * MAIN_CODEWORD_LIMIT)) {

                                /* 64-bit: write 3 literals at a time.  */
                                while (litrunlen >= 3) {
                                        unsigned lit0 = block_data[0];
                                        unsigned lit1 = block_data[1];
                                        unsigned lit2 = block_data[2];
                                        lzx_add_bits(os, codes->codewords.main[lit0],
                                                     codes->lens.main[lit0]);
                                        lzx_add_bits(os, codes->codewords.main[lit1],
                                                     codes->lens.main[lit1]);
                                        lzx_add_bits(os, codes->codewords.main[lit2],
                                                     codes->lens.main[lit2]);
                                        lzx_flush_bits(os, 3 * MAIN_CODEWORD_LIMIT);
                                        block_data += 3;
                                        litrunlen -= 3;
                                }
                                if (litrunlen--) {
                                        unsigned lit = *block_data++;
                                        lzx_add_bits(os, codes->codewords.main[lit],
                                                     codes->lens.main[lit]);
                                        if (litrunlen--) {
                                                unsigned lit = *block_data++;
                                                lzx_add_bits(os, codes->codewords.main[lit],
                                                             codes->lens.main[lit]);
                                                lzx_flush_bits(os, 2 * MAIN_CODEWORD_LIMIT);
                                        } else {
                                                lzx_flush_bits(os, 1 * MAIN_CODEWORD_LIMIT);
                                        }
                                }
                        } else {
                                /* 32-bit: write 1 literal at a time.  */
                                do {
                                        unsigned lit = *block_data++;
                                        lzx_add_bits(os, codes->codewords.main[lit],
                                                     codes->lens.main[lit]);
                                        lzx_flush_bits(os, MAIN_CODEWORD_LIMIT);
                                } while (--litrunlen);
                        }
                }

                /* Was this the last literal run?  */
                if (matchlen == 0)
                        return;

                /* Nope; output the match.  */

                block_data += matchlen;

                adjusted_offset = seq->adjusted_offset_and_mainsym >> SEQ_MAINSYM_BITS;
                main_symbol = seq->adjusted_offset_and_mainsym & SEQ_MAINSYM_MASK;

                offset_slot = (main_symbol - LZX_NUM_CHARS) / LZX_NUM_LEN_HEADERS;
                num_extra_bits = lzx_extra_offset_bits[offset_slot];
                extra_bits = adjusted_offset - (lzx_offset_slot_base[offset_slot] +
                                                LZX_OFFSET_ADJUSTMENT);

        #define MAX_MATCH_BITS (MAIN_CODEWORD_LIMIT +                \
                                LENGTH_CODEWORD_LIMIT +                \
                                LZX_MAX_NUM_EXTRA_BITS -        \
                                LZX_NUM_ALIGNED_OFFSET_BITS +        \
                                ALIGNED_CODEWORD_LIMIT)

                /* Verify optimization is enabled on 64-bit  */
                STATIC_ASSERT_STMT(WORDBITS < 64 || CAN_BUFFER(MAX_MATCH_BITS));

                /* Output the main symbol for the match.  */

                lzx_add_bits(os, codes->codewords.main[main_symbol],
                             codes->lens.main[main_symbol]);
                if (!CAN_BUFFER(MAX_MATCH_BITS))
                        lzx_flush_bits(os, MAIN_CODEWORD_LIMIT);

                /* If needed, output the length symbol for the match.  */

                if (matchlen >= LZX_MIN_SECONDARY_LEN) {
                        lzx_add_bits(os, codes->codewords.len[matchlen -
                                                              LZX_MIN_SECONDARY_LEN],
                                     codes->lens.len[matchlen -
                                                     LZX_MIN_SECONDARY_LEN]);
                        if (!CAN_BUFFER(MAX_MATCH_BITS))
                                lzx_flush_bits(os, LENGTH_CODEWORD_LIMIT);
                }

                /* Output the extra offset bits for the match.  In aligned
                 * offset blocks, the lowest 3 bits of the adjusted offset are
                 * Huffman-encoded using the aligned offset code, provided that
                 * there are at least extra 3 offset bits required.  All other
                 * extra offset bits are output verbatim.  */

                if (offset_slot >= min_aligned_offset_slot) {

                        lzx_add_bits(os, extra_bits >> LZX_NUM_ALIGNED_OFFSET_BITS,
                                     num_extra_bits - LZX_NUM_ALIGNED_OFFSET_BITS);
                        if (!CAN_BUFFER(MAX_MATCH_BITS))
                                lzx_flush_bits(os, LZX_MAX_NUM_EXTRA_BITS -
                                                   LZX_NUM_ALIGNED_OFFSET_BITS);

                        lzx_add_bits(os, codes->codewords.aligned[adjusted_offset &
                                                                  LZX_ALIGNED_OFFSET_BITMASK],
                                     codes->lens.aligned[adjusted_offset &
                                                         LZX_ALIGNED_OFFSET_BITMASK]);
                        if (!CAN_BUFFER(MAX_MATCH_BITS))
                                lzx_flush_bits(os, ALIGNED_CODEWORD_LIMIT);
                } else {
                        STATIC_ASSERT(CAN_BUFFER(LZX_MAX_NUM_EXTRA_BITS));

                        lzx_add_bits(os, extra_bits, num_extra_bits);
                        if (!CAN_BUFFER(MAX_MATCH_BITS))
                                lzx_flush_bits(os, LZX_MAX_NUM_EXTRA_BITS);
                }

                if (CAN_BUFFER(MAX_MATCH_BITS))
                        lzx_flush_bits(os, MAX_MATCH_BITS);

                /* Advance to the next sequence.  */
                seq++;
        }
}

static void
lzx_write_header(uint32_t e8_file_size, struct lzx_output_bitstream *os)
{
        if (e8_file_size == 0) {
                lzx_write_bits(os, 0, 1);
        } else {
                lzx_write_bits(os, 1, 1);
                lzx_write_bits(os, (e8_file_size >> 16) & 0xffffu, 16);
                lzx_write_bits(os, e8_file_size & 0xffffu, 16);
        }
}

static void
lzx_write_compressed_block(const uint8_t *block_begin,
                           int block_type,
                           uint32_t block_size,
                           enum liblzx_variant variant,
                           unsigned window_order,
                           unsigned num_main_syms,
                           const struct lzx_sequence sequences[],
                           const struct lzx_codes * codes,
                           const struct lzx_lens * prev_lens,
                           struct lzx_output_bitstream * os)
{
        /* The first three bits indicate the type of block and are one of the
         * LZX_BLOCKTYPE_* constants.  */
        lzx_write_bits(os, block_type, 3);

        /*
         * Output the block size.
         *
         * The original LZX format encoded the block size in 24 bits.  However,
         * the LZX format used in WIM archives uses 1 bit to specify whether the
         * block has the default size of 32768 bytes, then optionally 16 bits to
         * specify a non-default size.  This works fine for Microsoft's WIM
         * software (WIMGAPI), which never compresses more than 32768 bytes at a
         * time with LZX.  However, as an extension, our LZX compressor supports
         * compressing up to 2097152 bytes, with a corresponding increase in
         * window size.  It is possible for blocks in these larger buffers to
         * exceed 65535 bytes; such blocks cannot have their size represented in
         * 16 bits.
         *
         * The chosen solution was to use 24 bits for the block size when
         * possibly required --- specifically, when the compressor has been
         * allocated to be capable of compressing more than 32768 bytes at once
         * (which also causes the number of main symbols to be increased).
         */
        if (variant == LIBLZX_VARIANT_WIM) {
                if (block_size == LZX_DEFAULT_BLOCK_SIZE) {
                        lzx_write_bits(os, 1, 1);
                } else {
                        lzx_write_bits(os, 0, 1);

                        if (window_order >= 16)
                                lzx_write_bits(os, block_size >> 16, 8);

                        lzx_write_bits(os, block_size & 0xFFFF, 16);
                }
        } else {
                lzx_write_bits(os, block_size >> 16, 8);
                lzx_write_bits(os, block_size & 0xFFFF, 16);
        }

        /* If it's an aligned offset block, output the aligned offset code.  */
        if (block_type == LZX_BLOCKTYPE_ALIGNED) {
                for (int i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
                        lzx_write_bits(os, codes->lens.aligned[i],
                                       LZX_ALIGNEDCODE_ELEMENT_SIZE);
                }
        }

        /* Output the main code (two parts).  */
        lzx_write_compressed_code(os, codes->lens.main,
                                  prev_lens->main,
                                  LZX_NUM_CHARS);
        lzx_write_compressed_code(os, codes->lens.main + LZX_NUM_CHARS,
                                  prev_lens->main + LZX_NUM_CHARS,
                                  num_main_syms - LZX_NUM_CHARS);

        /* Output the length code.  */
        lzx_write_compressed_code(os, codes->lens.len,
                                  prev_lens->len,
                                  LZX_LENCODE_NUM_SYMBOLS);

        /* Output the compressed matches and literals.  */
        lzx_write_sequences(os, block_type, block_begin, sequences, codes);
}

/*
 * Given the frequencies of symbols in an LZX-compressed block and the
 * corresponding Huffman codes, return LZX_BLOCKTYPE_ALIGNED or
 * LZX_BLOCKTYPE_VERBATIM if an aligned offset or verbatim block, respectively,
 * will take fewer bits to output.
 */
static int
lzx_choose_verbatim_or_aligned(const struct lzx_freqs * freqs,
                               const struct lzx_codes * codes)
{
        uint32_t verbatim_cost = 0;
        uint32_t aligned_cost = 0;

        /* A verbatim block requires 3 bits in each place that an aligned offset
         * symbol would be used in an aligned offset block.  */
        for (unsigned i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
                verbatim_cost += LZX_NUM_ALIGNED_OFFSET_BITS * freqs->aligned[i];
                aligned_cost += codes->lens.aligned[i] * freqs->aligned[i];
        }

        /* Account for the cost of sending the codeword lengths of the aligned
         * offset code.  */
        aligned_cost += LZX_ALIGNEDCODE_ELEMENT_SIZE *
                        LZX_ALIGNEDCODE_NUM_SYMBOLS;

        if (aligned_cost < verbatim_cost)
                return LZX_BLOCKTYPE_ALIGNED;
        else
                return LZX_BLOCKTYPE_VERBATIM;
}

/*
 * Flush an LZX block:
 *
 * 1. Build the Huffman codes.
 * 2. Decide whether to output the block as VERBATIM or ALIGNED.
 * 3. Write the block.
 * 4. Swap the indices of the current and previous Huffman codes.
 *
 * Note: we never output UNCOMPRESSED blocks.  This probably should be
 * implemented sometime, but it doesn't make much difference.
 */
static void
lzx_flush_block(struct liblzx_compressor *c, struct lzx_output_bitstream *os,
                const uint8_t *block_begin, uint32_t block_size, uint32_t seq_idx)
{
        int block_type;

        lzx_build_huffman_codes(c);

        block_type = lzx_choose_verbatim_or_aligned(&c->freqs,
                                                    &c->codes[c->codes_index]);

        if (c->variant != LIBLZX_VARIANT_WIM) {
                if (c->first_block) {
                        lzx_write_header(c->e8_file_size, os);
                        c->first_block = false;
                }
        }

        lzx_write_compressed_block(block_begin,
                                   block_type,
                                   block_size,
                                   c->variant,
                                   c->window_order,
                                   c->num_main_syms,
                                   &c->chosen_sequences[seq_idx],
                                   &c->codes[c->codes_index],
                                   &c->codes[c->codes_index ^ 1].lens,
                                   os);
        c->codes_index ^= 1;
}

/******************************************************************************/
/*                          Block splitting algorithm                         */
/*----------------------------------------------------------------------------*/

/*
 * The problem of block splitting is to decide when it is worthwhile to start a
 * new block with new entropy codes.  There is a theoretically optimal solution:
 * recursively consider every possible block split, considering the exact cost
 * of each block, and choose the minimum cost approach.  But this is far too
 * slow.  Instead, as an approximation, we can count symbols and after every N
 * symbols, compare the expected distribution of symbols based on the previous
 * data with the actual distribution.  If they differ "by enough", then start a
 * new block.
 *
 * As an optimization and heuristic, we don't distinguish between every symbol
 * but rather we combine many symbols into a single "observation type".  For
 * literals we only look at the high bits and low bits, and for matches we only
 * look at whether the match is long or not.  The assumption is that for typical
 * "real" data, places that are good block boundaries will tend to be noticeable
 * based only on changes in these aggregate frequencies, without looking for
 * subtle differences in individual symbols.  For example, a change from ASCII
 * bytes to non-ASCII bytes, or from few matches (generally less compressible)
 * to many matches (generally more compressible), would be easily noticed based
 * on the aggregates.
 *
 * For determining whether the frequency distributions are "different enough" to
 * start a new block, the simply heuristic of splitting when the sum of absolute
 * differences exceeds a constant seems to be good enough.
 *
 * Finally, for an approximation, it is not strictly necessary that the exact
 * symbols being used are considered.  With "near-optimal parsing", for example,
 * the actual symbols that will be used are unknown until after the block
 * boundary is chosen and the block has been optimized.  Since the final choices
 * cannot be used, we can use preliminary "greedy" choices instead.
 */

/* Initialize the block split statistics when starting a new block. */
static void
lzx_init_block_split_stats(struct lzx_block_split_stats *stats)
{
        memset(stats, 0, sizeof(*stats));
}

/* Literal observation.  Heuristic: use the top 2 bits and low 1 bits of the
 * literal, for 8 possible literal observation types.  */
static attrib_forceinline void
lzx_observe_literal(struct lzx_block_split_stats *stats, uint8_t lit)
{
        stats->new_observations[((lit >> 5) & 0x6) | (lit & 1)]++;
        stats->num_new_observations++;
}

/* Match observation.  Heuristic: use one observation type for "short match" and
 * one observation type for "long match".  */
static attrib_forceinline void
lzx_observe_match(struct lzx_block_split_stats *stats, unsigned length)
{
        stats->new_observations[NUM_LITERAL_OBSERVATION_TYPES + (length >= 5)]++;
        stats->num_new_observations++;
}

static bool
lzx_should_end_block(struct lzx_block_split_stats *stats)
{
        if (stats->num_observations > 0) {

                /* Note: to avoid slow divisions, we do not divide by
                 * 'num_observations', but rather do all math with the numbers
                 * multiplied by 'num_observations'. */
                uint32_t total_delta = 0;
                for (int i = 0; i < NUM_OBSERVATION_TYPES; i++) {
                        uint32_t expected = stats->observations[i] *
                                       stats->num_new_observations;
                        uint32_t actual = stats->new_observations[i] *
                                     stats->num_observations;
                        uint32_t delta = (actual > expected) ? actual - expected :
                                                          expected - actual;
                        total_delta += delta;
                }

                /* Ready to end the block? */
                if (total_delta >=
                    stats->num_new_observations * 7 / 8 * stats->num_observations)
                        return true;
        }

        for (int i = 0; i < NUM_OBSERVATION_TYPES; i++) {
                stats->num_observations += stats->new_observations[i];
                stats->observations[i] += stats->new_observations[i];
                stats->new_observations[i] = 0;
        }
        stats->num_new_observations = 0;
        return false;
}

/******************************************************************************/
/*                   Slower ("near-optimal") compression algorithm            */
/*----------------------------------------------------------------------------*/

/*
 * Least-recently-used queue for match offsets.
 *
 * This is represented as a 64-bit integer for efficiency.  There are three
 * offsets of 21 bits each.  Bit 64 is garbage.
 */
struct attrib_aligned(8) lzx_lru_queue {
        uint64_t R;
};

#define LZX_QUEUE_OFFSET_SHIFT        21
#define LZX_QUEUE_OFFSET_MASK        (((uint64_t)1 << LZX_QUEUE_OFFSET_SHIFT) - 1)

#define LZX_QUEUE_R0_SHIFT (0 * LZX_QUEUE_OFFSET_SHIFT)
#define LZX_QUEUE_R1_SHIFT (1 * LZX_QUEUE_OFFSET_SHIFT)
#define LZX_QUEUE_R2_SHIFT (2 * LZX_QUEUE_OFFSET_SHIFT)

#define LZX_QUEUE_R0_MASK (LZX_QUEUE_OFFSET_MASK << LZX_QUEUE_R0_SHIFT)
#define LZX_QUEUE_R1_MASK (LZX_QUEUE_OFFSET_MASK << LZX_QUEUE_R1_SHIFT)
#define LZX_QUEUE_R2_MASK (LZX_QUEUE_OFFSET_MASK << LZX_QUEUE_R2_SHIFT)

static attrib_forceinline uint64_t
lzx_lru_queue_R0(struct lzx_lru_queue queue)
{
        return (queue.R >> LZX_QUEUE_R0_SHIFT) & LZX_QUEUE_OFFSET_MASK;
}

static attrib_forceinline uint64_t
lzx_lru_queue_R1(struct lzx_lru_queue queue)
{
        return (queue.R >> LZX_QUEUE_R1_SHIFT) & LZX_QUEUE_OFFSET_MASK;
}

static attrib_forceinline uint64_t
lzx_lru_queue_R2(struct lzx_lru_queue queue)
{
        return (queue.R >> LZX_QUEUE_R2_SHIFT) & LZX_QUEUE_OFFSET_MASK;
}

static attrib_forceinline void
lzx_lru_queue_save(uint32_t * restrict out_queue,
                   const struct lzx_lru_queue * restrict in_queue)
{
        struct lzx_lru_queue queue = *in_queue;
        out_queue[0] = lzx_lru_queue_R0(queue);
        out_queue[1] = lzx_lru_queue_R1(queue);
        out_queue[2] = lzx_lru_queue_R2(queue);
}

static attrib_forceinline void
lzx_lru_queue_load(struct lzx_lru_queue *restrict out_queue,
                   const uint32_t *restrict in_queue)
{
        uint64_t r = 0;
        r |= (uint64_t)(in_queue[0]) << LZX_QUEUE_R0_SHIFT;
        r |= (uint64_t)(in_queue[1]) << LZX_QUEUE_R1_SHIFT;
        r |= (uint64_t)(in_queue[2]) << LZX_QUEUE_R2_SHIFT;
        out_queue->R = r;
}

/* Push a match offset onto the front (most recently used) end of the queue.  */
static attrib_forceinline struct lzx_lru_queue
lzx_lru_queue_push(struct lzx_lru_queue queue, uint32_t offset)
{
        return (struct lzx_lru_queue) {
                .R = (queue.R << LZX_QUEUE_OFFSET_SHIFT) | offset,
        };
}

/* Swap a match offset to the front of the queue.  */
static attrib_forceinline struct lzx_lru_queue
lzx_lru_queue_swap(struct lzx_lru_queue queue, unsigned idx)
{
        unsigned shift = idx * 21;
        const uint64_t mask = LZX_QUEUE_R0_MASK;
        const uint64_t mask_high = mask << shift;

        return (struct lzx_lru_queue) {
                (queue.R & ~(mask | mask_high)) |
                ((queue.R & mask_high) >> shift) |
                ((queue.R & mask) << shift)
        };
}

static attrib_forceinline uint32_t
lzx_walk_item_list(struct liblzx_compressor *c, uint32_t block_size, bool is_16_bit,
                   bool record)
{
        struct lzx_sequence *seq =
                &c->chosen_sequences[ARRAY_LEN(c->chosen_sequences) - 1];
        uint32_t node_idx = block_size;
        uint32_t litrun_end; /* if record=true: end of the current literal run */

        if (record) {
                /* The last sequence has matchlen 0 */
                seq->litrunlen_and_matchlen = 0;
                litrun_end = node_idx;
        }

        for (;;) {
                uint32_t item;
                unsigned matchlen;
                uint32_t adjusted_offset;
                unsigned mainsym;

                /* Tally literals until either a match or the beginning of the
                 * block is reached.  Note: the item in the node at the
                 * beginning of the block (c->optimum_nodes[0]) has all bits
                 * set, causing this loop to end when it is reached. */
                for (;;) {
                        item = c->optimum_nodes[node_idx].item;
                        if (item & OPTIMUM_LEN_MASK)
                                break;
                        c->freqs.main[item >> OPTIMUM_OFFSET_SHIFT]++;
                        node_idx--;
                }

        #if CONSIDER_GAP_MATCHES
                if (item & OPTIMUM_GAP_MATCH) {
                        if (node_idx == 0)
                                break;
                        /* Tally/record the rep0 match after the gap. */
                        matchlen = item & OPTIMUM_LEN_MASK;
                        mainsym = lzx_tally_main_and_lensyms(c, matchlen, 0,
                                                             is_16_bit);
                        if (record) {
                                seq->litrunlen_and_matchlen |=
                                        (litrun_end - node_idx) <<
                                         SEQ_MATCHLEN_BITS;
                                seq--;
                                seq->litrunlen_and_matchlen = matchlen;
                                seq->adjusted_offset_and_mainsym = mainsym;
                                litrun_end = node_idx - matchlen;
                        }

                        /* Tally the literal in the gap. */
                        c->freqs.main[(uint8_t)(item >> OPTIMUM_OFFSET_SHIFT)]++;

                        /* Fall through and tally the match before the gap.
                         * (It was temporarily saved in the 'cost' field of the
                         * previous node, which was free to reuse.) */
                        item = c->optimum_nodes[--node_idx].cost;
                        node_idx -= matchlen;
                }
        #else /* CONSIDER_GAP_MATCHES */
                if (node_idx == 0)
                        break;
        #endif /* !CONSIDER_GAP_MATCHES */

                /* Tally/record a match. */
                matchlen = item & OPTIMUM_LEN_MASK;
                adjusted_offset = item >> OPTIMUM_OFFSET_SHIFT;
                mainsym = lzx_tally_main_and_lensyms(c, matchlen,
                                                     adjusted_offset,
                                                     is_16_bit);
                if (adjusted_offset >= LZX_MIN_ALIGNED_OFFSET +
                                       LZX_OFFSET_ADJUSTMENT)
                        c->freqs.aligned[adjusted_offset &
                                         LZX_ALIGNED_OFFSET_BITMASK]++;
                if (record) {
                        seq->litrunlen_and_matchlen |=
                                (litrun_end - node_idx) << SEQ_MATCHLEN_BITS;
                        seq--;
                        seq->litrunlen_and_matchlen = matchlen;
                        seq->adjusted_offset_and_mainsym =
                                (adjusted_offset << SEQ_MAINSYM_BITS) | mainsym;
                        litrun_end = node_idx - matchlen;
                }
                node_idx -= matchlen;
        }

        /* Record the literal run length for the first sequence. */
        if (record) {
                seq->litrunlen_and_matchlen |=
                        (litrun_end - node_idx) << SEQ_MATCHLEN_BITS;
        }

        /* Return the index in chosen_sequences at which the sequences begin. */
        return seq - &c->chosen_sequences[0];
}

/*
 * Given the minimum-cost path computed through the item graph for the current
 * block, walk the path and count how many of each symbol in each Huffman-coded
 * alphabet would be required to output the items (matches and literals) along
 * the path.
 *
 * Note that the path will be walked backwards (from the end of the block to the
 * beginning of the block), but this doesn't matter because this function only
 * computes frequencies.
 */
static attrib_forceinline void
lzx_tally_item_list(struct liblzx_compressor *c, uint32_t block_size, bool is_16_bit)
{
        lzx_walk_item_list(c, block_size, is_16_bit, false);
}

/*
 * Like lzx_tally_item_list(), but this function also generates the list of
 * lzx_sequences for the minimum-cost path and writes it to c->chosen_sequences,
 * ready to be output to the bitstream after the Huffman codes are computed.
 * The lzx_sequences will be written to decreasing memory addresses as the path
 * is walked backwards, which means they will end up in the expected
 * first-to-last order.  The return value is the index in c->chosen_sequences at
 * which the lzx_sequences begin.
 */
static attrib_forceinline uint32_t
lzx_record_item_list(struct liblzx_compressor *c, uint32_t block_size, bool is_16_bit)
{
        return lzx_walk_item_list(c, block_size, is_16_bit, true);
}

/*
 * Find an inexpensive path through the graph of possible match/literal choices
 * for the current block.  The nodes of the graph are
 * c->optimum_nodes[0...block_size].  They correspond directly to the bytes in
 * the current block, plus one extra node for end-of-block.  The edges of the
 * graph are matches and literals.  The goal is to find the minimum cost path
 * from 'c->optimum_nodes[0]' to 'c->optimum_nodes[block_size]', given the cost
 * model 'c->costs'.
 *
 * The algorithm works forwards, starting at 'c->optimum_nodes[0]' and
 * proceeding forwards one node at a time.  At each node, a selection of matches
 * (len >= 2), as well as the literal byte (len = 1), is considered.  An item of
 * length 'len' provides a new path to reach the node 'len' bytes later.  If
 * such a path is the lowest cost found so far to reach that later node, then
 * that later node is updated with the new cost and the "arrival" which provided
 * that cost.
 *
 * Note that although this algorithm is based on minimum cost path search, due
 * to various simplifying assumptions the result is not guaranteed to be the
 * true minimum cost, or "optimal", path over the graph of all valid LZX
 * representations of this block.
 *
 * Also, note that because of the presence of the recent offsets queue (which is
 * a type of adaptive state), the algorithm cannot work backwards and compute
 * "cost to end" instead of "cost to beginning".  Furthermore, the way the
 * algorithm handles this adaptive state in the "minimum cost" parse is actually
 * only an approximation.  It's possible for the globally optimal, minimum cost
 * path to contain a prefix, ending at a position, where that path prefix is
 * *not* the minimum cost path to that position.  This can happen if such a path
 * prefix results in a different adaptive state which results in lower costs
 * later.  The algorithm does not solve this problem in general; it only looks
 * one step ahead, with the exception of special consideration for "gap
 * matches".
 */
static attrib_forceinline struct lzx_lru_queue
lzx_find_min_cost_path(struct liblzx_compressor * const restrict c,
                       const uint8_t * const restrict block_begin,
                       const uint32_t block_size,
                       const struct lzx_lru_queue initial_queue,
                       bool is_16_bit)
{
        struct lzx_optimum_node *cur_node = c->optimum_nodes;
        struct lzx_optimum_node * const end_node = cur_node + block_size;
        struct lz_match *cache_ptr = c->match_cache;
        const uint8_t *in_next = block_begin;
        const uint8_t * const block_end = block_begin + block_size;

        /*
         * Instead of storing the match offset LRU queues in the
         * 'lzx_optimum_node' structures, we save memory (and cache lines) by
         * storing them in a smaller array.  This works because the algorithm
         * only requires a limited history of the adaptive state.  Once a given
         * state is more than LZX_MAX_MATCH_LEN bytes behind the current node
         * (more if gap match consideration is enabled; we just round up to 512
         * so it's a power of 2), it is no longer needed.
         *
         * The QUEUE() macro finds the queue for the given node.  This macro has
         * been optimized by taking advantage of 'struct lzx_lru_queue' and
         * 'struct lzx_optimum_node' both being 8 bytes in size and alignment.
         */
        struct lzx_lru_queue queues[512];
        STATIC_ASSERT(ARRAY_LEN(queues) >= LZX_MAX_MATCH_LEN + 1);
        STATIC_ASSERT(sizeof(c->optimum_nodes[0]) == sizeof(queues[0]));
#define QUEUE(node) \
        (*(struct lzx_lru_queue *)((char *)queues + \
                        ((uintptr_t)(node) % (ARRAY_LEN(queues) * sizeof(queues[0])))))
        /*(queues[(uintptr_t)(node) / sizeof(*(node)) % ARRAY_LEN(queues)])*/

#if CONSIDER_GAP_MATCHES
        uint32_t matches_before_gap[ARRAY_LEN(queues)];
#define MATCH_BEFORE_GAP(node) \
        (matches_before_gap[(uintptr_t)(node) / sizeof(*(node)) % \
                            ARRAY_LEN(matches_before_gap)])
#endif

        /*
         * Initially, the cost to reach each node is "infinity".
         *
         * The first node actually should have cost 0, but "infinity"
         * (0xFFFFFFFF) works just as well because it immediately overflows.
         *
         * The following statement also intentionally sets the 'item' of the
         * first node, which would otherwise have no meaning, to 0xFFFFFFFF for
         * use as a sentinel.  See lzx_walk_item_list().
         */
        memset(c->optimum_nodes, 0xFF,
               (block_size + 1) * sizeof(c->optimum_nodes[0]));

        /* Initialize the recent offsets queue for the first node. */
        QUEUE(cur_node) = initial_queue;

        do { /* For each node in the block in position order... */

                unsigned num_matches;
                unsigned literal;
                uint32_t cost;

                /*
                 * A selection of matches for the block was already saved in
                 * memory so that we don't have to run the uncompressed data
                 * through the matchfinder on every optimization pass.  However,
                 * we still search for repeat offset matches during each
                 * optimization pass because we cannot predict the state of the
                 * recent offsets queue.  But as a heuristic, we don't bother
                 * searching for repeat offset matches if the general-purpose
                 * matchfinder failed to find any matches.
                 *
                 * Note that a match of length n at some offset implies there is
                 * also a match of length l for LZX_MIN_MATCH_LEN <= l <= n at
                 * that same offset.  In other words, we don't necessarily need
                 * to use the full length of a match.  The key heuristic that
                 * saves a significicant amount of time is that for each
                 * distinct length, we only consider the smallest offset for
                 * which that length is available.  This heuristic also applies
                 * to repeat offsets, which we order specially: R0 < R1 < R2 <
                 * any explicit offset.  Of course, this heuristic may be
                 * produce suboptimal results because offset slots in LZX are
                 * subject to entropy encoding, but in practice this is a useful
                 * heuristic.
                 */

                num_matches = cache_ptr->length;
                cache_ptr++;

                if (num_matches) {
                        struct lz_match *end_matches = cache_ptr + num_matches;
                        unsigned next_len = LZX_MIN_MATCH_LEN;
                        unsigned max_len =
                            min_uint(block_end - in_next, LZX_MAX_MATCH_LEN);
                        const uint8_t *matchptr;

                        /* Consider rep0 matches. */
                        matchptr = in_next - lzx_lru_queue_R0(QUEUE(cur_node));
                        if (load_u16_unaligned(matchptr) != load_u16_unaligned(in_next))
                                goto rep0_done;
                        STATIC_ASSERT_STMT(LZX_MIN_MATCH_LEN == 2);
                        do {
                                uint32_t cost = cur_node->cost +
                                           c->costs.match_cost[0][
                                                        next_len - LZX_MIN_MATCH_LEN];
                                if (cost <= (cur_node + next_len)->cost) {
                                        (cur_node + next_len)->cost = cost;
                                        (cur_node + next_len)->item =
                                                (0 << OPTIMUM_OFFSET_SHIFT) | next_len;
                                }
                                if (unlikely(++next_len > max_len)) {
                                        cache_ptr = end_matches;
                                        goto done_matches;
                                }
                        } while (in_next[next_len - 1] == matchptr[next_len - 1]);

                rep0_done:

                        /* Consider rep1 matches. */
                        matchptr = in_next - lzx_lru_queue_R1(QUEUE(cur_node));
                        if (load_u16_unaligned(matchptr) != load_u16_unaligned(in_next))
                                goto rep1_done;
                        if (matchptr[next_len - 1] != in_next[next_len - 1])
                                goto rep1_done;
                        for (unsigned len = 2; len < next_len - 1; len++)
                                if (matchptr[len] != in_next[len])
                                        goto rep1_done;
                        do {
                                uint32_t cost = cur_node->cost +
                                           c->costs.match_cost[1][
                                                        next_len - LZX_MIN_MATCH_LEN];
                                if (cost <= (cur_node + next_len)->cost) {
                                        (cur_node + next_len)->cost = cost;
                                        (cur_node + next_len)->item =
                                                (1 << OPTIMUM_OFFSET_SHIFT) | next_len;
                                }
                                if (unlikely(++next_len > max_len)) {
                                        cache_ptr = end_matches;
                                        goto done_matches;
                                }
                        } while (in_next[next_len - 1] == matchptr[next_len - 1]);

                rep1_done:

                        /* Consider rep2 matches. */
                        matchptr = in_next - lzx_lru_queue_R2(QUEUE(cur_node));
                        if (load_u16_unaligned(matchptr) != load_u16_unaligned(in_next))
                                goto rep2_done;
                        if (matchptr[next_len - 1] != in_next[next_len - 1])
                                goto rep2_done;
                        for (unsigned len = 2; len < next_len - 1; len++)
                                if (matchptr[len] != in_next[len])
                                        goto rep2_done;
                        do {
                                uint32_t cost = cur_node->cost +
                                           c->costs.match_cost[2][
                                                        next_len - LZX_MIN_MATCH_LEN];
                                if (cost <= (cur_node + next_len)->cost) {
                                        (cur_node + next_len)->cost = cost;
                                        (cur_node + next_len)->item =
                                                (2 << OPTIMUM_OFFSET_SHIFT) | next_len;
                                }
                                if (unlikely(++next_len > max_len)) {
                                        cache_ptr = end_matches;
                                        goto done_matches;
                                }
                        } while (in_next[next_len - 1] == matchptr[next_len - 1]);

                rep2_done:

                        while (next_len > cache_ptr->length)
                                if (++cache_ptr == end_matches)
                                        goto done_matches;

                        /* Consider explicit offset matches. */
                        for (;;) {
                                uint32_t offset = cache_ptr->offset;
                                uint32_t adjusted_offset = offset + LZX_OFFSET_ADJUSTMENT;
                                unsigned offset_slot = lzx_get_offset_slot(c, adjusted_offset, is_16_bit);
                                uint32_t base_cost = cur_node->cost;
                                uint32_t cost;

                        #if CONSIDER_ALIGNED_COSTS
                                if (offset >= LZX_MIN_ALIGNED_OFFSET)
                                        base_cost += c->costs.aligned[adjusted_offset &
                                                                      LZX_ALIGNED_OFFSET_BITMASK];
                        #endif
                                do {
                                        cost = base_cost +
                                               c->costs.match_cost[offset_slot][
                                                                next_len - LZX_MIN_MATCH_LEN];
                                        if (cost < (cur_node + next_len)->cost) {
                                                (cur_node + next_len)->cost = cost;
                                                (cur_node + next_len)->item =
                                                        (adjusted_offset << OPTIMUM_OFFSET_SHIFT) | next_len;
                                        }
                                } while (++next_len <= cache_ptr->length);

                                if (++cache_ptr == end_matches) {
                                #if CONSIDER_GAP_MATCHES
                                        /* Also consider the longest explicit
                                         * offset match as a "gap match": match
                                         * + lit + rep0. */
                                        int32_t remaining = (block_end - in_next) - (int32_t)next_len;
                                        if (likely(remaining >= 2)) {
                                                const uint8_t *strptr = in_next + next_len;
                                                const uint8_t *matchptr = strptr - offset;
                                                if (load_u16_unaligned(strptr) == load_u16_unaligned(matchptr)) {
                                                        STATIC_ASSERT(ARRAY_LEN(queues) - LZX_MAX_MATCH_LEN - 2 >= 250);
                                                        STATIC_ASSERT(ARRAY_LEN(queues) == ARRAY_LEN(matches_before_gap));
                                                        unsigned limit = min_uint(remaining,
                                                                             min_uint(ARRAY_LEN(queues) - LZX_MAX_MATCH_LEN - 2,
                                                                                 LZX_MAX_MATCH_LEN));
                                                        unsigned rep0_len = lz_extend(strptr, matchptr, 2, limit);
                                                        uint8_t lit = strptr[-1];
                                                        unsigned total_len = next_len + rep0_len;
                                                        cost += c->costs.main[lit] +
                                                                c->costs.match_cost[0][rep0_len - LZX_MIN_MATCH_LEN];
                                                        if (cost < (cur_node + total_len)->cost) {
                                                                (cur_node + total_len)->cost = cost;
                                                                (cur_node + total_len)->item =
                                                                        OPTIMUM_GAP_MATCH |
                                                                        ((uint32_t)lit << OPTIMUM_OFFSET_SHIFT) |
                                                                        rep0_len;
                                                                MATCH_BEFORE_GAP(cur_node + total_len) =
                                                                        (adjusted_offset << OPTIMUM_OFFSET_SHIFT) |
                                                                        (next_len - 1);
                                                        }
                                                }
                                        }
                                #endif /* CONSIDER_GAP_MATCHES */
                                        break;
                                }
                        }
                }

        done_matches:

                /* Consider coding a literal.

                 * To avoid an extra branch, actually checking the preferability
                 * of coding the literal is integrated into the queue update
                 * code below. */
                literal = *in_next++;
                cost = cur_node->cost + c->costs.main[literal];

                /* Advance to the next position. */
                cur_node++;

                /* The lowest-cost path to the current position is now known.
                 * Finalize the recent offsets queue that results from taking
                 * this lowest-cost path. */

                if (cost <= cur_node->cost) {
                        /* Literal: queue remains unchanged. */
                        cur_node->cost = cost;
                        cur_node->item = (uint32_t)literal << OPTIMUM_OFFSET_SHIFT;
                        QUEUE(cur_node) = QUEUE(cur_node - 1);
                } else {
                        /* Match: queue update is needed. */
                        unsigned len = cur_node->item & OPTIMUM_LEN_MASK;
                #if CONSIDER_GAP_MATCHES
                        int32_t adjusted_offset = (int32_t)cur_node->item >> OPTIMUM_OFFSET_SHIFT;
                        STATIC_ASSERT(OPTIMUM_GAP_MATCH == 0x80000000); /* assuming sign extension */
                #else
                        uint32_t adjusted_offset = cur_node->item >> OPTIMUM_OFFSET_SHIFT;
                #endif

                        if (adjusted_offset >= LZX_NUM_RECENT_OFFSETS) {
                                /* Explicit offset match: insert offset at front. */
                                QUEUE(cur_node) =
                                        lzx_lru_queue_push(QUEUE(cur_node - len),
                                                           adjusted_offset - LZX_OFFSET_ADJUSTMENT);
                        }
                #if CONSIDER_GAP_MATCHES
                        else if (adjusted_offset < 0) {
                                /* "Gap match": Explicit offset match, then a
                                 * literal, then rep0 match.  Save the explicit
                                 * offset match information in the cost field of
                                 * the previous node, which isn't needed
                                 * anymore.  Then insert the offset at the front
                                 * of the queue. */
                                uint32_t match_before_gap = MATCH_BEFORE_GAP(cur_node);
                                (cur_node - 1)->cost = match_before_gap;
                                QUEUE(cur_node) =
                                        lzx_lru_queue_push(QUEUE(cur_node - len - 1 -
                                                                 (match_before_gap & OPTIMUM_LEN_MASK)),
                                                           (match_before_gap >> OPTIMUM_OFFSET_SHIFT) -
                                                           LZX_OFFSET_ADJUSTMENT);
                        }
                #endif
                        else {
                                /* Repeat offset match: swap offset to front. */
                                QUEUE(cur_node) =
                                        lzx_lru_queue_swap(QUEUE(cur_node - len),
                                                           adjusted_offset);
                        }
                }
        } while (cur_node != end_node);

        /* Return the recent offsets queue at the end of the path. */
        return QUEUE(cur_node);
}

/*
 * Given the costs for the main and length codewords (c->costs.main and
 * c->costs.len), initialize the match cost array (c->costs.match_cost) which
 * directly provides the cost of every possible (length, offset slot) pair.
 */
static void
lzx_compute_match_costs(struct liblzx_compressor *c)
{
        unsigned num_offset_slots = (c->num_main_syms - LZX_NUM_CHARS) /
                                        LZX_NUM_LEN_HEADERS;
        struct lzx_costs *costs = &c->costs;
        unsigned main_symbol = LZX_NUM_CHARS;

        for (unsigned offset_slot = 0; offset_slot < num_offset_slots;
             offset_slot++)
        {
                uint32_t extra_cost = lzx_extra_offset_bits[offset_slot] * BIT_COST;
                unsigned i;

        #if CONSIDER_ALIGNED_COSTS
                if (offset_slot >= LZX_MIN_ALIGNED_OFFSET_SLOT)
                        extra_cost -= LZX_NUM_ALIGNED_OFFSET_BITS * BIT_COST;
        #endif

                for (i = 0; i < LZX_NUM_PRIMARY_LENS; i++) {
                        costs->match_cost[offset_slot][i] =
                                costs->main[main_symbol++] + extra_cost;
                }

                extra_cost += costs->main[main_symbol++];

                for (; i < LZX_NUM_LENS; i++) {
                        costs->match_cost[offset_slot][i] =
                                costs->len[i - LZX_NUM_PRIMARY_LENS] +
                                extra_cost;
                }
        }
}

typedef struct fixed32frac_s {
        uint32_t value;
} fixed32frac;

typedef struct fixed32_s {
        uint64_t value;
} fixed32;

/*
 * Fast approximation for log2f(x).  This is not as accurate as the standard C
 * version.  It does not need to be perfectly accurate because it is only used
 * for estimating symbol costs, which is very approximate anyway.
 */
struct log2_fixed_table_pair
{
        uint32_t multiplier;
        uint32_t log_add;
};

static const struct log2_fixed_table_pair log2_fixed_table_0[255] = {
        { 0xff01fc08u, 0x16f2dcfu },  { 0xfe05ee36u, 0x2dceffeu },
        { 0xfd0bd0beu, 0x4494959u },  { 0xfc139debu, 0x5b43ca6u },
        { 0xfb1d5020u, 0x71dcca2u },  { 0xfa28e1d4u, 0x885fc02u },
        { 0xf9364d94u, 0x9eccd73u },  { 0xf8458e02u, 0xb52439au },
        { 0xf7569dd6u, 0xcb66115u },  { 0xf66977dau, 0xe19287au },
        { 0xf57e16edu, 0xf7a9c58u },  { 0xf4947602u, 0x10dabf37u },
        { 0xf3ac901fu, 0x12399395u }, { 0xf2c6605bu, 0x13971beeu },
        { 0xf1e1e1e2u, 0x14f35ab3u }, { 0xf0ff0ff1u, 0x164e524fu },
        { 0xf01de5d7u, 0x17a80527u }, { 0xef3e5ef4u, 0x19007598u },
        { 0xee6076bau, 0x1a57a5f9u }, { 0xed8428aau, 0x1bad989cu },
        { 0xeca97059u, 0x1d024fc9u }, { 0xebd04968u, 0x1e55cdc7u },
        { 0xeaf8af8bu, 0x1fa814d2u }, { 0xea229e85u, 0x20f92722u },
        { 0xe94e1228u, 0x224906e7u }, { 0xe87b0655u, 0x2397b64fu },
        { 0xe7a976fdu, 0x24e5377du }, { 0xe6d9601du, 0x26318c93u },
        { 0xe60abdc3u, 0x277cb7acu }, { 0xe53d8c0bu, 0x28c6bad9u },
        { 0xe471c71du, 0x2a0f982cu }, { 0xe3a76b2fu, 0x2b5751aeu },
        { 0xe2de7486u, 0x2c9de963u }, { 0xe216df74u, 0x2de36147u },
        { 0xe150a854u, 0x2f27bb59u }, { 0xe08bcb94u, 0x306af989u },
        { 0xdfc845a9u, 0x31ad1dc8u }, { 0xdf061318u, 0x32ee29feu },
        { 0xde45306fu, 0x342e2014u }, { 0xdd859a4au, 0x356d01e8u },
        { 0xdcc74d51u, 0x36aad154u }, { 0xdc0a4635u, 0x37e79032u },
        { 0xdb4e81b5u, 0x39234051u }, { 0xda93fc99u, 0x3a5de380u },
        { 0xd9dab3b6u, 0x3b977b86u }, { 0xd922a3e9u, 0x3cd00a2au },
        { 0xd86bca1bu, 0x3e07912bu }, { 0xd7b62341u, 0x3f3e1241u },
        { 0xd701ac57u, 0x40738f27u }, { 0xd64e6266u, 0x41a8098eu },
        { 0xd59c427fu, 0x42db8323u }, { 0xd4eb49bcu, 0x440dfd94u },
        { 0xd43b7544u, 0x453f7a82u }, { 0xd38cc244u, 0x466ffb93u },
        { 0xd2df2df3u, 0x479f8265u }, { 0xd232b593u, 0x48ce108eu },
        { 0xd187566cu, 0x49fba7a9u }, { 0xd0dd0dd1u, 0x4b284946u },
        { 0xd033d91du, 0x4c53f6f4u }, { 0xcf8bb5b4u, 0x4d7eb23bu },
        { 0xcee4a102u, 0x4ea87ca4u }, { 0xce3e987au, 0x4fd157b4u },
        { 0xcd99999au, 0x50f944e7u }, { 0xccf5a1e5u, 0x522045bcu },
        { 0xcc52aee8u, 0x53465baau }, { 0xcbb0be38u, 0x546b8825u },
        { 0xcb0fcd6fu, 0x558fcca0u }, { 0xca6fda31u, 0x56b32a89u },
        { 0xc9d0e229u, 0x57d5a34au }, { 0xc932e309u, 0x58f7384au },
        { 0xc895da89u, 0x5a17eaf0u }, { 0xc7f9c66bu, 0x5b37bc99u },
        { 0xc75ea476u, 0x5c56aea2u }, { 0xc6c47277u, 0x5d74c26au },
        { 0xc62b2e44u, 0x5e91f945u }, { 0xc592d5b8u, 0x5fae5488u },
        { 0xc4fb66b5u, 0x60c9d584u }, { 0xc464df24u, 0x61e47d87u },
        { 0xc3cf3cf4u, 0x62fe4dddu }, { 0xc33a7e1au, 0x641747cdu },
        { 0xc2a6a091u, 0x652f6c9eu }, { 0xc213a25cu, 0x6646bd8fu },
        { 0xc1818182u, 0x675d3be2u }, { 0xc0f03c0fu, 0x6872e8d5u },
        { 0xc05fd018u, 0x6987c59fu }, { 0xbfd03bb5u, 0x6a9bd379u },
        { 0xbf417d06u, 0x6baf1395u }, { 0xbeb3922eu, 0x6cc18729u },
        { 0xbe267957u, 0x6dd32f61u }, { 0xbd9a30b1u, 0x6ee40d69u },
        { 0xbd0eb670u, 0x6ff4226du }, { 0xbc8408cdu, 0x71036f95u },
        { 0xbbfa2609u, 0x7211f601u }, { 0xbb710c66u, 0x731fb6d9u },
        { 0xbae8ba2fu, 0x742cb339u }, { 0xba612db0u, 0x7538ec41u },
        { 0xb9da653eu, 0x7644630au }, { 0xb9545f30u, 0x774f18adu },
        { 0xb8cf19e3u, 0x78590e41u }, { 0xb84a93b8u, 0x796244d9u },
        { 0xb7c6cb15u, 0x7a6abd86u }, { 0xb743be65u, 0x7b727958u },
        { 0xb6c16c17u, 0x7c79795bu }, { 0xb63fd29du, 0x7d7fbe9eu },
        { 0xb5bef071u, 0x7e854a23u }, { 0xb53ec40eu, 0x7f8a1cf4u },
        { 0xb4bf4bf5u, 0x808e3815u }, { 0xb44086aau, 0x81919c88u },
        { 0xb3c272b6u, 0x82944b4cu }, { 0xb3450ea6u, 0x83964560u },
        { 0xb2c8590bu, 0x84978bc0u }, { 0xb24c507au, 0x85981f63u },
        { 0xb1d0f38cu, 0x86980143u }, { 0xb15640ddu, 0x87973255u },
        { 0xb0dc370eu, 0x8895b38du }, { 0xb062d4c3u, 0x899385ddu },
        { 0xafea18a4u, 0x8a90aa35u }, { 0xaf72015du, 0x8b8d2181u },
        { 0xaefa8d9eu, 0x8c88ecadu }, { 0xae83bc18u, 0x8d840ca6u },
        { 0xae0d8b83u, 0x8e7e8252u }, { 0xad97fa99u, 0x8f784e96u },
        { 0xad230816u, 0x90717259u }, { 0xacaeb2bbu, 0x9169ee7eu },
        { 0xac3af94cu, 0x9261c3e6u }, { 0xabc7da92u, 0x9358f36cu },
        { 0xab555555u, 0x944f7df3u }, { 0xaae36865u, 0x95456453u },
        { 0xaa721292u, 0x963aa768u }, { 0xaa0152b0u, 0x972f4809u },
        { 0xa9912796u, 0x9823470fu }, { 0xa9219020u, 0x9916a54au },
        { 0xa8b28b29u, 0x9a096393u }, { 0xa8441792u, 0x9afb82bau },
        { 0xa7d6343fu, 0x9bed038du }, { 0xa768e015u, 0x9cdde6ddu },
        { 0xa6fc19fdu, 0x9dce2d77u }, { 0xa68fe0e4u, 0x9ebdd823u },
        { 0xa62433b8u, 0x9face7adu }, { 0xa5b91169u, 0xa09b5cdfu },
        { 0xa54e78edu, 0xa189387du }, { 0xa4e46939u, 0xa2767b4fu },
        { 0xa47ae148u, 0xa3632616u }, { 0xa411e014u, 0xa44f3999u },
        { 0xa3a9649eu, 0xa53ab692u }, { 0xa3416de5u, 0xa6259dc7u },
        { 0xa2d9faeeu, 0xa70feff2u }, { 0xa2730abfu, 0xa7f9add0u },
        { 0xa20c9c60u, 0xa8e2d81du }, { 0xa1a6aedcu, 0xa9cb6f95u },
        { 0xa1414141u, 0xaab374eeu }, { 0xa0dc529fu, 0xab9ae8dfu },
        { 0xa077e207u, 0xac81cc1fu }, { 0xa013ee8fu, 0xad681f62u },
        { 0x9fb0774du, 0xae4de35au }, { 0x9f4d7b5au, 0xaf3318bau },
        { 0x9eeaf9d1u, 0xb017c033u }, { 0x9e88f1d0u, 0xb0fbda74u },
        { 0x9e276276u, 0xb1df682bu }, { 0x9dc64ae5u, 0xb2c26a06u },
        { 0x9d65aa42u, 0xb3a4e0acu }, { 0x9d057fb2u, 0xb486cccbu },
        { 0x9ca5ca5du, 0xb5682f0cu }, { 0x9c46896du, 0xb6490816u },
        { 0x9be7bc0eu, 0xb7295893u }, { 0x9b896170u, 0xb8092121u },
        { 0x9b2b78c1u, 0xb8e8626cu }, { 0x9ace0134u, 0xb9c71d13u },
        { 0x9a70f9fdu, 0xbaa551b9u }, { 0x9a146253u, 0xbb8300fdu },
        { 0x99b8396cu, 0xbc602b82u }, { 0x995c7e82u, 0xbd3cd1e6u },
        { 0x990130d1u, 0xbe18f4c6u }, { 0x98a64f97u, 0xbef494bdu },
        { 0x984bda13u, 0xbfcfb267u }, { 0x97f1cf85u, 0xc0aa4e5fu },
        { 0x97982f30u, 0xc184693fu }, { 0x973ef859u, 0xc25e039eu },
        { 0x96e62a46u, 0xc3371e12u }, { 0x968dc43fu, 0xc40fb932u },
        { 0x9635c58du, 0xc4e7d594u }, { 0x95de2d7cu, 0xc5bf73cau },
        { 0x9586fb58u, 0xc696946au }, { 0x95302e70u, 0xc76d3803u },
        { 0x94d9c615u, 0xc8435f25u }, { 0x9483c197u, 0xc9190a64u },
        { 0x942e204au, 0xc9ee3a4eu }, { 0x93d8e182u, 0xcac2ef71u },
        { 0x93840497u, 0xcb972a58u }, { 0x932f88e0u, 0xcc6aeb90u },
        { 0x92db6db7u, 0xcd3e33a3u }, { 0x9287b275u, 0xce110320u },
        { 0x92345678u, 0xcee35a8du }, { 0x91e1591eu, 0xcfb53a70u },
        { 0x918eb9c5u, 0xd086a355u }, { 0x913c77ceu, 0xd15795c2u },
        { 0x90ea929bu, 0xd228123cu }, { 0x90990990u, 0xd2f81946u },
        { 0x9047dc12u, 0xd3c7ab65u }, { 0x8ff70986u, 0xd496c91du },
        { 0x8fa69154u, 0xd56572f1u }, { 0x8f5672e4u, 0xd633a963u },
        { 0x8f06ada2u, 0xd7016cf0u }, { 0x8eb740f9u, 0xd7cebe18u },
        { 0x8e682c54u, 0xd89b9d5fu }, { 0x8e196f23u, 0xd9680b3du },
        { 0x8dcb08d4u, 0xda340833u }, { 0x8d7cf8d8u, 0xdaff94bcu },
        { 0x8d2f3ea0u, 0xdbcab157u }, { 0x8ce1d9a0u, 0xdc955e7au },
        { 0x8c94c94cu, 0xdd5f9ca0u }, { 0x8c480d19u, 0xde296c45u },
        { 0x8bfba47eu, 0xdef2cddeu }, { 0x8baf8ef2u, 0xdfbbc1e5u },
        { 0x8b63cbeeu, 0xe08448d1u }, { 0x8b185aedu, 0xe14c6316u },
        { 0x8acd3b69u, 0xe214112du }, { 0x8a826cdeu, 0xe2db5389u },
        { 0x8a37eecau, 0xe3a22a9fu }, { 0x89edc0acu, 0xe46896deu },
        { 0x89a3e202u, 0xe52e98bfu }, { 0x895a524eu, 0xe5f430b0u },
        { 0x89111111u, 0xe6b95f22u }, { 0x88c81dceu, 0xe77e2486u },
        { 0x887f7808u, 0xe842814eu }, { 0x88371f45u, 0xe90675e5u },
        { 0x87ef130au, 0xe9ca02bcu }, { 0x87a752dfu, 0xea8d283du },
        { 0x875fde4au, 0xeb4fe6dau }, { 0x8718b4d4u, 0xec123effu },
        { 0x86d1d608u, 0xecd43114u }, { 0x868b4170u, 0xed95bd86u },
        { 0x8644f698u, 0xee56e4beu }, { 0x85fef50du, 0xef17a726u },
        { 0x85b93c5bu, 0xefd8052bu }, { 0x8573cc12u, 0xf097ff30u },
        { 0x852ea3c2u, 0xf157959cu }, { 0x84e9c2f9u, 0xf216c8ddu },
        { 0x84a5294au, 0xf2d59955u }, { 0x8460d647u, 0xf3940768u },
        { 0x841cc982u, 0xf4521381u }, { 0x83d90290u, 0xf50fbdffu },
        { 0x83958106u, 0xf5cd0747u }, { 0x83524478u, 0xf689efc0u },
        { 0x830f4c7eu, 0xf74677c9u }, { 0x82cc98afu, 0xf8029fc5u },
        { 0x828a28a2u, 0xf8be6819u }, { 0x8247fbf2u, 0xf979d120u },
        { 0x82061236u, 0xfa34db42u }, { 0x81c46b0bu, 0xfaef86d9u },
        { 0x8183060cu, 0xfba9d445u }, { 0x8141e2d4u, 0xfc63c3e8u },
        { 0x81010101u, 0xfd1d561du }, { 0x80c06030u, 0xfdd68b44u },
        { 0x80800000u, 0xfe8f63b9u },
};

static const uint32_t log2_fixed_table_1[255] = {
        0x17152u,   0x2e2a3u,        0x453f2u,   0x5c540u,        0x7368du,   0x8a7d8u,
        0xa1921u,   0xb8a69u,        0xcfbb0u,   0xe6cf6u,        0xfde39u,   0x114f7cu,
        0x12c0bdu,  0x1431fcu,        0x15a33au,  0x171477u,        0x1885b2u,  0x19f6ecu,
        0x1b6824u,  0x1cd95bu,        0x1e4a91u,  0x1fbbc5u,        0x212cf7u,  0x229e28u,
        0x240f58u,  0x258086u,        0x26f1b3u,  0x2862deu,        0x29d408u,  0x2b4530u,
        0x2cb657u,  0x2e277du,        0x2f98a1u,  0x3109c4u,        0x327ae5u,  0x33ec05u,
        0x355d23u,  0x36ce40u,        0x383f5bu,  0x39b077u,        0x3b218fu,  0x3c92a6u,
        0x3e03bcu,  0x3f74d0u,        0x40e5e3u,  0x4256f4u,        0x43c804u,  0x453912u,
        0x46aa1fu,  0x481b2bu,        0x498c36u,  0x4afd3fu,        0x4c6e46u,  0x4ddf4cu,
        0x4f5050u,  0x50c153u,        0x523254u,  0x53a355u,        0x551454u,  0x568551u,
        0x57f64cu,  0x596747u,        0x5ad83fu,  0x5c4938u,        0x5dba2eu,  0x5f2b22u,
        0x609c15u,  0x620d06u,        0x637df8u,  0x64eee6u,        0x665fd3u,  0x67d0bfu,
        0x6941abu,  0x6ab293u,        0x6c237bu,  0x6d9461u,        0x6f0546u,  0x707629u,
        0x71e70bu,  0x7357ecu,        0x74c8cbu,  0x7639a8u,        0x77aa84u,  0x791b5fu,
        0x7a8c38u,  0x7bfd10u,        0x7d6de7u,  0x7edebbu,        0x804f8eu,  0x81c061u,
        0x833131u,  0x84a202u,        0x8612cfu,  0x87839au,        0x88f466u,  0x8a652fu,
        0x8bd5f8u,  0x8d46beu,        0x8eb784u,  0x902847u,        0x91990au,  0x9309cau,
        0x947a89u,  0x95eb47u,        0x975c03u,  0x98ccbfu,        0x9a3d79u,  0x9bae31u,
        0x9d1ee8u,  0x9e8f9cu,        0xa00051u,  0xa17103u,        0xa2e1b4u,  0xa45263u,
        0xa5c312u,  0xa733bfu,        0xa8a469u,  0xaa1513u,        0xab85bcu,  0xacf662u,
        0xae6708u,  0xafd7adu,        0xb1484eu,  0xb2b8f0u,        0xb42990u,  0xb59a2du,
        0xb70acbu,  0xb87b67u,        0xb9ec01u,  0xbb5c98u,        0xbccd30u,  0xbe3dc6u,
        0xbfae5au,  0xc11eedu,        0xc28f7fu,  0xc4000eu,        0xc5709cu,  0xc6e12au,
        0xc851b5u,  0xc9c240u,        0xcb32c9u,  0xcca350u,        0xce13d6u,  0xcf845bu,
        0xd0f4deu,  0xd2655fu,        0xd3d5dfu,  0xd5465eu,        0xd6b6dbu,  0xd82757u,
        0xd997d2u,  0xdb084au,        0xdc78c2u,  0xdde938u,        0xdf59acu,  0xe0ca1fu,
        0xe23a91u,  0xe3ab01u,        0xe51b70u,  0xe68bdfu,        0xe7fc4au,  0xe96cb5u,
        0xeadd1du,  0xec4d85u,        0xedbdecu,  0xef2e51u,        0xf09eb4u,  0xf20f17u,
        0xf37f77u,  0xf4efd6u,        0xf66033u,  0xf7d090u,        0xf940eau,  0xfab144u,
        0xfc219cu,  0xfd91f2u,        0xff0248u,  0x100729bu, 0x101e2eeu, 0x103533eu,
        0x104c38eu, 0x10633dbu, 0x107a428u, 0x1091472u, 0x10a84bdu, 0x10bf504u,
        0x10d654bu, 0x10ed591u, 0x11045d4u, 0x111b617u, 0x1132658u, 0x1149697u,
        0x11606d6u, 0x1177713u, 0x118e74du, 0x11a5787u, 0x11bc7c0u, 0x11d37f7u,
        0x11ea82du, 0x1201860u, 0x1218892u, 0x122f8c4u, 0x12468f4u, 0x125d922u,
        0x127494fu, 0x128b97bu, 0x12a29a5u, 0x12b99ceu, 0x12d09f5u, 0x12e7a1bu,
        0x12fea3fu, 0x1315a62u, 0x132ca83u, 0x1343aa3u, 0x135aac1u, 0x1371adeu,
        0x1388afau, 0x139fb15u, 0x13b6b2eu, 0x13cdb45u, 0x13e4b5bu, 0x13fbb6fu,
        0x1412b83u, 0x1429b94u, 0x1440ba4u, 0x1457bb4u, 0x146ebc1u, 0x1485bccu,
        0x149cbd8u, 0x14b3be0u, 0x14cabe8u, 0x14e1beeu, 0x14f8bf2u, 0x150fbf6u,
        0x1526bf9u, 0x153dbf9u, 0x1554bf8u, 0x156bbf5u, 0x1582bf2u, 0x1599becu,
        0x15b0be6u, 0x15c7bdeu, 0x15debd3u, 0x15f5bc9u, 0x160cbbdu, 0x1623bafu,
        0x163ab9fu, 0x1651b8eu, 0x1668b7du, 0x167fb69u, 0x1696b54u, 0x16adb3eu,
        0x16c4b26u, 0x16dbb0du, 0x16f2af3u,
};

static int32_t
log2_fixed_fast_normalized(const fixed32 *value, int multiplier_bits)
{
        int32_t base_pos = 0;
        uint32_t mantissa = 0;
        uint32_t mantissa_log2 = 0;
        uint8_t mantissa_byte = 0;
        int64_t final_log = 0;

        if (value->value == 0)
                return 0;

        base_pos = (int)bsr64(value->value) - 32;
        if (base_pos > 0) {
                mantissa = (value->value >> base_pos) & 0xffffffffu;
        } else {
                mantissa = (value->value << -base_pos) & 0xffffffffu;
        }

        /* Get the first byte */
        mantissa_byte = (mantissa >> 24) & 0xffu;

        if (mantissa_byte != 0) {
                const struct log2_fixed_table_pair *pair = log2_fixed_table_0 + (mantissa_byte - 1);
                mantissa = (uint32_t)((mantissa * (uint64_t)pair->multiplier) >> 32) + pair->multiplier;

                mantissa_log2 += pair->log_add;
        }

        mantissa_byte = (mantissa >> 16) & 0xffu;

        if (mantissa_byte != 0) {
                mantissa_log2 += log2_fixed_table_1[mantissa_byte - 1];
        }

        final_log = (int64_t)mantissa_log2 + ((int64_t)base_pos << 32);
        final_log /= ((int64_t)1 << (32 - multiplier_bits));

        return (int32_t)final_log;
}

/*
 * Return the estimated cost of a symbol which has been estimated to have the
 * given probability.
 */
static uint32_t
lzx_cost_for_probability(const fixed32* prob)
{
        /*
         * The basic formula is:
         *
         *        entropy = -log2(probability)
         *
         * Use this to get the cost in fractional bits.  Then multiply by our
         * scaling factor of BIT_COST and convert to an integer.
         *
         * In addition, the minimum cost is BIT_COST (one bit) because the
         * entropy coding method will be Huffman codes.
         *
         * Careful: even though 'prob' should be <= 1.0, 'log2f_fast(prob)' may
         * be positive due to inaccuracy in our log2 approximation.  Therefore,
         * we cannot, in general, assume the computed cost is non-negative, and
         * we should make sure negative costs get rounded up correctly.
         */
        int32_t cost = -log2_fixed_fast_normalized(prob, BIT_COST_BITS);
        return max_u32(cost, BIT_COST);
}

/*
 * Mapping: number of used literals => heuristic probability of a literal times
 * 6870.  Generated by running this R command:
 *
 *        cat(paste(round(6870*2^-((304+(0:256))/64)), collapse=", "))
 */
static const uint8_t literal_scaled_probs[257] = {
        255, 253, 250, 247, 244, 242, 239, 237, 234, 232, 229, 227, 224, 222,
        219, 217, 215, 212, 210, 208, 206, 203, 201, 199, 197, 195, 193, 191,
        189, 186, 184, 182, 181, 179, 177, 175, 173, 171, 169, 167, 166, 164,
        162, 160, 159, 157, 155, 153, 152, 150, 149, 147, 145, 144, 142, 141,
        139, 138, 136, 135, 133, 132, 130, 129, 128, 126, 125, 124, 122, 121,
        120, 118, 117, 116, 115, 113, 112, 111, 110, 109, 107, 106, 105, 104,
        103, 102, 101, 100, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 87, 86,
        86, 85, 84, 83, 82, 81, 80, 79, 78, 78, 77, 76, 75, 74, 73, 73, 72, 71,
        70, 70, 69, 68, 67, 67, 66, 65, 65, 64, 63, 62, 62, 61, 60, 60, 59, 59,
        58, 57, 57, 56, 55, 55, 54, 54, 53, 53, 52, 51, 51, 50, 50, 49, 49, 48,
        48, 47, 47, 46, 46, 45, 45, 44, 44, 43, 43, 42, 42, 41, 41, 40, 40, 40,
        39, 39, 38, 38, 38, 37, 37, 36, 36, 36, 35, 35, 34, 34, 34, 33, 33, 33,
        32, 32, 32, 31, 31, 31, 30, 30, 30, 29, 29, 29, 28, 28, 28, 27, 27, 27,
        27, 26, 26, 26, 25, 25, 25, 25, 24, 24, 24, 24, 23, 23, 23, 23, 22, 22,
        22, 22, 21, 21, 21, 21, 20, 20, 20, 20, 20, 19, 19, 19, 19, 19, 18, 18,
        18, 18, 18, 17, 17, 17, 17, 17, 16, 16, 16, 16
};

/*
 * Mapping: length symbol => default cost of that symbol.  This is derived from
 * sample data but has been slightly edited to add more bias towards the
 * shortest lengths, which are the most common.
 */
static const uint16_t lzx_default_len_costs[LZX_LENCODE_NUM_SYMBOLS] = {
        300, 310, 320, 330, 360, 396, 399, 416, 451, 448, 463, 466, 505, 492,
        503, 514, 547, 531, 566, 561, 589, 563, 592, 586, 623, 602, 639, 627,
        659, 643, 657, 650, 685, 662, 661, 672, 685, 686, 696, 680, 657, 682,
        666, 699, 674, 699, 679, 709, 688, 712, 692, 714, 694, 716, 698, 712,
        706, 727, 714, 727, 713, 723, 712, 718, 719, 719, 720, 735, 725, 735,
        728, 740, 727, 739, 727, 742, 716, 733, 733, 740, 738, 746, 737, 747,
        738, 745, 736, 748, 742, 749, 745, 749, 743, 748, 741, 752, 745, 752,
        747, 750, 747, 752, 748, 753, 750, 752, 753, 753, 749, 744, 752, 755,
        753, 756, 745, 748, 746, 745, 723, 757, 755, 758, 755, 758, 752, 757,
        754, 757, 755, 759, 755, 758, 753, 755, 755, 758, 757, 761, 755, 750,
        758, 759, 759, 760, 758, 751, 757, 757, 759, 759, 758, 759, 758, 761,
        750, 761, 758, 760, 759, 761, 758, 761, 760, 752, 759, 760, 759, 759,
        757, 762, 760, 761, 761, 748, 761, 760, 762, 763, 752, 762, 762, 763,
        762, 762, 763, 763, 762, 763, 762, 763, 762, 763, 763, 764, 763, 762,
        763, 762, 762, 762, 764, 764, 763, 764, 763, 763, 763, 762, 763, 763,
        762, 764, 764, 763, 762, 763, 763, 763, 763, 762, 764, 763, 762, 764,
        764, 763, 763, 765, 764, 764, 762, 763, 764, 765, 763, 764, 763, 764,
        762, 764, 764, 754, 763, 764, 763, 763, 762, 763, 584,
};

static void
fixed_rcp_approx(fixed32frac *result, uint32_t i)
{
        result->value = ((uint64_t)0x100000000ull) / i;
}

static void
fixed_set(fixed32 *result, uint32_t i)
{
        result->value = ((uint64_t)i << 32);
}

static void
fixed_set_fraction(fixed32frac *result, uint32_t num, uint32_t denom)
{
        result->value = (((uint64_t)num) << 32) / denom;
}

static void
fixed_mul_uint_frac(fixed32 *result, uint32_t a, const fixed32frac *b)
{
        result->value = ((uint64_t)a) * (uint64_t)b->value;
}

static void
fixed_mul_uint_frac_to_frac(fixed32frac *result, uint32_t a, const fixed32frac *b)
{
        fixed32 fixed;
        fixed_mul_uint_frac(&fixed, a, b);
        result->value = (uint32_t)fixed.value;
}

static void
fixed_add_frac(fixed32 *result, const fixed32 *a, const fixed32frac *b)
{
        result->value = a->value + b->value;
}

static void
fixed_sub(fixed32 *result, const fixed32 *a, const fixed32 *b)
{
        result->value = a->value + b->value;
}

static void
fixed_max_frac(fixed32 *result, const fixed32 *a, const fixed32frac *b)
{
        result->value = max_u64(a->value, b->value);
}

static void
fixed_div_uint(fixed32 *result, const fixed32 *a, uint32_t b)
{
        result->value = a->value / b;
}

/* Set default costs to bootstrap the iterative optimization algorithm. */
static void
lzx_set_default_costs(struct liblzx_compressor *c)
{
        unsigned i;
        uint32_t num_literals = 0;
        uint32_t num_used_literals = 0;
        fixed32frac inv_num_matches;
        fixed32frac half_inv_num_items;
        fixed32frac half_inv_6870;
        fixed32 prob_match;
        fixed32frac frac_15_100;
        uint32_t match_cost;
        fixed32frac half_base_literal_prob;
        fixed32 temp_fixed;

        fixed_rcp_approx(&inv_num_matches, c->freqs.main[LZX_NUM_CHARS]);
        fixed_rcp_approx(&half_inv_6870, 6870 * 2);
        fixed_set(&prob_match, 1);
        fixed_set_fraction(&frac_15_100, 15, 100);

        /* Some numbers here have been hardcoded to assume a bit cost of 64. */
        STATIC_ASSERT_STMT(BIT_COST == 64);

        /* Estimate the number of literals that will used.  'num_literals' is
         * the total number, whereas 'num_used_literals' is the number of
         * distinct symbols. */
        for (i = 0; i < LZX_NUM_CHARS; i++) {
                num_literals += c->freqs.main[i];
                num_used_literals += (c->freqs.main[i] != 0);
        }

        /* Note: all match headers were tallied as symbol 'LZX_NUM_CHARS'.  We
         * don't attempt to estimate which ones will be used. */

        fixed_rcp_approx(&half_inv_num_items,
                         (num_literals + c->freqs.main[LZX_NUM_CHARS]) * 2);
        fixed_mul_uint_frac_to_frac(&half_base_literal_prob,
                            literal_scaled_probs[num_used_literals],
                            &half_inv_6870);

        /* Literal costs.  We use two different methods to compute the
         * probability of each literal and mix together their results. */
        for (i = 0; i < LZX_NUM_CHARS; i++) {
                uint32_t freq = c->freqs.main[i];
                if (freq != 0) {
                        fixed32 prob;
                        fixed_mul_uint_frac(&prob, freq, &half_inv_num_items);
                        fixed_add_frac(&prob, &prob, &half_base_literal_prob);

                        c->costs.main[i] = lzx_cost_for_probability(&prob);
                        fixed_sub(&prob_match, &prob_match, &prob);
                } else {
                        c->costs.main[i] = 11 * BIT_COST;
                }
        }

        /* Match header costs.  We just assume that all match headers are
         * equally probable, but we do take into account the relative cost of a
         * match header vs. a literal depending on how common matches are
         * expected to be vs. literals. */
        fixed_max_frac(&prob_match, &prob_match, &frac_15_100);
        fixed_div_uint(&temp_fixed, &prob_match,
                       (c->num_main_syms - LZX_NUM_CHARS));
        match_cost = lzx_cost_for_probability(&temp_fixed);
        for (; i < c->num_main_syms; i++)
                c->costs.main[i] = match_cost;

        /* Length symbol costs.  These are just set to fixed values which
         * reflect the fact the smallest lengths are typically the most common,
         * and therefore are typically the cheapest. */
        for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++)
                c->costs.len[i] = lzx_default_len_costs[i];

#if CONSIDER_ALIGNED_COSTS
        /* Aligned offset symbol costs.  These are derived from the estimated
         * probability of each aligned offset symbol. */
        for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
                /* We intentionally tallied the frequencies in the wrong slots,
                 * not accounting for LZX_OFFSET_ADJUSTMENT, since doing the
                 * fixup here is faster: a constant 8 subtractions here vs. one
                 * addition for every match. */
                unsigned j = (i - LZX_OFFSET_ADJUSTMENT) & LZX_ALIGNED_OFFSET_BITMASK;
                if (c->freqs.aligned[j] != 0) {
                        fixed32 prob;
                        fixed_mul_uint_frac(&prob, c->freqs.aligned[j],
                                            &inv_num_matches);
                        c->costs.aligned[i] = lzx_cost_for_probability(&prob);
                } else {
                        c->costs.aligned[i] =
                                (2 * LZX_NUM_ALIGNED_OFFSET_BITS) * BIT_COST;
                }
        }
#endif
}

/* Update the current cost model to reflect the computed Huffman codes.  */
static void
lzx_set_costs_from_codes(struct liblzx_compressor *c)
{
        unsigned i;
        const struct lzx_lens *lens = &c->codes[c->codes_index].lens;

        for (i = 0; i < c->num_main_syms; i++) {
                c->costs.main[i] = (lens->main[i] ? lens->main[i] :
                                    MAIN_CODEWORD_LIMIT) * BIT_COST;
        }

        for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++) {
                c->costs.len[i] = (lens->len[i] ? lens->len[i] :
                                   LENGTH_CODEWORD_LIMIT) * BIT_COST;
        }

#if CONSIDER_ALIGNED_COSTS
        for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
                c->costs.aligned[i] = (lens->aligned[i] ? lens->aligned[i] :
                                       ALIGNED_CODEWORD_LIMIT) * BIT_COST;
        }
#endif
}

/*
 * Choose a "near-optimal" literal/match sequence to use for the current block,
 * then flush the block.  Because the cost of each Huffman symbol is unknown
 * until the Huffman codes have been built and the Huffman codes themselves
 * depend on the symbol frequencies, this uses an iterative optimization
 * algorithm to approximate an optimal solution.  The first optimization pass
 * for the block uses default costs; additional passes use costs derived from
 * the Huffman codes computed in the previous pass.
 */
static attrib_forceinline struct lzx_lru_queue
lzx_optimize_and_flush_block(struct liblzx_compressor * const restrict c,
                             struct lzx_output_bitstream * const restrict os,
                             const uint8_t * const restrict block_begin,
                             const uint32_t block_size,
                             const struct lzx_lru_queue initial_queue,
                             bool is_16_bit)
{
        unsigned num_passes_remaining = c->num_optim_passes;
        struct lzx_lru_queue new_queue;
        uint32_t seq_idx;

        lzx_set_default_costs(c);

        for (;;) {
                lzx_compute_match_costs(c);
                new_queue = lzx_find_min_cost_path(c, block_begin, block_size,
                                                   initial_queue, is_16_bit);

                if (--num_passes_remaining == 0)
                        break;

                /* At least one optimization pass remains.  Update the costs. */
                lzx_reset_symbol_frequencies(c);
                lzx_tally_item_list(c, block_size, is_16_bit);
                lzx_build_huffman_codes(c);
                lzx_set_costs_from_codes(c);
        }

        /* Done optimizing.  Generate the sequence list and flush the block. */
        lzx_reset_symbol_frequencies(c);
        seq_idx = lzx_record_item_list(c, block_size, is_16_bit);
        lzx_flush_block(c, os, block_begin, block_size, seq_idx);
        return new_queue;
}

/*
 * This is the "near-optimal" LZX compressor.
 *
 * For each block, it performs a relatively thorough graph search to find an
 * inexpensive (in terms of compressed size) way to output the block.
 *
 * Note: there are actually many things this algorithm leaves on the table in
 * terms of compression ratio.  So although it may be "near-optimal", it is
 * certainly not "optimal".  The goal is not to produce the optimal compression
 * ratio, which for LZX is probably impossible within any practical amount of
 * time, but rather to produce a compression ratio significantly better than a
 * simpler "greedy" or "lazy" parse while still being relatively fast.
 */
static attrib_forceinline void
lzx_reset_near_optimal(struct liblzx_compressor *c, bool is_16_bit)
{
        /* Initialize the matchfinder. */
        CALL_BT_MF(is_16_bit, c, bt_matchfinder_init);
}

static void
lzx_reset_near_optimal_16(struct liblzx_compressor *c)
{
        lzx_reset_near_optimal(c, true);
}

static void
lzx_reset_near_optimal_32(struct liblzx_compressor *c)
{
        lzx_reset_near_optimal(c, false);
}

static attrib_forceinline void
lzx_compress_near_optimal(struct liblzx_compressor * restrict c,
                          const uint8_t *restrict in_begin,
                          size_t in_nchunk, size_t in_ndata,
                          struct lzx_output_bitstream * restrict os,
                          bool is_16_bit)
{
        uint32_t max_offset                 = c->window_size;
        const uint8_t *         in_next = in_begin;
        const uint8_t * const in_chunk_end = in_begin + in_nchunk;
        const uint8_t * const in_data_end = in_begin + in_ndata;
        uint32_t max_find_len = LZX_MAX_MATCH_LEN;
        uint32_t max_produce_len = LZX_MAX_MATCH_LEN;
        uint32_t nice_len = min_u32(c->nice_match_length, max_find_len);
        uint32_t next_hashes[2] = {0, 0};
        struct lzx_lru_queue queue;

        if (max_offset >= LZX_MAX_WINDOW_SIZE) {
                /* Slightly shrink window to avoid offset values that are
                 * greater than 21 bits. */
                max_offset = LZX_MAX_WINDOW_SIZE - 1 - LZX_OFFSET_ADJUSTMENT;
        }

        in_begin -= c->in_prefix_size;

        if (c->variant == LIBLZX_VARIANT_WIM) {
                CALL_BT_MF(is_16_bit, c, bt_matchfinder_init);
        } else {
                /* Load the LRU queue */
                lzx_lru_queue_load(&queue, c->lru_queue);
        }

        do {
                /* Starting a new block */

                const uint8_t * const in_block_begin = in_next;
                const uint8_t * const in_max_block_end =
                        in_next + min_size(SOFT_MAX_BLOCK_SIZE, in_chunk_end - in_next);
                struct lz_match *cache_ptr = c->match_cache;
                const uint8_t *next_search_pos = in_next;
                const uint8_t *next_observation = in_next;
                const uint8_t *next_pause_point =
                        min_constptr(in_next + min_size(MIN_BLOCK_SIZE,
                                          in_max_block_end - in_next),
                    in_max_block_end - min_size(LZX_MAX_MATCH_LEN - 1,
                                                   in_max_block_end - in_next));

                lzx_init_block_split_stats(&c->split_stats);
                lzx_reset_symbol_frequencies(c);

                if (in_next >= next_pause_point)
                        goto pause;

                /*
                 * Run the input buffer through the matchfinder, caching the
                 * matches, until we decide to end the block.
                 *
                 * For a tighter matchfinding loop, we compute a "pause point",
                 * which is the next position at which we may need to check
                 * whether to end the block or to decrease max_len.  We then
                 * only do these extra checks upon reaching the pause point.
                 */
        resume_matchfinding:
                do {
                        size_t min_match_pos = in_next - in_begin;
                        min_match_pos -= min_size(min_match_pos, max_offset);

                        if (in_next >= next_search_pos &&
                                likely(nice_len >= LZX_MIN_MATCH_LEN)) {
                                /* Search for matches at this position. */
                                struct lz_match *lz_matchptr;
                                uint32_t best_len;

                                lz_matchptr = CALL_BT_MF(is_16_bit, c,
                                                         bt_matchfinder_get_matches,
                                                         in_begin,
                                                         min_match_pos,
                                                         in_next - in_begin,
                                                         max_find_len,
                                                         max_produce_len,
                                                         nice_len,
                                                         c->max_search_depth,
                                                         next_hashes,
                                                         &best_len,
                                                         cache_ptr + 1);
                                cache_ptr->length = lz_matchptr - (cache_ptr + 1);
                                cache_ptr = lz_matchptr;

                                /* Accumulate literal/match statistics for block
                                 * splitting and for generating the initial cost
                                 * model. */
                                if (in_next >= next_observation) {
                                        best_len = cache_ptr[-1].length;
                                        if (best_len >= 3) {
                                                /* Match (len >= 3) */

                                                /*
                                                 * Note: for performance reasons this has
                                                 * been simplified significantly:
                                                 *
                                                 * - We wait until later to account for
                                                 *   LZX_OFFSET_ADJUSTMENT.
                                                 * - We don't account for repeat offsets.
                                                 * - We don't account for different match headers.
                                                 */
                                                c->freqs.aligned[cache_ptr[-1].offset &
                                                        LZX_ALIGNED_OFFSET_BITMASK]++;
                                                c->freqs.main[LZX_NUM_CHARS]++;

                                                lzx_observe_match(&c->split_stats, best_len);
                                                next_observation = in_next + best_len;
                                        } else {
                                                /* Literal */
                                                c->freqs.main[*in_next]++;
                                                lzx_observe_literal(&c->split_stats, *in_next);
                                                next_observation = in_next + 1;
                                        }
                                }

                                /*
                                 * If there was a very long match found, then
                                 * don't cache any matches for the bytes covered
                                 * by that match.  This avoids degenerate
                                 * behavior when compressing highly redundant
                                 * data, where the number of matches can be very
                                 * large.
                                 *
                                 * This heuristic doesn't actually hurt the
                                 * compression ratio *too* much.  If there's a
                                 * long match, then the data must be highly
                                 * compressible, so it doesn't matter as much
                                 * what we do.
                                 */
                                if (best_len >= nice_len)
                                        next_search_pos = in_next + best_len;
                        } else {
                                /* Don't search for matches at this position. */
                                CALL_BT_MF(is_16_bit, c,
                                           bt_matchfinder_skip_byte,
                                           in_begin,
                                           min_match_pos,
                                           in_next - in_begin,
                                           nice_len,
                                           c->max_search_depth,
                                           next_hashes);
                                cache_ptr->length = 0;
                                cache_ptr++;
                        }
                } while (++in_next < next_pause_point &&
                         likely(cache_ptr < &c->match_cache[CACHE_LENGTH]));

        pause:

                /* Adjust max_len and nice_len if we're nearing the end of the
                 * input buffer.  In addition, if we are so close to the end of
                 * the input buffer that there cannot be any more matches, then
                 * just advance through the last few positions and record no
                 * matches. */
                if (unlikely(max_produce_len > in_data_end - in_next)) {
                        max_produce_len = in_chunk_end - in_next;
                        max_find_len = in_data_end - in_next;
                        nice_len = min_u32(max_produce_len, nice_len);
                        if (max_find_len < BT_MATCHFINDER_REQUIRED_NBYTES) {
                                while (in_next != in_chunk_end) {
                                        cache_ptr->length = 0;
                                        cache_ptr++;
                                        in_next++;
                                }
                        }
                }

                /* End the block if the match cache may overflow. */
                if (unlikely(cache_ptr >= &c->match_cache[CACHE_LENGTH]))
                        goto end_block;

                /* End the block if the soft maximum size has been reached. */
                if (in_next >= in_max_block_end)
                        goto end_block;

                /* End the block if the block splitting algorithm thinks this is
                 * a good place to do so. */
                if (c->split_stats.num_new_observations >=
                                NUM_OBSERVATIONS_PER_BLOCK_CHECK &&
                    in_max_block_end - in_next >= MIN_BLOCK_SIZE &&
                    lzx_should_end_block(&c->split_stats))
                        goto end_block;

                /* It's not time to end the block yet.  Compute the next pause
                 * point and resume matchfinding. */
                next_pause_point =
                        min_constptr(in_next + min_size(NUM_OBSERVATIONS_PER_BLOCK_CHECK * 2 -
                                            c->split_stats.num_new_observations,
                                          in_max_block_end - in_next),
                            in_max_block_end - min_size(LZX_MAX_MATCH_LEN - 1,
                                                   in_max_block_end - in_next));
                goto resume_matchfinding;

        end_block:
                /* We've decided on a block boundary and cached matches.  Now
                 * choose a match/literal sequence and flush the block. */
                queue = lzx_optimize_and_flush_block(c, os, in_block_begin,
                                                     in_next - in_block_begin,
                                                     queue, is_16_bit);
        } while (in_next != in_chunk_end);

        /* Save the LRU queue and next hashes */
        lzx_lru_queue_save(c->lru_queue, &queue);
}

static void
lzx_compress_near_optimal_16(struct liblzx_compressor *c, const uint8_t *in,
                             size_t in_nchunk, size_t in_ndata,
                             struct lzx_output_bitstream *os)
{
        lzx_compress_near_optimal(c, in, in_nchunk, in_ndata, os, true);
}

static void
lzx_compress_near_optimal_32(struct liblzx_compressor *c, const uint8_t *in,
                             size_t in_nchunk, size_t in_ndata,
                             struct lzx_output_bitstream *os)
{
        lzx_compress_near_optimal(c, in, in_nchunk, in_ndata, os, false);
}

static attrib_forceinline void
lzx_cull_near_optimal(struct liblzx_compressor *c, size_t nbytes, const bool is_16_bit)
{
        CALL_BT_MF(is_16_bit, c, bt_matchfinder_cull, nbytes, c->window_size);
}

static void
lzx_cull_near_optimal_16(struct liblzx_compressor *c, size_t nbytes)
{
        lzx_cull_near_optimal(c, nbytes, true);
}

static void
lzx_cull_near_optimal_32(struct liblzx_compressor *c, size_t nbytes)
{
        lzx_cull_near_optimal(c, nbytes, false);
}

/******************************************************************************/
/*                     Faster ("lazy") compression algorithm                  */
/*----------------------------------------------------------------------------*/

/*
 * Called when the compressor chooses to use a literal.  This tallies the
 * Huffman symbol for the literal, increments the current literal run length,
 * and "observes" the literal for the block split statistics.
 */
static attrib_forceinline void
lzx_choose_literal(struct liblzx_compressor *c, unsigned literal, uint32_t *litrunlen_p)
{
        lzx_observe_literal(&c->split_stats, literal);
        c->freqs.main[literal]++;
        ++*litrunlen_p;
}

/*
 * Called when the compressor chooses to use a match.  This tallies the Huffman
 * symbol(s) for a match, saves the match data and the length of the preceding
 * literal run, updates the recent offsets queue, and "observes" the match for
 * the block split statistics.
 */
static attrib_forceinline void
lzx_choose_match(struct liblzx_compressor *c, unsigned length, uint32_t adjusted_offset,
                 uint32_t recent_offsets[LZX_NUM_RECENT_OFFSETS], bool is_16_bit,
                 uint32_t *litrunlen_p, struct lzx_sequence **next_seq_p)
{
        struct lzx_sequence *next_seq = *next_seq_p;
        unsigned mainsym;

        lzx_observe_match(&c->split_stats, length);

        mainsym = lzx_tally_main_and_lensyms(c, length, adjusted_offset,
                                             is_16_bit);
        next_seq->litrunlen_and_matchlen =
                (*litrunlen_p << SEQ_MATCHLEN_BITS) | length;
        next_seq->adjusted_offset_and_mainsym =
                (adjusted_offset << SEQ_MAINSYM_BITS) | mainsym;

        /* Update the recent offsets queue. */
        if (adjusted_offset < LZX_NUM_RECENT_OFFSETS) {
                /* Repeat offset match. */
                uint32_t temp = recent_offsets[adjusted_offset];
                recent_offsets[adjusted_offset] = recent_offsets[0];
                recent_offsets[0] = temp;
        } else {
                /* Explicit offset match. */

                /* Tally the aligned offset symbol if needed. */
                if (adjusted_offset >= LZX_MIN_ALIGNED_OFFSET + LZX_OFFSET_ADJUSTMENT)
                        c->freqs.aligned[adjusted_offset & LZX_ALIGNED_OFFSET_BITMASK]++;

                recent_offsets[2] = recent_offsets[1];
                recent_offsets[1] = recent_offsets[0];
                recent_offsets[0] = adjusted_offset - LZX_OFFSET_ADJUSTMENT;
        }

        /* Reset the literal run length and advance to the next sequence. */
        *next_seq_p = next_seq + 1;
        *litrunlen_p = 0;
}

/*
 * Called when the compressor ends a block.  This finshes the last lzx_sequence,
 * which is just a literal run with no following match.  This literal run might
 * be empty.
 */
static attrib_forceinline void
lzx_finish_sequence(struct lzx_sequence *last_seq, uint32_t litrunlen)
{
        last_seq->litrunlen_and_matchlen = litrunlen << SEQ_MATCHLEN_BITS;
}

/*
 * Find the longest repeat offset match with the current position.  If a match
 * is found, return its length and set *best_rep_idx_ret to the index of its
 * offset in @recent_offsets.  Otherwise, return 0.
 *
 * Don't bother with length 2 matches; consider matches of length >= 3 only.
 * Also assume that max_len >= 3.
 */
static unsigned
lzx_find_longest_repeat_offset_match(const uint8_t * const in_next,
                                     const uint32_t recent_offsets[],
                                     const unsigned max_len,
                                     unsigned *best_rep_idx_ret)
{
        STATIC_ASSERT(LZX_NUM_RECENT_OFFSETS == 3); /* loop is unrolled */

        const uint32_t seq3 = load_u24_unaligned(in_next);
        const uint8_t *matchptr;
        unsigned best_rep_len = 0;
        unsigned best_rep_idx = 0;
        unsigned rep_len;

        /* Check for rep0 match (most recent offset) */
        matchptr = in_next - recent_offsets[0];
        if (load_u24_unaligned(matchptr) == seq3)
                best_rep_len = lz_extend(in_next, matchptr, 3, max_len);

        /* Check for rep1 match (second most recent offset) */
        matchptr = in_next - recent_offsets[1];
        if (load_u24_unaligned(matchptr) == seq3) {
                rep_len = lz_extend(in_next, matchptr, 3, max_len);
                if (rep_len > best_rep_len) {
                        best_rep_len = rep_len;
                        best_rep_idx = 1;
                }
        }

        /* Check for rep2 match (third most recent offset) */
        matchptr = in_next - recent_offsets[2];
        if (load_u24_unaligned(matchptr) == seq3) {
                rep_len = lz_extend(in_next, matchptr, 3, max_len);
                if (rep_len > best_rep_len) {
                        best_rep_len = rep_len;
                        best_rep_idx = 2;
                }
        }

        *best_rep_idx_ret = best_rep_idx;
        return best_rep_len;
}

/*
 * Fast heuristic scoring for lazy parsing: how "good" is this match?
 * This is mainly determined by the length: longer matches are better.
 * However, we also give a bonus to close (small offset) matches and to repeat
 * offset matches, since those require fewer bits to encode.
 */

static attrib_forceinline unsigned
lzx_explicit_offset_match_score(unsigned len, uint32_t adjusted_offset)
{
        unsigned score = len;

        if (adjusted_offset < 4096)
                score++;
        if (adjusted_offset < 256)
                score++;

        return score;
}

static attrib_forceinline unsigned
lzx_repeat_offset_match_score(unsigned rep_len, unsigned rep_idx)
{
        return rep_len + 3;
}

/*
 * This is the "lazy" LZX compressor.  The basic idea is that before it chooses
 * a match, it checks to see if there's a longer match at the next position.  If
 * yes, it chooses a literal and continues to the next position.  If no, it
 * chooses the match.
 *
 * Some additional heuristics are used as well.  Repeat offset matches are
 * considered favorably and sometimes are chosen immediately.  In addition, long
 * matches (at least "nice_len" bytes) are chosen immediately as well.  Finally,
 * when we decide whether a match is "better" than another, we take the offset
 * into consideration as well as the length.
 */
static attrib_forceinline void
lzx_reset_lazy(struct liblzx_compressor *c, bool is_16_bit)
{
        bool streaming = (c->variant != LIBLZX_VARIANT_WIM);

        /* Initialize the matchfinder. */
        CALL_HC_MF(is_16_bit, c, hc_matchfinder_init, c->window_size,
                   streaming);
}

static void
lzx_reset_lazy_16(struct liblzx_compressor *c)
{
        lzx_reset_lazy(c, true);
}

static void
lzx_reset_lazy_32(struct liblzx_compressor *c)
{
        lzx_reset_lazy(c, false);
}

static attrib_forceinline void
lzx_compress_lazy(struct liblzx_compressor * restrict c,
                  const uint8_t * restrict in_begin, size_t in_nchunk,
                  size_t in_ndata, struct lzx_output_bitstream * restrict os,
                  bool is_16_bit)
{
        uint32_t max_offset                 = c->window_size;
        const uint8_t *         in_next = in_begin;
        const uint8_t * const in_chunk_end = in_begin + in_nchunk;
        const uint8_t *const in_data_end = in_begin + in_ndata;
        unsigned max_find_len = LZX_MAX_MATCH_LEN;
        unsigned max_produce_len = LZX_MAX_MATCH_LEN;
        unsigned nice_len = min_uint(c->nice_match_length, max_find_len);
        STATIC_ASSERT(LZX_NUM_RECENT_OFFSETS == 3);
        uint32_t recent_offsets[LZX_NUM_RECENT_OFFSETS];
        uint32_t next_hashes[2];

        if (max_offset >= LZX_MAX_WINDOW_SIZE) {
                /* Slightly shrink window to avoid offset values that are
                 * greater than 21 bits. */
                max_offset = LZX_MAX_WINDOW_SIZE - 1 - LZX_OFFSET_ADJUSTMENT;
        }

        in_begin -= c->in_prefix_size;

        /* Load the LRU queue and next hashes. */
        {
                int i;
                for (i = 0; i < LZX_NUM_RECENT_OFFSETS; i++) {
                        recent_offsets[i] = c->lru_queue[i];
                }

                next_hashes[0] = c->next_hashes[0];
                next_hashes[1] = c->next_hashes[1];
        }

        do {
                /* Starting a new block */

                const uint8_t * const in_block_begin = in_next;
                const uint8_t * const in_max_block_end =
                        in_next + min_size(SOFT_MAX_BLOCK_SIZE, in_chunk_end - in_next);
                struct lzx_sequence *next_seq = c->chosen_sequences;
                uint32_t litrunlen = 0;
                unsigned cur_len;
                uint32_t cur_offset;
                uint32_t cur_adjusted_offset;
                unsigned cur_score;
                unsigned next_len;
                uint32_t next_offset;
                uint32_t next_adjusted_offset;
                unsigned next_score;
                unsigned best_rep_len;
                unsigned best_rep_idx;
                unsigned rep_score;
                unsigned skip_len;

                lzx_reset_symbol_frequencies(c);
                lzx_init_block_split_stats(&c->split_stats);

                do {
                        /* Adjust max_len and nice_len if we're nearing the end
                         * of the input buffer. */
                        if (unlikely(max_produce_len >
                                     in_chunk_end - in_next)) {
                                max_produce_len = in_chunk_end - in_next;
                                max_find_len = in_data_end - in_next;
                                nice_len =
                                    min_uint(max_produce_len, nice_len);
                        }

                        /* Find the longest match (subject to the
                         * max_search_depth cutoff parameter) with the current
                         * position.  Don't bother with length 2 matches; only
                         * look for matches of length >= 3. */
                        {
                                size_t min_match_pos = in_next - in_begin;
                                min_match_pos -=
                                    min_size(min_match_pos, max_offset);

                                cur_len = CALL_HC_MF(is_16_bit, c,
                                                     hc_matchfinder_longest_match,
                                                     in_begin,
                                                     min_match_pos,
                                                     in_next,
                                                     2,
                                                     max_find_len,
                                                     max_produce_len,
                                                     nice_len,
                                                     c->max_search_depth,
                                                     next_hashes,
                                                     &cur_offset);
                        }

                        /* If there was no match found, or the only match found
                         * was a distant short match, then choose a literal. */
                        if (cur_len < 3 ||
                            (cur_len == 3 &&
                             cur_offset >= 8192 - LZX_OFFSET_ADJUSTMENT &&
                             cur_offset != recent_offsets[0] &&
                             cur_offset != recent_offsets[1] &&
                             cur_offset != recent_offsets[2]))
                        {
                                lzx_choose_literal(c, *in_next, &litrunlen);
                                in_next++;
                                continue;
                        }

                        /* Heuristic: if this match has the most recent offset,
                         * then go ahead and choose it as a rep0 match. */
                        if (cur_offset == recent_offsets[0]) {
                                in_next++;
                                skip_len = cur_len - 1;
                                cur_adjusted_offset = 0;
                                goto choose_cur_match;
                        }

                        /* Compute the longest match's score as an explicit
                         * offset match. */
                        cur_adjusted_offset = cur_offset + LZX_OFFSET_ADJUSTMENT;
                        cur_score = lzx_explicit_offset_match_score(cur_len, cur_adjusted_offset);

                        /* Find the longest repeat offset match at this
                         * position.  If we find one and it's "better" than the
                         * explicit offset match we found, then go ahead and
                         * choose the repeat offset match immediately. */
                        best_rep_len = lzx_find_longest_repeat_offset_match(in_next,
                                                                            recent_offsets,
                                                                            max_produce_len,
                                                                            &best_rep_idx);
                        in_next++;

                        if (best_rep_len != 0 &&
                            (rep_score = lzx_repeat_offset_match_score(best_rep_len,
                                                                       best_rep_idx)) >= cur_score)
                        {
                                cur_len = best_rep_len;
                                cur_adjusted_offset = best_rep_idx;
                                skip_len = best_rep_len - 1;
                                goto choose_cur_match;
                        }

                have_cur_match:
                        /*
                         * We have a match at the current position.  If the
                         * match is very long, then choose it immediately.
                         * Otherwise, see if there's a better match at the next
                         * position.
                         */

                        if (cur_len >= nice_len) {
                                skip_len = cur_len - 1;
                                goto choose_cur_match;
                        }

                        if (unlikely(max_produce_len >
                                     in_chunk_end - in_next)) {
                                max_produce_len = in_chunk_end - in_next;
                                max_find_len = in_data_end - in_next;
                                nice_len =
                                    min_uint(max_produce_len, nice_len);
                        }

                        {
                                size_t min_match_pos = in_next - in_begin;
                                min_match_pos -=
                                    min_uint(min_match_pos, max_offset);

                                next_len = CALL_HC_MF(
                                                      is_16_bit, c,
                                                      hc_matchfinder_longest_match,
                                                      in_begin,
                                                      min_match_pos,
                                                      in_next,
                                                      cur_len - 2,
                                                      max_find_len,
                                                      max_produce_len,
                                                      nice_len,
                                                      c->max_search_depth / 2,
                                                      next_hashes,
                                                      &next_offset);
                        }

                        if (next_len <= cur_len - 2) {
                                /* No potentially better match was found. */
                                in_next++;
                                skip_len = cur_len - 2;
                                goto choose_cur_match;
                        }

                        next_adjusted_offset = next_offset + LZX_OFFSET_ADJUSTMENT;
                        next_score = lzx_explicit_offset_match_score(next_len, next_adjusted_offset);

                        best_rep_len = lzx_find_longest_repeat_offset_match(in_next,
                                                                            recent_offsets,
                                                                            max_produce_len,
                                                                            &best_rep_idx);
                        in_next++;

                        if (best_rep_len != 0 &&
                            (rep_score = lzx_repeat_offset_match_score(best_rep_len,
                                                                       best_rep_idx)) >= next_score)
                        {

                                if (rep_score > cur_score) {
                                        /* The next match is better, and it's a
                                         * repeat offset match. */
                                        lzx_choose_literal(c, *(in_next - 2),
                                                           &litrunlen);
                                        cur_len = best_rep_len;
                                        cur_adjusted_offset = best_rep_idx;
                                        skip_len = cur_len - 1;
                                        goto choose_cur_match;
                                }
                        } else {
                                if (next_score > cur_score) {
                                        /* The next match is better, and it's an
                                         * explicit offset match. */
                                        lzx_choose_literal(c, *(in_next - 2),
                                                           &litrunlen);
                                        cur_len = next_len;
                                        cur_adjusted_offset = next_adjusted_offset;
                                        cur_score = next_score;
                                        goto have_cur_match;
                                }
                        }

                        /* The original match was better; choose it. */
                        skip_len = cur_len - 2;

                choose_cur_match:
                        /* Choose a match and have the matchfinder skip over its
                         * remaining bytes. */
                        lzx_choose_match(c, cur_len, cur_adjusted_offset,
                                         recent_offsets, is_16_bit,
                                         &litrunlen, &next_seq);

                        CALL_HC_MF(is_16_bit, c,
                                   hc_matchfinder_skip_bytes,
                                   in_begin,
                                   in_next,
                                   in_chunk_end,
                                   skip_len,
                                   next_hashes);
                        in_next += skip_len;

                        /* Keep going until it's time to end the block. */
                } while (in_next < in_max_block_end &&
                         !(c->split_stats.num_new_observations >=
                                        NUM_OBSERVATIONS_PER_BLOCK_CHECK &&
                           in_next - in_block_begin >= MIN_BLOCK_SIZE &&
                           in_chunk_end - in_next >= MIN_BLOCK_SIZE &&
                           lzx_should_end_block(&c->split_stats)));

                /* Flush the block. */
                lzx_finish_sequence(next_seq, litrunlen);
                lzx_flush_block(c, os, in_block_begin, in_next - in_block_begin, 0);

                /* Keep going until we've reached the end of the input buffer. */
        } while (in_next != in_chunk_end);

        /* Save the LRU queue and next hashes */
        {
                int i;
                for (i = 0; i < LZX_NUM_RECENT_OFFSETS; i++) {
                        c->lru_queue[i] = recent_offsets[i];
                }
                c->next_hashes[0] = next_hashes[0];
                c->next_hashes[1] = next_hashes[1];
        }
}

static void
lzx_compress_lazy_16(struct liblzx_compressor *c, const uint8_t *in,
                     size_t in_nchunk, size_t in_navail,
                     struct lzx_output_bitstream *os)
{
        lzx_compress_lazy(c, in, in_nchunk, in_navail, os, true);
}

static void
lzx_compress_lazy_32(struct liblzx_compressor *c, const uint8_t *in,
                     size_t in_nchunk, size_t in_navail,
                     struct lzx_output_bitstream *os)
{
        lzx_compress_lazy(c, in, in_nchunk, in_navail, os, false);
}

static void
lzx_cull_lazy_16(struct liblzx_compressor *c, size_t nbytes)
{
        CALL_HC_MF(true, c, hc_matchfinder_cull, nbytes, c->window_size);
}

static void
lzx_cull_lazy_32(struct liblzx_compressor *c, size_t nbytes)
{
        CALL_HC_MF(false, c, hc_matchfinder_cull, nbytes, c->window_size);
}

/******************************************************************************/
/*                          Compressor operations                             */
/*----------------------------------------------------------------------------*/

/*
 * Generate tables for mapping match offsets (actually, "adjusted" match
 * offsets) to offset slots.
 */
static void
lzx_init_offset_slot_tabs(struct liblzx_compressor *c)
{
        uint32_t adjusted_offset = 0;
        unsigned slot = 0;

        /* slots [0, 29] */
        for (; adjusted_offset < ARRAY_LEN(c->offset_slot_tab_1);
             adjusted_offset++)
        {
                if (adjusted_offset >= lzx_offset_slot_base[slot + 1] +
                                       LZX_OFFSET_ADJUSTMENT)
                        slot++;
                c->offset_slot_tab_1[adjusted_offset] = slot;
        }

        /* slots [30, 49] */
        for (; adjusted_offset < LZX_MAX_WINDOW_SIZE;
             adjusted_offset += (uint32_t)1 << 14)
        {
                if (adjusted_offset >= lzx_offset_slot_base[slot + 1] +
                                       LZX_OFFSET_ADJUSTMENT)
                        slot++;
                c->offset_slot_tab_2[adjusted_offset >> 14] = slot;
        }
}

static size_t
lzx_bt_max_search_depth(unsigned compression_level)
{
        return (24 * compression_level) / 50;
}

static size_t
lzx_get_compressor_size(size_t window_size, unsigned compression_level,
        bool streaming)
{

        if (compression_level <= MAX_FAST_LEVEL) {
                if (lzx_is_16_bit(window_size))
                        return offsetof(struct liblzx_compressor, hc_mf_16) +
                               hc_matchfinder_size_16(window_size, streaming);
                else
                        return offsetof(struct liblzx_compressor, hc_mf_32) +
                               hc_matchfinder_size_32(window_size, streaming);
        } else {
                if (lzx_is_16_bit(window_size))
                        return offsetof(struct liblzx_compressor, bt_mf_16) +
                               bt_matchfinder_size_16(window_size, streaming);
                else
                        return offsetof(struct liblzx_compressor, bt_mf_32) +
                               bt_matchfinder_size_32(window_size, streaming);
        }
}

/* Compress a buffer of data. */
static void
lzx_reset(struct liblzx_compressor *c)
{
        /* Initially, the previous Huffman codeword lengths are all zeroes. */
        c->codes_index = 0;
        memset(&c->codes[1].lens, 0, sizeof(struct lzx_lens));

        /* Reset the E8 preprocessor offset */
        c->e8_chunk_offset = 0;

        /* Reset the streaming prefix */
        c->in_prefix_size = 0;

        /* Reset the LRU queue */
        {
                int i;
                for (i = 0; i < LZX_NUM_RECENT_OFFSETS; i++) {
                        c->lru_queue[i] = 1;
                }
        }

        /* Reset next hashes */
        c->next_hashes[0] = 0;
        c->next_hashes[1] = 0;

        c->reset(c);
}

/* Allocate an LZX compressor. */
liblzx_compressor_t *
liblzx_compress_create(const struct liblzx_compress_properties *props)
{
        unsigned window_order;
        struct liblzx_compressor *c;
        bool streaming = (props->lzx_variant != LIBLZX_VARIANT_WIM);

        /* Validate the maximum buffer size and get the window order from it. */
        window_order = lzx_get_window_order(props->window_size);
        if (window_order == 0)
                return NULL;

        /* Allocate the compressor. */
        c = props->alloc_func(props->userdata,
            lzx_get_compressor_size(props->window_size, props->compression_level, streaming));
        if (!c)
                goto oom0;

        c->alloc_func = props->alloc_func;
        c->free_func = props->free_func;
        c->alloc_userdata = props->userdata;
        c->window_size = props->window_size;
        c->window_order = window_order;
        c->num_main_syms = lzx_get_num_main_syms(window_order);
        c->variant = props->lzx_variant;
        c->first_block = true;
        c->out_chunk.data = NULL;
        c->out_chunk.size = 0;
        c->flushing = false;
        c->e8_chunk_offset = 0;
        c->e8_file_size = props->e8_file_size;
        c->in_buffer_capacity = c->window_size;
        c->in_prefix_size = 0;
        c->in_used = 0;
        c->chunk_size = props->chunk_granularity;

        /* Allocate the buffer for preprocessed data if needed. */
        if (streaming) {
                /* Pad out to include past blocks and extra
                 * matchfinding space  */
                c->in_buffer_capacity *= 2;
                c->in_buffer_capacity +=
                    LZX_MAX_MATCH_LEN + LZX_E8_FILTER_TAIL_SIZE;
        }

        if (c->variant == LIBLZX_VARIANT_WIM)
                c->e8_file_size = LZX_WIM_MAGIC_FILESIZE;

        c->in_buffer =
            props->alloc_func(props->userdata, c->in_buffer_capacity);

        if (!c->in_buffer)
                goto oom1;

        c->out_buffer_capacity = c->chunk_size;
        if (c->variant != LIBLZX_VARIANT_WIM)
                c->out_buffer_capacity += 6144;

        c->out_chunk.data = c->out_buffer =
            props->alloc_func(props->userdata, c->out_buffer_capacity);

        if (!c->out_buffer)
                goto oom2;

        if (props->compression_level <= MAX_FAST_LEVEL) {

                /* Fast compression: Use lazy parsing. */
                if (lzx_is_16_bit(props->window_size)) {
                        c->reset = lzx_reset_lazy_16;
                        c->impl = lzx_compress_lazy_16;
                        c->cull = lzx_cull_lazy_16;
                } else {
                        c->reset = lzx_reset_lazy_32;
                        c->impl = lzx_compress_lazy_32;
                        c->cull = lzx_cull_lazy_32;
                }

                /* Scale max_search_depth and nice_match_length with the
                 * compression level. */
                c->max_search_depth = (60 * props->compression_level) / 20;
                c->nice_match_length = (80 * props->compression_level) / 20;

                /* lzx_compress_lazy() needs max_search_depth >= 2 because it
                 * halves the max_search_depth when attempting a lazy match, and
                 * max_search_depth must be at least 1. */
                c->max_search_depth = max_uint(c->max_search_depth, 2);
        } else {

                /* Normal / high compression: Use near-optimal parsing. */
                if (lzx_is_16_bit(c->window_size)) {
                        c->reset = lzx_reset_near_optimal_16;
                        c->impl = lzx_compress_near_optimal_16;
                        c->cull = lzx_cull_near_optimal_16;
                } else {
                        c->reset = lzx_reset_near_optimal_32;
                        c->impl = lzx_compress_near_optimal_32;
                        c->cull = lzx_cull_near_optimal_32;
                }

                /* Scale max_search_depth and nice_match_length with the
                 * compression level. */
                c->max_search_depth = lzx_bt_max_search_depth(props->compression_level);
                c->nice_match_length = (48 * props->compression_level) / 50;

                /* Also scale num_optim_passes with the compression level.  But
                 * the more passes there are, the less they help --- so don't
                 * add them linearly.  */
                c->num_optim_passes = 1;
                c->num_optim_passes += (props->compression_level >= 45);
                c->num_optim_passes += (props->compression_level >= 70);
                c->num_optim_passes += (props->compression_level >= 100);
                c->num_optim_passes += (props->compression_level >= 150);
                c->num_optim_passes += (props->compression_level >= 200);
                c->num_optim_passes += (props->compression_level >= 300);

                /* max_search_depth must be at least 1. */
                c->max_search_depth = max_uint(c->max_search_depth, 1);
        }

        /* Prepare the offset => offset slot mapping. */
        lzx_init_offset_slot_tabs(c);

        lzx_reset(c);

        return c;

oom2:
        props->free_func(props->userdata, c->in_buffer);
oom1:
        props->free_func(props->userdata, c);
oom0:
        return NULL;
}

/* Compress a buffer of data. */
static size_t
lzx_compress_chunk(struct liblzx_compressor *c)
{
        struct lzx_output_bitstream os;
        size_t result;
        bool e8_preprocess_enabled = (c->e8_chunk_offset < 0x40000000);
        bool next_e8_preprocess_enabled =
            (c->e8_chunk_offset + c->chunk_size < 0x40000000);
        uint32_t chunk_size = min_u32(c->chunk_size, c->in_used);
        uint32_t next_chunk_preprocess_size = 0;

        uint8_t *in = (uint8_t *)c->in_buffer + c->in_prefix_size;

        /* Preprocess the input data. */
        if (e8_preprocess_enabled) {
                lzx_preprocess(in, chunk_size, c->e8_chunk_offset,
                               c->e8_file_size);
        }

        if (c->in_used > c->chunk_size && next_e8_preprocess_enabled) {
                next_chunk_preprocess_size =
                    min_u32(LZX_MAX_MATCH_LEN + LZX_E8_FILTER_TAIL_SIZE,
                            c->in_used - c->chunk_size);
        }

        /* Preprocess enough of the next block input data for the
           matchfinder */
        if (next_chunk_preprocess_size > 0) {
                lzx_preprocess(in + c->chunk_size, next_chunk_preprocess_size,
                               c->e8_chunk_offset + c->chunk_size,
                               c->e8_file_size);
        }

        /* Initialize the output bitstream. */
        lzx_init_output(&os, c->out_buffer, c->out_buffer_capacity);

        /* Call the compression level-specific compress() function. */
        (*c->impl)(c, in, chunk_size, c->in_used, &os);

        /* Undo next block preprocessing */
        if (next_chunk_preprocess_size > 0) {
                lzx_postprocess(in + c->chunk_size, next_chunk_preprocess_size,
                               c->e8_chunk_offset + c->chunk_size,
                               c->e8_file_size);
        }

        /* Flush the output bitstream. */
        result = lzx_flush_output(&os);

        /* Update the E8 chunk offset. */
        c->e8_chunk_offset += (uint32_t)chunk_size;

        /* Update the prefix and used amounts. */
        c->in_prefix_size += (uint32_t)chunk_size;
        c->in_used -= chunk_size;

        if (c->in_prefix_size >= c->window_size * 2) {
                uint32_t cull_amount = (c->in_prefix_size - c->window_size);

                in = (uint8_t *)c->in_buffer + c->in_prefix_size;

                memmove(c->in_buffer, in - c->window_size,
                        c->in_used + c->window_size);
                c->in_prefix_size = c->window_size;

                (*c->cull)(c, cull_amount);
        }

        /* Return the number of compressed bytes, or 0 if the input did not
         * compress to less than its original size. */
        return result;
}

void
liblzx_compress_destroy(liblzx_compressor_t *c)
{
        c->free_func(c->alloc_userdata, c->out_buffer);
        c->free_func(c->alloc_userdata, c->in_buffer);
        c->free_func(c->alloc_userdata, c);
}

size_t
liblzx_compress_add_input(liblzx_compressor_t *c, const void *in_data,
                          size_t in_data_size)
{
        uint32_t max_used = 0;
        size_t fill_amount = 0;

        if (c->out_chunk.size > 0 || c->flushing)
                return 0;

        max_used = min_uint(c->in_buffer_capacity - c->in_prefix_size,
                            c->chunk_size + LZX_MAX_MATCH_LEN +
                                LZX_E8_FILTER_TAIL_SIZE);
        fill_amount = min_size(in_data_size, max_used - c->in_used);

        memcpy(((uint8_t *)c->in_buffer) + c->in_prefix_size + c->in_used, in_data,
               fill_amount);

        c->in_used += fill_amount;

        if (c->in_used == max_used) {
                c->out_chunk.size = lzx_compress_chunk(c);
        }

        return fill_amount;
}

const liblzx_output_chunk_t *
liblzx_compress_get_next_chunk(const liblzx_compressor_t *c)
{
        if (c->out_chunk.size > 0)
                return &c->out_chunk;
        else
                return NULL;
}

void
liblzx_compress_release_next_chunk(liblzx_compressor_t *c)
{
        c->out_chunk.size = 0;
        if (c->flushing && c->in_used > 0) {
                c->out_chunk.size = lzx_compress_chunk(c);
        }
}

void
liblzx_compress_end_input(liblzx_compressor_t *c)
{
        if (!c->flushing) {
                c->flushing = true;
                if (c->in_used > 0 && c->out_chunk.size == 0) {
                        c->out_chunk.size = lzx_compress_chunk(c);
                }
        }
}
