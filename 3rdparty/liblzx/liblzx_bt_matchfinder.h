/*
 * bt_matchfinder.h - Lempel-Ziv matchfinding with a hash table of binary trees
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
 *
 * ----------------------------------------------------------------------------
 *
 * This is a Binary Trees (bt) based matchfinder.
 *
 * The main data structure is a hash table where each hash bucket contains a
 * binary tree of sequences whose first 4 bytes share the same hash code.  Each
 * sequence is identified by its starting position in the input buffer.  Each
 * binary tree is always sorted such that each left child represents a sequence
 * lexicographically lesser than its parent and each right child represents a
 * sequence lexicographically greater than its parent.
 *
 * The algorithm processes the input buffer sequentially.  At each byte
 * position, the hash code of the first 4 bytes of the sequence beginning at
 * that position (the sequence being matched against) is computed.  This
 * identifies the hash bucket to use for that position.  Then, a new binary tree
 * node is created to represent the current sequence.  Then, in a single tree
 * traversal, the hash bucket's binary tree is searched for matches and is
 * re-rooted at the new node.
 *
 * Compared to the simpler algorithm that uses linked lists instead of binary
 * trees (see hc_matchfinder.h), the binary tree version gains more information
 * at each node visitation.  Ideally, the binary tree version will examine only
 * 'log(n)' nodes to find the same matches that the linked list version will
 * find by examining 'n' nodes.  In addition, the binary tree version can
 * examine fewer bytes at each node by taking advantage of the common prefixes
 * that result from the sort order, whereas the linked list version may have to
 * examine up to the full length of the match at each node.
 *
 * However, it is not always best to use the binary tree version.  It requires
 * nearly twice as much memory as the linked list version, and it takes time to
 * keep the binary trees sorted, even at positions where the compressor does not
 * need matches.  Generally, when doing fast compression on small buffers,
 * binary trees are the wrong approach.  They are best suited for thorough
 * compression and/or large buffers.
 *
 * ----------------------------------------------------------------------------
 */


#include <string.h>

#include "liblzx_matchfinder_common.h"

#define BT_MATCHFINDER_HASH3_ORDER 15
#define BT_MATCHFINDER_HASH3_WAYS  2
#define BT_MATCHFINDER_HASH4_ORDER 16

/* TEMPLATED functions and structures have MF_SUFFIX appended to their name.  */
#undef TEMPLATED
#define TEMPLATED(name)                CONCAT(name, MF_SUFFIX)

#ifndef _LIBLZX_BT_MATCHFINDER_H
#define _LIBLZX_BT_MATCHFINDER_H

/* Non-templated definitions  */

/* Representation of a match found by the bt_matchfinder  */
struct lz_match {

        /* The number of bytes matched.  */
        uint32_t length;

        /* The offset back from the current position that was matched.  */
        uint32_t offset;
};

#endif /* _LIBLZX_BT_MATCHFINDER_H */

struct TEMPLATED(bt_matchfinder) {

        /* The hash table for finding length 2 matches, if enabled  */
#ifdef BT_MATCHFINDER_HASH2_ORDER
        mf_pos_t hash2_tab[1UL << BT_MATCHFINDER_HASH2_ORDER];
#endif

        /* The hash table for finding length 3 matches  */
        mf_pos_t hash3_tab[1UL << BT_MATCHFINDER_HASH3_ORDER][BT_MATCHFINDER_HASH3_WAYS];

        /* The hash table which contains the roots of the binary trees for
         * finding length 4+ matches  */
        mf_pos_t hash4_tab[1UL << BT_MATCHFINDER_HASH4_ORDER];

        /* The child node references for the binary trees.  The left and right
         * children of the node for the sequence with position 'pos' are
         * 'child_tab[pos * 2]' and 'child_tab[pos * 2 + 1]', respectively.  */
        mf_pos_t child_tab[];
};

static attrib_forceinline bool
TEMPLATED(matchfinder_is_valid_pos)(mf_pos_t pos, mf_pos_t min_pos)
{
        return ((pos + 1) & MF_INVALID_POS) > min_pos;
}

static attrib_forceinline void
TEMPLATED(matchfinder_rebase)(mf_pos_t * mf_base, size_t count,
                              mf_pos_t cull_amount)
{
        /* The invalid value points to the last element of the buffer. */
        /* Since no match can start from that byte, it is always invalid. */
        while (count > 0) {
                mf_pos_t pos = *mf_base;

                if (pos < cull_amount || pos == MF_INVALID_POS) {
                        *mf_base = MF_INVALID_POS;
                } else {
                        *mf_base -= cull_amount;
                }

                mf_base++;
                count--;
        }
}

/* Return the number of bytes that must be allocated for a 'bt_matchfinder' that
 * can work with buffers up to the specified size.  */
static attrib_forceinline size_t
TEMPLATED(bt_matchfinder_size)(size_t max_bufsize, bool streaming)
{
        const size_t streaming_bufsize_mul = streaming ? 4 : 2;

        const size_t base_size =
            sizeof(struct TEMPLATED(bt_matchfinder)) +
            (streaming_bufsize_mul * max_bufsize * sizeof(mf_pos_t));

        return base_size;
}

/* Prepare the matchfinder for a new input buffer.  */
static attrib_forceinline void
TEMPLATED(bt_matchfinder_init)(struct TEMPLATED(bt_matchfinder) *mf)
{
        memset(mf, 0xFF, sizeof(*mf));
}

static attrib_forceinline mf_pos_t *
TEMPLATED(bt_left_child)(struct TEMPLATED(bt_matchfinder) *mf, uint32_t node)
{
        return &mf->child_tab[(node << 1) + 0];
}

static attrib_forceinline mf_pos_t *
TEMPLATED(bt_right_child)(struct TEMPLATED(bt_matchfinder) *mf, uint32_t node)
{
        return &mf->child_tab[(node << 1) + 1];
}

/* The minimum permissible value of 'max_len' for bt_matchfinder_get_matches()
 * and bt_matchfinder_skip_byte().  There must be sufficiently many bytes
 * remaining to load a 32-bit integer from the *next* position.  */
#define BT_MATCHFINDER_REQUIRED_NBYTES        5

/* Advance the binary tree matchfinder by one byte, optionally recording
 * matches.  @record_matches should be a compile-time constant.  */
static attrib_forceinline struct lz_match *
TEMPLATED(bt_matchfinder_advance_one_byte)(struct TEMPLATED(bt_matchfinder) * const mf,
                                           const uint8_t * const in_begin,
                                           mf_pos_t in_min_pos,
                                           const ptrdiff_t cur_pos,
                                           const uint32_t max_find_len,
                                           const uint32_t max_produce_len,
                                           const uint32_t nice_len,
                                           const uint32_t max_search_depth,
                                           uint32_t * const next_hashes,
                                           uint32_t * const best_len_ret,
                                           struct lz_match *lz_matchptr,
                                           const bool record_matches)
{
        const uint8_t *in_next = in_begin + cur_pos;
        uint32_t depth_remaining = max_search_depth;
        uint32_t next_hashseq;
        uint32_t hash3;
        uint32_t hash4;
#ifdef BT_MATCHFINDER_HASH2_ORDER
        uint16_t seq2;
        uint32_t hash2;
#endif
        STATIC_ASSERT(BT_MATCHFINDER_HASH3_WAYS >= 1 &&
                      BT_MATCHFINDER_HASH3_WAYS <= 2);
        uint32_t cur_node;
#if BT_MATCHFINDER_HASH3_WAYS >= 2
        uint32_t cur_node_2;
#endif
        const uint8_t *matchptr;
        mf_pos_t *pending_lt_ptr, *pending_gt_ptr;
        uint32_t best_lt_len, best_gt_len;
        uint32_t len;
        uint32_t best_len = 3;

        next_hashseq = get_unaligned_le32(in_next + 1);

        hash3 = next_hashes[0];
        hash4 = next_hashes[1];

        next_hashes[0] = lz_hash(next_hashseq & 0xFFFFFF, BT_MATCHFINDER_HASH3_ORDER);
        next_hashes[1] = lz_hash(next_hashseq, BT_MATCHFINDER_HASH4_ORDER);
        prefetchw(&mf->hash3_tab[next_hashes[0]]);
        prefetchw(&mf->hash4_tab[next_hashes[1]]);

#ifdef BT_MATCHFINDER_HASH2_ORDER
        seq2 = load_u16_unaligned(in_next);
        hash2 = lz_hash(seq2, BT_MATCHFINDER_HASH2_ORDER);
        cur_node = mf->hash2_tab[hash2];
        mf->hash2_tab[hash2] = cur_pos;
        if (record_matches &&
            TEMPLATED(matchfinder_is_valid_pos)(cur_node, in_min_pos) &&
            seq2 == load_u16_unaligned(&in_begin[cur_node]))
        {
                lz_matchptr->length = 2;
                lz_matchptr->offset = in_next - &in_begin[cur_node];
                lz_matchptr++;
        }
#endif

        cur_node = mf->hash3_tab[hash3][0];
        mf->hash3_tab[hash3][0] = cur_pos;
#if BT_MATCHFINDER_HASH3_WAYS >= 2
        cur_node_2 = mf->hash3_tab[hash3][1];
        mf->hash3_tab[hash3][1] = cur_node;
#endif
        if (record_matches &&
            TEMPLATED(matchfinder_is_valid_pos)(cur_node, in_min_pos)) {
                uint32_t seq3 = load_u24_unaligned(in_next);
                if (seq3 == load_u24_unaligned(&in_begin[cur_node]) &&
                        likely(cur_node >= in_min_pos)) {
                        lz_matchptr->length = 3;
                        lz_matchptr->offset = in_next - &in_begin[cur_node];
                        lz_matchptr++;
                }
        #if BT_MATCHFINDER_HASH3_WAYS >= 2
                else if (TEMPLATED(matchfinder_is_valid_pos)(cur_node_2,
                                                             in_min_pos) &&
                        seq3 == load_u24_unaligned(&in_begin[cur_node_2])) {
                        lz_matchptr->length = 3;
                        lz_matchptr->offset = in_next - &in_begin[cur_node_2];
                        lz_matchptr++;
                }
        #endif
        }

        cur_node = mf->hash4_tab[hash4];
        mf->hash4_tab[hash4] = cur_pos;

        pending_lt_ptr = TEMPLATED(bt_left_child)(mf, cur_pos);
        pending_gt_ptr = TEMPLATED(bt_right_child)(mf, cur_pos);

        if (!TEMPLATED(matchfinder_is_valid_pos)(cur_node, in_min_pos)) {
                *pending_lt_ptr = MF_INVALID_POS;
                *pending_gt_ptr = MF_INVALID_POS;
                *best_len_ret = best_len;
                return lz_matchptr;
        }

        best_lt_len = 0;
        best_gt_len = 0;
        len = 0;

        for (;;) {
                matchptr = &in_begin[cur_node];

                if (matchptr[len] == in_next[len]) {
                        len = lz_extend(in_next, matchptr, len + 1, max_find_len);
                        if (!record_matches || len > best_len) {
                                if (record_matches) {
                                        best_len = len;
                                        lz_matchptr->length = min_u32(len, max_produce_len);
                                        lz_matchptr->offset =
                                                in_next - matchptr;
                                        lz_matchptr++;
                                }
                                if (len >= nice_len) {
                                        *pending_lt_ptr =
                                                *TEMPLATED(bt_left_child)(mf, cur_node);
                                        *pending_gt_ptr =
                                                *TEMPLATED(bt_right_child)(mf, cur_node);
                                        *best_len_ret = best_len;
                                        return lz_matchptr;
                                }
                        }
                }

                if (matchptr[len] < in_next[len]) {
                        *pending_lt_ptr = cur_node;
                        pending_lt_ptr = TEMPLATED(bt_right_child)(mf, cur_node);
                        cur_node = *pending_lt_ptr;
                        best_lt_len = len;
                        if (best_gt_len < len)
                                len = best_gt_len;
                } else {
                        *pending_gt_ptr = cur_node;
                        pending_gt_ptr = TEMPLATED(bt_left_child)(mf, cur_node);
                        cur_node = *pending_gt_ptr;
                        best_gt_len = len;
                        if (best_lt_len < len)
                                len = best_lt_len;
                }

                if (!TEMPLATED(matchfinder_is_valid_pos)(cur_node,
                                                         in_min_pos) ||
                    !--depth_remaining) {
                        *pending_lt_ptr = MF_INVALID_POS;
                        *pending_gt_ptr = MF_INVALID_POS;
                        *best_len_ret = best_len;

                        return lz_matchptr;
                }
        }
}

/*
 * Retrieve a list of matches with the current position.
 *
 * @mf
 *        The matchfinder structure.
 * @in_begin
 *        Pointer to the beginning of the input buffer.
 * @in_abs_pos
 *        Absolute position of in_begin in the file
 * @cur_pos
 *        The current position in the input buffer relative to @in_begin (the
 *        position of the sequence being matched against).
 * @max_len
 *        The maximum permissible match length at this position.  Must be >=
 *        BT_MATCHFINDER_REQUIRED_NBYTES.
 * @nice_len
 *        Stop searching if a match of at least this length is found.
 *        Must be <= @max_len.
 * @max_search_depth
 *        Limit on the number of potential matches to consider.  Must be >= 1.
 * @next_hashes
 *        The precomputed hash codes for the sequence beginning at @in_next.
 *        These will be used and then updated with the precomputed hashcodes for
 *        the sequence beginning at @in_next + 1.
 * @best_len_ret
 *        If a match of length >= 4 was found, then the length of the longest such
 *        match is written here; otherwise 3 is written here.  (Note: this is
 *        redundant with the 'struct lz_match' array, but this is easier for the
 *        compiler to optimize when inlined and the caller immediately does a
 *        check against 'best_len'.)
 * @lz_matchptr
 *        An array in which this function will record the matches.  The recorded
 *        matches will be sorted by strictly increasing length and (non-strictly)
 *        increasing offset.  The maximum number of matches that may be found is
 *        'nice_len - 1', or one less if length 2 matches are disabled.
 *
 * The return value is a pointer to the next available slot in the @lz_matchptr
 * array.  (If no matches were found, this will be the same as @lz_matchptr.)
 */
static attrib_forceinline struct lz_match *
TEMPLATED(bt_matchfinder_get_matches)(struct TEMPLATED(bt_matchfinder) *mf,
                                      const uint8_t *in_begin,
                                      uint32_t in_min_pos,
                                      ptrdiff_t cur_pos,
                                      uint32_t max_find_len,
                                      uint32_t max_produce_len,
                                      uint32_t nice_len,
                                      uint32_t max_search_depth,
                                      uint32_t next_hashes[2],
                                      uint32_t *best_len_ret,
                                      struct lz_match *lz_matchptr)
{
        return TEMPLATED(bt_matchfinder_advance_one_byte)(mf,
                                                          in_begin,
                                                          in_min_pos,
                                                          cur_pos,
                                                          max_find_len,
                                                          max_produce_len,
                                                          nice_len,
                                                          max_search_depth,
                                                          next_hashes,
                                                          best_len_ret,
                                                          lz_matchptr,
                                                          true);
}

/*
 * Advance the matchfinder, but don't record any matches.
 *
 * This is very similar to bt_matchfinder_get_matches() because both functions
 * must do hashing and tree re-rooting.
 */
static attrib_forceinline void
TEMPLATED(bt_matchfinder_skip_byte)(struct TEMPLATED(bt_matchfinder) *mf,
                                    const uint8_t *in_begin,
                                    uint32_t in_min_pos,
                                    ptrdiff_t cur_pos,
                                    uint32_t nice_len,
                                    uint32_t max_search_depth,
                                    uint32_t next_hashes[2])
{
        uint32_t best_len;
        TEMPLATED(bt_matchfinder_advance_one_byte)(mf,
                                                   in_begin,
                                                   in_min_pos,
                                                   cur_pos,
                                                   nice_len,
                                                   nice_len,
                                                   nice_len,
                                                   max_search_depth,
                                                   next_hashes,
                                                   &best_len,
                                                   NULL,
                                                   false);
}

/*
 * Culls any matches that are lower than a specified offset and reduces any
 * remaining offsets by the same amount.
 */
static attrib_forceinline void
TEMPLATED(bt_matchfinder_cull)(struct TEMPLATED(bt_matchfinder) * mf,
                               uint32_t cull_size, uint32_t window_size)
{
        size_t mf_size = TEMPLATED(bt_matchfinder_size)(window_size, true);

        const size_t mf_count = mf_size / sizeof(mf_pos_t);

        TEMPLATED(matchfinder_rebase)((mf_pos_t *)mf, mf_count, cull_size);
}
