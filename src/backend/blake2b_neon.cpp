// Copyright (c) 2025-2026, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "blake2b_compress.h"

/*
 * ARM NEON vectorised BLAKE2b compression.
 * Uses 2x uint64x2_t to represent 4-lane column/diagonal groups.
 *
 * Optimizations over baseline:
 *  - vcombine_u64/vcreate_u64 for message loading (no stack roundtrips)
 *  - vqtbl1q_u8 byte-shuffle for 16-bit and 24-bit rotations (AArch64)
 *  - vsli for 63-bit rotation (2 ops instead of 3)
 *  - Direct vectorized row4 initialization
 */

#if defined(__ARM_NEON) || defined(__aarch64__) || defined(_M_ARM64)

#include "../internal/endian.h"
#include <arm_neon.h>

namespace tinyblake {

static const uint64_t IV[8] = {0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
                               0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
                               0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
                               0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL};

static const uint8_t SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

static inline uint64x2_t rotr64_32(uint64x2_t x) {
  return vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64(x)));
}

#if defined(__aarch64__) || defined(_M_ARM64)

/* AArch64: use vqtbl1q_u8 byte-shuffle for 16-bit and 24-bit rotations */

static inline uint64x2_t rotr64_24(uint64x2_t x, uint8x16_t tbl) {
  return vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(x), tbl));
}

static inline uint64x2_t rotr64_16(uint64x2_t x, uint8x16_t tbl) {
  return vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(x), tbl));
}

#else

/* 32-bit ARM NEON: shift+or fallback */

static inline uint64x2_t rotr64_24(uint64x2_t x, uint8x16_t) {
  return vorrq_u64(vshrq_n_u64(x, 24), vshlq_n_u64(x, 40));
}

static inline uint64x2_t rotr64_16(uint64x2_t x, uint8x16_t) {
  return vorrq_u64(vshrq_n_u64(x, 16), vshlq_n_u64(x, 48));
}

#endif

static inline uint64x2_t rotr64_63(uint64x2_t x) {
  /* vsli: shift-left-and-insert — merges (x << 1) into (x >> 63) */
  return vsliq_n_u64(vshrq_n_u64(x, 63), x, 1);
}

#define G_NEON(a, b, c, d, mx, my)                                             \
  do {                                                                         \
    a = vaddq_u64(vaddq_u64(a, b), mx);                                        \
    d = rotr64_32(veorq_u64(d, a));                                            \
    c = vaddq_u64(c, d);                                                       \
    b = rotr64_24(veorq_u64(b, c), rot24_tbl);                                 \
    a = vaddq_u64(vaddq_u64(a, b), my);                                        \
    d = rotr64_16(veorq_u64(d, a), rot16_tbl);                                 \
    c = vaddq_u64(c, d);                                                       \
    b = rotr64_63(veorq_u64(b, c));                                            \
  } while (0)

void blake2b_compress_neon(uint64_t state[8], const uint8_t block[128],
                           uint64_t t0, uint64_t t1, bool last) {
  uint64_t m[16];
  for (int i = 0; i < 16; ++i) {
    m[i] = detail::load_le64(block + i * 8);
  }

  /* Byte-shuffle tables for rotations (preloaded once) */
  static const uint8_t rot16_bytes[16] = {2,  3,  4,  5,  6,  7,  0, 1,
                                          10, 11, 12, 13, 14, 15, 8, 9};
  static const uint8_t rot24_bytes[16] = {3,  4,  5,  6,  7,  0, 1, 2,
                                          11, 12, 13, 14, 15, 8, 9, 10};
  const uint8x16_t rot16_tbl = vld1q_u8(rot16_bytes);
  const uint8x16_t rot24_tbl = vld1q_u8(rot24_bytes);

  /* Load state into NEON registers (2 lanes each) */
  uint64x2_t row1a = vld1q_u64(state);     /* v0, v1 */
  uint64x2_t row1b = vld1q_u64(state + 2); /* v2, v3 */
  uint64x2_t row2a = vld1q_u64(state + 4); /* v4, v5 */
  uint64x2_t row2b = vld1q_u64(state + 6); /* v6, v7 */

  uint64x2_t row3a = vld1q_u64(&IV[0]); /* v8, v9 */
  uint64x2_t row3b = vld1q_u64(&IV[2]); /* v10, v11 */

  /* Vectorized row4 initialization — no stack arrays */
  uint64x2_t row4a =
      veorq_u64(vcombine_u64(vcreate_u64(IV[4]), vcreate_u64(IV[5])),
                vcombine_u64(vcreate_u64(t0), vcreate_u64(t1)));
  uint64x2_t row4b =
      vcombine_u64(vcreate_u64(last ? (IV[6] ^ 0xFFFFFFFFFFFFFFFFULL) : IV[6]),
                   vcreate_u64(IV[7]));

  uint64x2_t orig1a = row1a, orig1b = row1b;
  uint64x2_t orig2a = row2a, orig2b = row2b;

  for (int r = 0; r < 12; ++r) {
    const uint8_t *s = SIGMA[r];

    /* Column step: G(0..3) */
    {
      uint64x2_t mx = vcombine_u64(vcreate_u64(m[s[0]]), vcreate_u64(m[s[2]]));
      uint64x2_t my = vcombine_u64(vcreate_u64(m[s[1]]), vcreate_u64(m[s[3]]));
      G_NEON(row1a, row2a, row3a, row4a, mx, my);
    }
    {
      uint64x2_t mx = vcombine_u64(vcreate_u64(m[s[4]]), vcreate_u64(m[s[6]]));
      uint64x2_t my = vcombine_u64(vcreate_u64(m[s[5]]), vcreate_u64(m[s[7]]));
      G_NEON(row1b, row2b, row3b, row4b, mx, my);
    }

    /* Diagonalize */
    {
      uint64x2_t t2a = vextq_u64(row2a, row2b, 1);
      uint64x2_t t2b = vextq_u64(row2b, row2a, 1);
      row2a = t2a;
      row2b = t2b;

      uint64x2_t t3a = row3b;
      uint64x2_t t3b = row3a;
      row3a = t3a;
      row3b = t3b;

      uint64x2_t t4a = vextq_u64(row4b, row4a, 1);
      uint64x2_t t4b = vextq_u64(row4a, row4b, 1);
      row4a = t4a;
      row4b = t4b;
    }

    /* Diagonal step: G(4..7) */
    {
      uint64x2_t mx = vcombine_u64(vcreate_u64(m[s[8]]), vcreate_u64(m[s[10]]));
      uint64x2_t my = vcombine_u64(vcreate_u64(m[s[9]]), vcreate_u64(m[s[11]]));
      G_NEON(row1a, row2a, row3a, row4a, mx, my);
    }
    {
      uint64x2_t mx =
          vcombine_u64(vcreate_u64(m[s[12]]), vcreate_u64(m[s[14]]));
      uint64x2_t my =
          vcombine_u64(vcreate_u64(m[s[13]]), vcreate_u64(m[s[15]]));
      G_NEON(row1b, row2b, row3b, row4b, mx, my);
    }

    /* Undiagonalize */
    {
      uint64x2_t t2a = vextq_u64(row2b, row2a, 1);
      uint64x2_t t2b = vextq_u64(row2a, row2b, 1);
      row2a = t2a;
      row2b = t2b;

      uint64x2_t t3a = row3b;
      uint64x2_t t3b = row3a;
      row3a = t3a;
      row3b = t3b;

      uint64x2_t t4a = vextq_u64(row4a, row4b, 1);
      uint64x2_t t4b = vextq_u64(row4b, row4a, 1);
      row4a = t4a;
      row4b = t4b;
    }
  }

  /* Finalize: state[i] ^= v[i] ^ v[i+8] */
  row1a = veorq_u64(veorq_u64(row1a, row3a), orig1a);
  row1b = veorq_u64(veorq_u64(row1b, row3b), orig1b);
  row2a = veorq_u64(veorq_u64(row2a, row4a), orig2a);
  row2b = veorq_u64(veorq_u64(row2b, row4b), orig2b);

  vst1q_u64(state, row1a);
  vst1q_u64(state + 2, row1b);
  vst1q_u64(state + 4, row2a);
  vst1q_u64(state + 6, row2b);
}

} /* namespace tinyblake */

#else

#include "blake2b_compress.h"

namespace tinyblake {

void blake2b_compress_neon(uint64_t state[8], const uint8_t block[128],
                           uint64_t t0, uint64_t t1, bool last) {
  blake2b_compress_portable(state, block, t0, t1, last);
}

} /* namespace tinyblake */

#endif
