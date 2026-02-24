// Copyright (c) 2025-2026, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list
//    of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be
//    used to endorse or promote products derived from this software without
//    specific prior written permission.
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

#include "../internal/endian.h"
#include "blake2b_compress.h"

#include <cstring>

namespace tinyblake {

/* BLAKE2b IV */
static const uint64_t IV[8] = {0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
                               0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
                               0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
                               0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL};

/* BLAKE2b sigma schedule */
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

static inline uint64_t rotr64(uint64_t x, int n) {
  return (x >> n) | (x << (64 - n));
}

#define G(r, i, a, b, c, d)                                                    \
  do {                                                                         \
    a = a + b + m[SIGMA[r][2 * i + 0]];                                        \
    d = rotr64(d ^ a, 32);                                                     \
    c = c + d;                                                                 \
    b = rotr64(b ^ c, 24);                                                     \
    a = a + b + m[SIGMA[r][2 * i + 1]];                                        \
    d = rotr64(d ^ a, 16);                                                     \
    c = c + d;                                                                 \
    b = rotr64(b ^ c, 63);                                                     \
  } while (0)

#define ROUND(r)                                                               \
  do {                                                                         \
    G(r, 0, v[0], v[4], v[8], v[12]);                                          \
    G(r, 1, v[1], v[5], v[9], v[13]);                                          \
    G(r, 2, v[2], v[6], v[10], v[14]);                                         \
    G(r, 3, v[3], v[7], v[11], v[15]);                                         \
    G(r, 4, v[0], v[5], v[10], v[15]);                                         \
    G(r, 5, v[1], v[6], v[11], v[12]);                                         \
    G(r, 6, v[2], v[7], v[8], v[13]);                                          \
    G(r, 7, v[3], v[4], v[9], v[14]);                                          \
  } while (0)

void blake2b_compress_portable(uint64_t state[8], const uint8_t block[128],
                               uint64_t t0, uint64_t t1, bool last) {
  uint64_t m[16];
  uint64_t v[16];

  for (int i = 0; i < 16; ++i) {
    m[i] = detail::load_le64(block + i * 8);
  }

  for (int i = 0; i < 8; ++i) {
    v[i] = state[i];
  }
  v[8] = IV[0];
  v[9] = IV[1];
  v[10] = IV[2];
  v[11] = IV[3];
  v[12] = IV[4] ^ t0;
  v[13] = IV[5] ^ t1;
  v[14] = last ? (IV[6] ^ 0xFFFFFFFFFFFFFFFFULL) : IV[6];
  v[15] = IV[7];

  ROUND(0);
  ROUND(1);
  ROUND(2);
  ROUND(3);
  ROUND(4);
  ROUND(5);
  ROUND(6);
  ROUND(7);
  ROUND(8);
  ROUND(9);
  ROUND(10);
  ROUND(11);

  for (int i = 0; i < 8; ++i) {
    state[i] ^= v[i] ^ v[i + 8];
  }
}

#undef G
#undef ROUND

} /* namespace tinyblake */