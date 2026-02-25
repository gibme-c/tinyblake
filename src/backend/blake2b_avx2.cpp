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
 * AVX2 vectorised BLAKE2b compression.
 *
 * Only compiled when targeting x86-64 and the compiler supports AVX2
 * intrinsics. The build system must pass -mavx2 (GCC/Clang) or /arch:AVX2
 * (MSVC).
 */

#if (defined(__x86_64__) || defined(_M_X64)) &&                                \
    (defined(__AVX2__) || defined(__GNUC__) || defined(_MSC_VER))

#include "../internal/endian.h"
#include <cstring>
#include <immintrin.h>

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

/*
 * AVX2 approach: operate on 4x uint64 lanes.
 * We pack the 16-word working vector into four __m256i registers:
 *   row1 = {v0, v1, v2, v3}
 *   row2 = {v4, v5, v6, v7}
 *   row3 = {v8, v9, v10, v11}
 *   row4 = {v12, v13, v14, v15}
 *
 * The diagonal step uses permute to rotate rows for mixing.
 */

static inline __m256i rotr64_32(__m256i x) {
  return _mm256_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1));
}

static inline __m256i rotr64_24(__m256i x) {
  return _mm256_or_si256(_mm256_srli_epi64(x, 24), _mm256_slli_epi64(x, 40));
}

alignas(32) static const uint8_t rotr16_mask[32] = {
    2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9,
    2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9};

static inline __m256i rotr64_16(__m256i x) {
  const __m256i mask =
      _mm256_load_si256(reinterpret_cast<const __m256i *>(rotr16_mask));
  return _mm256_shuffle_epi8(x, mask);
}

static inline __m256i rotr64_63(__m256i x) {
  return _mm256_or_si256(_mm256_srli_epi64(x, 63), _mm256_slli_epi64(x, 1));
}

/* Diagonalize: rotate rows for diagonal mixing step */
static inline void diag(__m256i &row2, __m256i &row3, __m256i &row4) {
  row2 = _mm256_permute4x64_epi64(row2, _MM_SHUFFLE(0, 3, 2, 1));
  row3 = _mm256_permute4x64_epi64(row3, _MM_SHUFFLE(1, 0, 3, 2));
  row4 = _mm256_permute4x64_epi64(row4, _MM_SHUFFLE(2, 1, 0, 3));
}

/* Undiagonalize: reverse the row rotation */
static inline void undiag(__m256i &row2, __m256i &row3, __m256i &row4) {
  row2 = _mm256_permute4x64_epi64(row2, _MM_SHUFFLE(2, 1, 0, 3));
  row3 = _mm256_permute4x64_epi64(row3, _MM_SHUFFLE(1, 0, 3, 2));
  row4 = _mm256_permute4x64_epi64(row4, _MM_SHUFFLE(0, 3, 2, 1));
}

static inline void g_column(__m256i &a, __m256i &b, __m256i &c, __m256i &d,
                            __m256i mx, __m256i my) {
  a = _mm256_add_epi64(_mm256_add_epi64(a, b), mx);
  d = rotr64_32(_mm256_xor_si256(d, a));
  c = _mm256_add_epi64(c, d);
  b = rotr64_24(_mm256_xor_si256(b, c));
  a = _mm256_add_epi64(_mm256_add_epi64(a, b), my);
  d = rotr64_16(_mm256_xor_si256(d, a));
  c = _mm256_add_epi64(c, d);
  b = rotr64_63(_mm256_xor_si256(b, c));
}

void blake2b_compress_avx2(uint64_t state[8], const uint8_t block[128],
                           uint64_t t0, uint64_t t1, bool last) {
  uint64_t m[16];
  for (int i = 0; i < 16; ++i) {
    m[i] = detail::load_le64(block + i * 8);
  }

  __m256i row1 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(state));
  __m256i row2 =
      _mm256_loadu_si256(reinterpret_cast<const __m256i *>(state + 4));
  __m256i row3 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(IV));
  __m256i row4 = _mm256_set_epi64x(
      static_cast<int64_t>(IV[7]),
      static_cast<int64_t>(last ? (IV[6] ^ 0xFFFFFFFFFFFFFFFFULL) : IV[6]),
      static_cast<int64_t>(IV[5] ^ t1), static_cast<int64_t>(IV[4] ^ t0));

  __m256i orig1 = row1;
  __m256i orig2 = row2;

  for (int r = 0; r < 12; ++r) {
    const uint8_t *s = SIGMA[r];

    /* Column step */
    __m256i mx = _mm256_set_epi64x(
        static_cast<int64_t>(m[s[6]]), static_cast<int64_t>(m[s[4]]),
        static_cast<int64_t>(m[s[2]]), static_cast<int64_t>(m[s[0]]));
    __m256i my = _mm256_set_epi64x(
        static_cast<int64_t>(m[s[7]]), static_cast<int64_t>(m[s[5]]),
        static_cast<int64_t>(m[s[3]]), static_cast<int64_t>(m[s[1]]));
    g_column(row1, row2, row3, row4, mx, my);

    /* Diagonal step */
    diag(row2, row3, row4);
    mx = _mm256_set_epi64x(
        static_cast<int64_t>(m[s[14]]), static_cast<int64_t>(m[s[12]]),
        static_cast<int64_t>(m[s[10]]), static_cast<int64_t>(m[s[8]]));
    my = _mm256_set_epi64x(
        static_cast<int64_t>(m[s[15]]), static_cast<int64_t>(m[s[13]]),
        static_cast<int64_t>(m[s[11]]), static_cast<int64_t>(m[s[9]]));
    g_column(row1, row2, row3, row4, mx, my);
    undiag(row2, row3, row4);
  }

  row1 = _mm256_xor_si256(_mm256_xor_si256(row1, row3), orig1);
  row2 = _mm256_xor_si256(_mm256_xor_si256(row2, row4), orig2);

  _mm256_storeu_si256(reinterpret_cast<__m256i *>(state), row1);
  _mm256_storeu_si256(reinterpret_cast<__m256i *>(state + 4), row2);
}

} /* namespace tinyblake */

#else /* No x86-64 support — provide a stub that forwards to portable */

#include "blake2b_compress.h"

namespace tinyblake {

void blake2b_compress_avx2(uint64_t state[8], const uint8_t block[128],
                           uint64_t t0, uint64_t t1, bool last) {
  blake2b_compress_portable(state, block, t0, t1, last);
}

} /* namespace tinyblake */

#endif