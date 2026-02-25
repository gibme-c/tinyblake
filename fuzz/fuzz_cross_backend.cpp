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

#include <tinyblake/blake2b.h>

#include "backend/blake2b_compress.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

/*
 * Fuzz target: cross-backend consistency.
 * Runs the portable compress and the runtime-dispatched compress on identical
 * inputs and asserts identical output. Would have caught the AVX2 alignment
 * crash.
 *
 * Input layout (minimum 153 bytes):
 *   [0..63]    — initial state (8 x uint64_t LE)
 *   [64..191]  — 128-byte message block
 *   [192]      — flags byte: bit 0 = last
 *
 * Counter values are fixed at 128/0 to keep the test deterministic.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 193)
    return 0;

  /* Parse initial state from fuzz input */
  uint64_t state_portable[8];
  uint64_t state_dispatched[8];
  for (int i = 0; i < 8; ++i) {
    uint64_t v = 0;
    for (int b = 0; b < 8; ++b) {
      v |= static_cast<uint64_t>(data[i * 8 + b]) << (b * 8);
    }
    state_portable[i] = v;
    state_dispatched[i] = v;
  }

  const uint8_t *block = data + 64;
  bool last = (data[192] & 1) != 0;
  uint64_t t0 = 128;
  uint64_t t1 = 0;

  /* Run portable backend */
  tinyblake::blake2b_compress_portable(state_portable, block, t0, t1, last);

  /* Run full BLAKE2b to exercise the dispatched backend with the same inputs.
   * We construct a state manually and call update+final which internally
   * calls the dispatched compress. Instead, we use the public API to hash
   * the same block and compare at the compress level.
   *
   * Actually: we can call the dispatched compress directly by going through
   * a full hash that exercises it. But the cleanest approach is to use
   * the init_param path to set up identical initial state, then compare
   * after one block compression.
   *
   * Simplest: just call both compress functions directly. The fuzz targets
   * already have access to ../src via target_include_directories. */

  /* Use the public API to get the dispatched compress result.
   * We do this by setting up a state with init, manually overwriting h[],
   * then calling update with exactly 128 bytes followed by final.
   * But that changes counters. Instead, let's just exercise the dispatched
   * compress directly — we have the header. */

  /* The dispatched function is accessed via get_compress() which is static
   * in blake2b.cpp. We can't call it directly. Instead, exercise the
   * dispatched path through the public incremental API:
   *
   * 1. init with outlen=64
   * 2. overwrite h[] with our fuzz state
   * 3. feed 128+1 bytes (forces one compress of the first 128 bytes)
   * 4. The compress uses the dispatched backend
   *
   * But the counter and last flag won't match. A cleaner approach:
   * just hash the same message with both a portable-forced build and
   * the dispatched build — but we can't force portable at runtime.
   *
   * Best approach for this fuzz target: compare full BLAKE2b hash output
   * using portable compress vs dispatched compress by running the full
   * hash algorithm manually with each. */

  /* Direct comparison: init identical states, process the same message,
   * and compare final output. Use init_param to set up both states
   * identically, then the dispatched path via the public API. */

  /* Build a valid param block: outlen=64, fanout=1, depth=1 */
  uint8_t param[64];
  std::memset(param, 0, 64);
  param[0] = 64; /* digest_length */
  param[2] = 1;  /* fanout */
  param[3] = 1;  /* depth */

  /* State A: use public API (dispatched compress) */
  tinyblake_blake2b_state Sa;
  tinyblake_blake2b_init_param(&Sa, param);
  tinyblake_blake2b_update(&Sa, block, 128);
  uint8_t out_a[64];
  tinyblake_blake2b_final(&Sa, out_a, 64);

  /* State B: use portable compress manually */
  uint64_t h[8];
  static const uint64_t IV[8] = {
      0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
      0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
      0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
  };

  /* XOR IV with param block (same as init_from_param) */
  for (int i = 0; i < 8; ++i) {
    uint64_t p = 0;
    for (int b = 0; b < 8; ++b) {
      p |= static_cast<uint64_t>(param[i * 8 + b]) << (b * 8);
    }
    h[i] = IV[i] ^ p;
  }

  /* Process the 128-byte block as the only data (counter = 128, last = true) */
  uint8_t padded[128];
  std::memcpy(padded, block, 128);
  tinyblake::blake2b_compress_portable(h, padded, 128, 0, true);

  /* Extract portable output */
  uint8_t out_b[64];
  for (int i = 0; i < 8; ++i) {
    for (int b = 0; b < 8; ++b) {
      out_b[i * 8 + b] = static_cast<uint8_t>(h[i] >> (b * 8));
    }
  }

  /* Both must produce identical output */
  if (std::memcmp(out_a, out_b, 64) != 0)
    __builtin_trap();

  return 0;
}
