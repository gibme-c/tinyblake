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

#include <cstddef>
#include <cstdint>
#include <cstring>

/*
 * Fuzz target: unkeyed BLAKE2b.
 * Differential test: one-shot vs incremental with random split point.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1)
    return 0;

  /* Use first byte to determine output length (1..64) */
  size_t outlen = (data[0] % 64) + 1;
  const uint8_t *msg = data + 1;
  size_t msglen = size - 1;

  /* One-shot */
  uint8_t out1[64];
  int rc1 = tinyblake_blake2b(out1, outlen, msg, msglen, nullptr, 0);

  /* Incremental */
  tinyblake_blake2b_state S;
  tinyblake_blake2b_init(&S, outlen);

  if (msglen > 0) {
    size_t split = (data[0] % msglen) + 1;
    if (split > msglen)
      split = msglen;
    tinyblake_blake2b_update(&S, msg, split);
    tinyblake_blake2b_update(&S, msg + split, msglen - split);
  }

  uint8_t out2[64];
  int rc2 = tinyblake_blake2b_final(&S, out2, outlen);

  /* Both must succeed and produce identical output */
  if (rc1 != 0 || rc2 != 0)
    __builtin_trap();
  if (std::memcmp(out1, out2, outlen) != 0)
    __builtin_trap();

  return 0;
}