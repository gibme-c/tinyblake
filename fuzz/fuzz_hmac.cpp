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

#include <tinyblake/hmac.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

/*
 * Fuzz target: HMAC-BLAKE2b-512.
 * Differential test: one-shot vs incremental HMAC.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return 0;

  /* Byte 0: key length hint */
  size_t keylen = (data[0] % 128) + 1;
  const uint8_t *rest = data + 1;
  size_t restlen = size - 1;

  if (restlen < keylen) {
    keylen = restlen;
  }
  if (keylen == 0)
    return 0;

  const uint8_t *key = rest;
  const uint8_t *msg = rest + keylen;
  size_t msglen = restlen - keylen;

  /* One-shot */
  uint8_t out1[64];
  int rc1 = tinyblake_hmac(out1, 64, key, keylen, msg, msglen);

  /* Incremental */
  tinyblake_hmac_state state;
  tinyblake_hmac_init(&state, key, keylen);

  size_t off = 0;
  while (off < msglen) {
    size_t n = 1;
    if (off + n > msglen)
      n = msglen - off;
    tinyblake_hmac_update(&state, msg + off, n);
    off += n;
  }

  uint8_t out2[64];
  int rc2 = tinyblake_hmac_final(&state, out2, 64);

  if (rc1 != 0 || rc2 != 0)
    __builtin_trap();
  if (std::memcmp(out1, out2, 64) != 0)
    __builtin_trap();

  return 0;
}