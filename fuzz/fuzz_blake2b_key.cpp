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
 * Fuzz target: keyed BLAKE2b.
 * Differential test: one-shot vs incremental keyed hashing.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return 0;

  /* Byte 0: output length (1..64), Byte 1: key length (1..64) */
  size_t outlen = (data[0] % 64) + 1;
  size_t keylen = (data[1] % 64) + 1;

  const uint8_t *rest = data + 2;
  size_t restlen = size - 2;

  if (restlen < keylen)
    return 0;

  const uint8_t *key = rest;
  const uint8_t *msg = rest + keylen;
  size_t msglen = restlen - keylen;

  /* One-shot */
  uint8_t out1[64];
  int rc1 = tinyblake_blake2b(out1, outlen, msg, msglen, key, keylen);

  /* Incremental */
  tinyblake_blake2b_state S;
  int rc_init = tinyblake_blake2b_init_key(&S, outlen, key, keylen);
  if (rc_init != 0)
    return 0;

  /* Feed in varying chunks */
  size_t off = 0;
  size_t chunk = 1;
  while (off < msglen) {
    size_t n = (off + chunk > msglen) ? (msglen - off) : chunk;
    tinyblake_blake2b_update(&S, msg + off, n);
    off += n;
    chunk = chunk * 2 + 1; /* varying chunk sizes */
  }

  uint8_t out2[64];
  int rc2 = tinyblake_blake2b_final(&S, out2, outlen);

  if (rc1 != 0 || rc2 != 0)
    __builtin_trap();
  if (std::memcmp(out1, out2, outlen) != 0)
    __builtin_trap();

  return 0;
}