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

#include <tinyblake/pbkdf2.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

/*
 * Fuzz target: PBKDF2-HMAC-BLAKE2b-512.
 * Verifies determinism: same inputs always produce same output.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4)
    return 0;

  /* Parse inputs from fuzz data */
  uint8_t rounds_byte = data[0];
  uint8_t passlen_byte = data[1];
  uint8_t saltlen_byte = data[2];
  uint8_t outlen_byte = data[3];

  const uint8_t *rest = data + 4;
  size_t restlen = size - 4;

  /* Limit parameters to keep execution fast */
  uint32_t rounds = (rounds_byte % 3) + 1; /* 1..3 rounds */
  size_t outlen = (outlen_byte % 64) + 1;  /* 1..64 bytes */

  size_t passlen = passlen_byte;
  if (passlen > restlen)
    passlen = restlen;
  if (passlen == 0)
    passlen = 1; /* HMAC rejects zero-length keys; skip to interesting paths */
  if (passlen > restlen)
    return 0;

  const uint8_t *password = rest;
  rest += passlen;
  restlen -= passlen;

  size_t saltlen = saltlen_byte;
  if (saltlen > restlen)
    saltlen = restlen;

  const uint8_t *salt = rest;

  /* Run twice and verify identical results */
  uint8_t out1[64], out2[64];
  int rc1 =
      tinyblake_pbkdf2(out1, outlen, password, passlen, salt, saltlen, rounds);
  int rc2 =
      tinyblake_pbkdf2(out2, outlen, password, passlen, salt, saltlen, rounds);

  if (rc1 != rc2)
    __builtin_trap();
  if (rc1 == 0 && std::memcmp(out1, out2, outlen) != 0)
    __builtin_trap();

  return 0;
}