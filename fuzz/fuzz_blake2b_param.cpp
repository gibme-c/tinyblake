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

#include <tinyblake/blake2b.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

/*
 * Fuzz target: raw parameter block fuzzing.
 * Feeds attacker-controlled 64-byte parameter blocks into init_param.
 * Exercises the validation boundary that guards against over-reads.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 64)
    return 0;

  const uint8_t *param = data;
  const uint8_t *msg = data + 64;
  size_t msglen = size - 64;

  tinyblake_blake2b_state S;
  int rc = tinyblake_blake2b_init_param(&S, param);

  if (rc != 0) {
    /* Invalid param block — verify it rejected gracefully (no crash) */
    return 0;
  }

  /* Valid param block — exercise update + final */
  if (msglen > 0) {
    tinyblake_blake2b_update(&S, msg, msglen);
  }

  uint8_t out1[64];
  size_t outlen = param[0]; /* digest_length from the param block */
  int rc1 = tinyblake_blake2b_final(&S, out1, outlen);

  /* Replay with identical params to verify determinism */
  tinyblake_blake2b_state S2;
  int rc_init2 = tinyblake_blake2b_init_param(&S2, param);
  if (rc_init2 != 0)
    __builtin_trap(); /* same param must succeed again */

  if (msglen > 0) {
    tinyblake_blake2b_update(&S2, msg, msglen);
  }

  uint8_t out2[64];
  int rc2 = tinyblake_blake2b_final(&S2, out2, outlen);

  if (rc1 != rc2)
    __builtin_trap();
  if (rc1 == 0 && std::memcmp(out1, out2, outlen) != 0)
    __builtin_trap();

  return 0;
}
