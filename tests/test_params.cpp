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

#include "test_harness.h"
#include <tinyblake/blake2b.h>

#include <cstring>

TEST(params_salt) {
  /* Two hashes with different salts should differ */
  uint8_t param1[64] = {};
  param1[0] = 64; /* digest_length */
  param1[2] = 1;  /* fanout */
  param1[3] = 1;  /* depth */
  /* salt at bytes 32..47 */
  param1[32] = 0x01;

  uint8_t param2[64] = {};
  param2[0] = 64;
  param2[2] = 1;
  param2[3] = 1;
  param2[32] = 0x02;

  tinyblake_blake2b_state S1, S2;
  tinyblake_blake2b_init_param(&S1, param1);
  tinyblake_blake2b_init_param(&S2, param2);

  tinyblake_blake2b_update(&S1, "abc", 3);
  tinyblake_blake2b_update(&S2, "abc", 3);

  uint8_t out1[64], out2[64];
  tinyblake_blake2b_final(&S1, out1, 64);
  tinyblake_blake2b_final(&S2, out2, 64);

  ASSERT_TRUE(std::memcmp(out1, out2, 64) != 0);
}

TEST(params_personal) {
  /* Two hashes with different personalization should differ */
  uint8_t param1[64] = {};
  param1[0] = 64;
  param1[2] = 1;
  param1[3] = 1;
  /* personal at bytes 48..63 */
  param1[48] = 'A';

  uint8_t param2[64] = {};
  param2[0] = 64;
  param2[2] = 1;
  param2[3] = 1;
  param2[48] = 'B';

  tinyblake_blake2b_state S1, S2;
  tinyblake_blake2b_init_param(&S1, param1);
  tinyblake_blake2b_init_param(&S2, param2);

  tinyblake_blake2b_update(&S1, "test", 4);
  tinyblake_blake2b_update(&S2, "test", 4);

  uint8_t out1[64], out2[64];
  tinyblake_blake2b_final(&S1, out1, 64);
  tinyblake_blake2b_final(&S2, out2, 64);

  ASSERT_TRUE(std::memcmp(out1, out2, 64) != 0);
}

TEST(params_cpp_custom_param_block) {
  /* Use C++ API with custom parameter block */
  uint8_t param[64] = {};
  param[0] = 32;   /* digest_length */
  param[2] = 1;    /* fanout */
  param[3] = 1;    /* depth */
  param[48] = 'T'; /* personalization */
  param[49] = 'B';

  tinyblake::blake2b::hasher h(param);
  h.update("hello", 5);
  auto digest = h.final_();

  ASSERT_EQ(digest.size(), 32u);

  /* Different personalization = different hash */
  param[48] = 'X';
  tinyblake::blake2b::hasher h2(param);
  h2.update("hello", 5);
  auto digest2 = h2.final_();

  ASSERT_TRUE(std::memcmp(digest.data(), digest2.data(), 32) != 0);
}

TEST(params_default_matches_spec) {
  /* Default param: digest_length=64, key_length=0, fanout=1, depth=1, rest=0 */
  uint8_t param[64] = {};
  param[0] = 64;
  param[2] = 1;
  param[3] = 1;

  tinyblake_blake2b_state S1;
  tinyblake_blake2b_init_param(&S1, param);
  tinyblake_blake2b_update(&S1, "abc", 3);
  uint8_t out1[64];
  tinyblake_blake2b_final(&S1, out1, 64);

  /* Should match the standard init */
  tinyblake_blake2b_state S2;
  tinyblake_blake2b_init(&S2, 64);
  tinyblake_blake2b_update(&S2, "abc", 3);
  uint8_t out2[64];
  tinyblake_blake2b_final(&S2, out2, 64);

  ASSERT_BYTES_EQ(out1, out2, 64);
}

TEST(params_reset_cpp) {
  /* Reset should produce the same result as a fresh instance */
  tinyblake::blake2b::hasher h(64);
  h.update("first message", 13);
  h.final_(); /* consumes state */

  h.reset();
  h.update("second message", 14);
  auto d1 = h.final_();

  auto d2 = tinyblake::blake2b::hash("second message", 14, 64);
  ASSERT_BYTES_EQ(d1.data(), d2.data(), 64);
}

TEST(params_keyed_reset) {
  uint8_t key[4] = {0xDE, 0xAD, 0xBE, 0xEF};

  tinyblake::blake2b::hasher h(key, 4, 64);
  h.update("msg1", 4);
  h.final_();

  h.reset();
  h.update("msg2", 4);
  auto d1 = h.final_();

  /* Fresh keyed hash of msg2 */
  auto d2 = tinyblake::blake2b::keyed_hash(key, 4, "msg2", 4, 64);
  ASSERT_BYTES_EQ(d1.data(), d2.data(), 64);
}