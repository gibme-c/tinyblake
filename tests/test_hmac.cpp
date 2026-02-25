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
#include <stdexcept>
#include <tinyblake/common.h>
#include <tinyblake/hmac.h>
#include <tinyblake/pbkdf2.h>

#include "vectors_hmac.inl"

TEST(hmac_blake2b_basic) {
  auto key = test::hex_to_bytes(hmac_vectors[0].key_hex);
  auto data = test::hex_to_bytes(hmac_vectors[0].data_hex);
  auto expected = test::hex_to_bytes(hmac_vectors[0].expected_hex);

  uint8_t out[64];
  int rc =
      tinyblake_hmac(out, 64, key.data(), key.size(), data.data(), data.size());
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(hmac_blake2b_empty_data) {
  auto key = test::hex_to_bytes(hmac_vectors[1].key_hex);
  auto expected = test::hex_to_bytes(hmac_vectors[1].expected_hex);

  uint8_t out[64];
  int rc = tinyblake_hmac(out, 64, key.data(), key.size(), nullptr, 0);
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(hmac_incremental_matches_oneshot) {
  const char *key_str = "test-key";
  const char *msg = "Hello, World! This is a test message for HMAC.";

  /* One-shot */
  uint8_t out1[64];
  tinyblake_hmac(out1, 64, key_str, std::strlen(key_str), msg,
                 std::strlen(msg));

  /* Incremental */
  tinyblake_hmac_state state;
  tinyblake_hmac_init(&state, key_str, std::strlen(key_str));
  tinyblake_hmac_update(&state, msg, 10);
  tinyblake_hmac_update(&state, msg + 10, std::strlen(msg) - 10);
  uint8_t out2[64];
  tinyblake_hmac_final(&state, out2, 64);

  ASSERT_BYTES_EQ(out1, out2, 64);
}

TEST(hmac_cpp_api) {
  std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04};
  std::string data = "test data";

  auto result1 =
      tinyblake::hmac::mac(key.data(), key.size(), data.data(), data.size());

  tinyblake::hmac::hasher h(key);
  h.update(data);
  auto result2 = h.final_();

  ASSERT_EQ(result1.size(), 64u);
  ASSERT_BYTES_EQ(result1.data(), result2.data(), 64);
}

TEST(hmac_long_key) {
  /* Key longer than 128 bytes should be hashed first */
  std::vector<uint8_t> long_key(200);
  for (size_t i = 0; i < long_key.size(); ++i)
    long_key[i] = static_cast<uint8_t>(i);

  const char *msg = "data";

  uint8_t out[64];
  int rc = tinyblake_hmac(out, 64, long_key.data(), long_key.size(), msg,
                          std::strlen(msg));
  ASSERT_EQ(rc, 0);

  /* Verify it's deterministic */
  uint8_t out2[64];
  tinyblake_hmac(out2, 64, long_key.data(), long_key.size(), msg,
                 std::strlen(msg));
  ASSERT_BYTES_EQ(out, out2, 64);
}

TEST(hmac_long_key_vector) {
  /* Verify against known-good vector for 200-byte key */
  auto key = test::hex_to_bytes(hmac_vectors[2].key_hex);
  auto data = test::hex_to_bytes(hmac_vectors[2].data_hex);
  auto expected = test::hex_to_bytes(hmac_vectors[2].expected_hex);

  uint8_t out[64];
  int rc =
      tinyblake_hmac(out, 64, key.data(), key.size(), data.data(), data.size());
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(hmac_null_key_rejected) {
  tinyblake_hmac_state state;
  ASSERT_EQ(tinyblake_hmac_init(&state, nullptr, 0), -1);
  ASSERT_EQ(tinyblake_hmac_init(&state, nullptr, 4), -1);

  uint8_t key[4] = {1, 2, 3, 4};
  ASSERT_EQ(tinyblake_hmac_init(&state, key, 0), -1);
}

TEST(hmac_cpp_null_key_throws) {
  bool caught = false;
  try {
    tinyblake::hmac::hasher h(nullptr, 0);
    (void)h;
  } catch (const std::invalid_argument &) {
    caught = true;
  }
  ASSERT_TRUE(caught);

  caught = false;
  uint8_t key[4] = {1, 2, 3, 4};
  try {
    tinyblake::hmac::hasher h(key, 0);
    (void)h;
  } catch (const std::invalid_argument &) {
    caught = true;
  }
  ASSERT_TRUE(caught);
}

TEST(hmac_constant_time_eq) {
  uint8_t a[64] = {};
  uint8_t b[64] = {};

  /* Equal buffers */
  for (size_t i = 0; i < 64; ++i) {
    a[i] = static_cast<uint8_t>(i);
    b[i] = static_cast<uint8_t>(i);
  }
  ASSERT_EQ(tinyblake_constant_time_eq(a, b, 64), 1);
  ASSERT_TRUE(tinyblake::constant_time_eq(a, b, 64));

  /* Differ in last byte */
  b[63] ^= 0x01;
  ASSERT_EQ(tinyblake_constant_time_eq(a, b, 64), 0);
  ASSERT_TRUE(!tinyblake::constant_time_eq(a, b, 64));

  /* Differ in first byte */
  b[63] = a[63];
  b[0] ^= 0x80;
  ASSERT_EQ(tinyblake_constant_time_eq(a, b, 64), 0);

  /* Zero-length compare is always equal */
  ASSERT_EQ(tinyblake_constant_time_eq(a, b, 0), 1);
}

TEST(hmac_update_error_paths) {
  /* null state */
  ASSERT_EQ(tinyblake_hmac_update(nullptr, "abc", 3), -1);
}

TEST(hmac_final_error_paths) {
  uint8_t out[64];

  /* null state */
  ASSERT_EQ(tinyblake_hmac_final(nullptr, out, 64), -1);

  /* null output */
  tinyblake_hmac_state S;
  uint8_t key[4] = {1, 2, 3, 4};
  tinyblake_hmac_init(&S, key, 4);
  ASSERT_EQ(tinyblake_hmac_final(&S, nullptr, 64), -1);

  /* outlen too small */
  tinyblake_hmac_init(&S, key, 4);
  ASSERT_EQ(tinyblake_hmac_final(&S, out, 63), -1);
}

TEST(hmac_consistency_across_chunk_sizes) {
  /* HMAC with different update chunk sizes should yield same result */
  const char *key = "hmac-key";
  std::vector<uint8_t> data(500);
  for (size_t i = 0; i < data.size(); ++i)
    data[i] = static_cast<uint8_t>(i % 256);

  uint8_t ref[64];
  tinyblake_hmac(ref, 64, key, std::strlen(key), data.data(), data.size());

  /* Feed 1 byte at a time */
  tinyblake_hmac_state S;
  tinyblake_hmac_init(&S, key, std::strlen(key));
  for (size_t i = 0; i < data.size(); ++i) {
    tinyblake_hmac_update(&S, &data[i], 1);
  }
  uint8_t out[64];
  tinyblake_hmac_final(&S, out, 64);

  ASSERT_BYTES_EQ(out, ref, 64);
}

TEST(hmac_null_state_init) {
  ASSERT_EQ(tinyblake_hmac_init(nullptr, "key", 3), -1);
}

TEST(hmac_move_construct) {
  std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04};
  std::string data = "move test data";

  auto expected =
      tinyblake::hmac::mac(key.data(), key.size(), data.data(), data.size());

  tinyblake::hmac::hasher h1(key);
  h1.update(data);
  tinyblake::hmac::hasher h2(std::move(h1));
  auto digest = h2.final_();

  ASSERT_BYTES_EQ(digest.data(), expected.data(), 64);
}

TEST(hmac_move_assign) {
  std::vector<uint8_t> key = {0x05, 0x06, 0x07, 0x08};
  std::string data = "move assign test";

  auto expected =
      tinyblake::hmac::mac(key.data(), key.size(), data.data(), data.size());

  tinyblake::hmac::hasher h1(key);
  h1.update(data);
  tinyblake::hmac::hasher h2(key);
  h2 = std::move(h1);
  auto digest = h2.final_();

  ASSERT_BYTES_EQ(digest.data(), expected.data(), 64);
}

TEST(pbkdf2_null_password_rejected) {
  uint8_t out[64];
  uint8_t salt[4] = {0x01, 0x02, 0x03, 0x04};
  /* null password fails in HMAC layer */
  ASSERT_EQ(tinyblake_pbkdf2(out, 64, nullptr, 0, salt, 4, 1), -1);
}

TEST(pbkdf2_empty_password_rejected) {
  uint8_t out[64];
  uint8_t salt[4] = {0x01, 0x02, 0x03, 0x04};
  /* empty (zero-length) password fails in HMAC layer (keylen == 0) */
  uint8_t pw = 0;
  ASSERT_EQ(tinyblake_pbkdf2(out, 64, &pw, 0, salt, 4, 1), -1);
}