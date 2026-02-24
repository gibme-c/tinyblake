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

#include "test_harness.h"
#include <stdexcept>
#include <tinyblake/blake2b.h>

#include "vectors_rfc7693.inl"

TEST_MAIN()

TEST(blake2b_rfc7693_abc) {
  auto input = test::hex_to_bytes(rfc7693_vectors[0].input_hex);
  auto expected = test::hex_to_bytes(rfc7693_vectors[0].expected_hex);

  uint8_t out[64];
  int rc = tinyblake_blake2b(out, 64, input.data(), input.size(), nullptr, 0);
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(blake2b_rfc7693_empty) {
  auto expected = test::hex_to_bytes(rfc7693_vectors[1].expected_hex);

  uint8_t out[64];
  int rc = tinyblake_blake2b(out, 64, nullptr, 0, nullptr, 0);
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(blake2b_cpp_api_abc) {
  auto expected = test::hex_to_bytes(rfc7693_vectors[0].input_hex);

  tinyblake::blake2b::hasher h(64);
  h.update(expected.data(), expected.size());
  auto digest = h.final_();

  auto exp = test::hex_to_bytes(rfc7693_vectors[0].expected_hex);
  ASSERT_EQ(digest.size(), 64u);
  ASSERT_BYTES_EQ(digest.data(), exp.data(), 64);
}

TEST(blake2b_cpp_oneshot) {
  auto expected = test::hex_to_bytes(rfc7693_vectors[0].expected_hex);

  auto digest = tinyblake::blake2b::hash("abc", 3, 64);
  ASSERT_EQ(digest.size(), 64u);
  ASSERT_BYTES_EQ(digest.data(), expected.data(), 64);
}

TEST(blake2b_incremental_matches_oneshot) {
  /* Hash a longer message incrementally vs one-shot */
  std::vector<uint8_t> data(1000);
  for (size_t i = 0; i < data.size(); ++i)
    data[i] = static_cast<uint8_t>(i & 0xFF);

  auto oneshot = tinyblake::blake2b::hash(data.data(), data.size(), 64);

  tinyblake::blake2b::hasher h(64);
  /* Feed in various chunk sizes */
  size_t off = 0;
  size_t chunks[] = {1, 7, 63, 64, 65, 127, 128, 129, 200};
  for (size_t cs : chunks) {
    size_t n = (off + cs > data.size()) ? (data.size() - off) : cs;
    if (n == 0)
      break;
    h.update(data.data() + off, n);
    off += n;
  }
  if (off < data.size()) {
    h.update(data.data() + off, data.size() - off);
  }
  auto incremental = h.final_();

  ASSERT_BYTES_EQ(incremental.data(), oneshot.data(), 64);
}

TEST(blake2b_init_param_block) {
  /* Build parameter block manually: unkeyed, 32-byte output */
  uint8_t param[64] = {};
  param[0] = 32; /* digest_length */
  param[1] = 0;  /* key_length */
  param[2] = 1;  /* fanout */
  param[3] = 1;  /* depth */

  tinyblake_blake2b_state S;
  int rc = tinyblake_blake2b_init_param(&S, param);
  ASSERT_EQ(rc, 0);
  rc = tinyblake_blake2b_update(&S, "abc", 3);
  ASSERT_EQ(rc, 0);

  uint8_t out[32];
  rc = tinyblake_blake2b_final(&S, out, 32);
  ASSERT_EQ(rc, 0);

  /* Verify against C++ API with same output length */
  auto cpp_digest = tinyblake::blake2b::hash("abc", 3, 32);
  ASSERT_BYTES_EQ(out, cpp_digest.data(), 32);
}

TEST(blake2b_error_cases) {
  tinyblake_blake2b_state S;

  /* outlen = 0 should fail */
  ASSERT_EQ(tinyblake_blake2b_init(&S, 0), -1);

  /* outlen > 64 should fail */
  ASSERT_EQ(tinyblake_blake2b_init(&S, 65), -1);

  /* null state should fail */
  ASSERT_EQ(tinyblake_blake2b_init(nullptr, 32), -1);

  /* key init: keylen = 0 should fail */
  uint8_t key[4] = {1, 2, 3, 4};
  ASSERT_EQ(tinyblake_blake2b_init_key(&S, 32, key, 0), -1);

  /* key init: keylen > 64 should fail */
  uint8_t bigkey[65] = {};
  ASSERT_EQ(tinyblake_blake2b_init_key(&S, 32, bigkey, 65), -1);
}

TEST(blake2b_init_param_invalid_outlen) {
  tinyblake_blake2b_state S;

  /* outlen = 0 in param block */
  uint8_t param0[64] = {};
  param0[0] = 0;
  param0[2] = 1;
  param0[3] = 1;
  ASSERT_EQ(tinyblake_blake2b_init_param(&S, param0), -1);

  /* outlen = 65 in param block */
  uint8_t param65[64] = {};
  param65[0] = 65;
  param65[2] = 1;
  param65[3] = 1;
  ASSERT_EQ(tinyblake_blake2b_init_param(&S, param65), -1);

  /* outlen = 255 in param block */
  uint8_t param255[64] = {};
  param255[0] = 255;
  param255[2] = 1;
  param255[3] = 1;
  ASSERT_EQ(tinyblake_blake2b_init_param(&S, param255), -1);
}

TEST(blake2b_cpp_constructor_invalid_outlen) {
  bool caught = false;
  try {
    tinyblake::blake2b::hasher h(size_t{0});
    (void)h;
  } catch (const std::invalid_argument &) {
    caught = true;
  }
  ASSERT_TRUE(caught);

  caught = false;
  try {
    tinyblake::blake2b::hasher h(size_t{65});
    (void)h;
  } catch (const std::invalid_argument &) {
    caught = true;
  }
  ASSERT_TRUE(caught);

  /* 256 silently truncates to 0 without validation */
  caught = false;
  try {
    tinyblake::blake2b::hasher h(size_t{256});
    (void)h;
  } catch (const std::invalid_argument &) {
    caught = true;
  }
  ASSERT_TRUE(caught);
}

TEST(blake2b_cpp_keyed_constructor_invalid) {
  uint8_t key[4] = {1, 2, 3, 4};

  /* null key */
  bool caught = false;
  try {
    tinyblake::blake2b::hasher h(nullptr, 4, 64);
    (void)h;
  } catch (const std::invalid_argument &) {
    caught = true;
  }
  ASSERT_TRUE(caught);

  /* keylen = 0 */
  caught = false;
  try {
    tinyblake::blake2b::hasher h(key, 0, 64);
    (void)h;
  } catch (const std::invalid_argument &) {
    caught = true;
  }
  ASSERT_TRUE(caught);

  /* keylen > 64 */
  caught = false;
  uint8_t bigkey[65] = {};
  try {
    tinyblake::blake2b::hasher h(bigkey, 65, 64);
    (void)h;
  } catch (const std::invalid_argument &) {
    caught = true;
  }
  ASSERT_TRUE(caught);
}

TEST(blake2b_cpp_param_constructor_invalid) {
  /* outlen=0 in param block should throw */
  uint8_t param[64] = {};
  param[0] = 0;
  param[2] = 1;
  param[3] = 1;

  bool caught = false;
  try {
    tinyblake::blake2b::hasher h(param);
    (void)h;
  } catch (const std::invalid_argument &) {
    caught = true;
  }
  ASSERT_TRUE(caught);
}

TEST(blake2b_update_error_paths) {
  /* null state */
  ASSERT_EQ(tinyblake_blake2b_update(nullptr, "abc", 3), -1);

  /* null data with nonzero length */
  tinyblake_blake2b_state S;
  tinyblake_blake2b_init(&S, 64);
  ASSERT_EQ(tinyblake_blake2b_update(&S, nullptr, 5), -1);

  /* null data with zero length is OK */
  ASSERT_EQ(tinyblake_blake2b_update(&S, nullptr, 0), 0);
}

TEST(blake2b_final_error_paths) {
  /* null state */
  uint8_t out[64];
  ASSERT_EQ(tinyblake_blake2b_final(nullptr, out, 64), -1);

  /* null output */
  tinyblake_blake2b_state S;
  tinyblake_blake2b_init(&S, 64);
  ASSERT_EQ(tinyblake_blake2b_final(&S, nullptr, 64), -1);

  /* outlen too small */
  tinyblake_blake2b_init(&S, 64);
  ASSERT_EQ(tinyblake_blake2b_final(&S, out, 32), -1);
}

TEST(blake2b_cpp_final_on_finalized_throws) {
  tinyblake::blake2b::hasher h(64);
  h.update("abc", 3);
  auto digest = h.final_();
  (void)digest;

  /* State is zeroed after final_, second call should throw */
  bool caught = false;
  try {
    h.final_();
  } catch (const std::runtime_error &) {
    caught = true;
  }
  ASSERT_TRUE(caught);
}

TEST(blake2b_empty_updates) {
  /* Zero-byte updates between real data should not affect the hash */
  auto ref = tinyblake::blake2b::hash("abc", 3, 64);

  tinyblake::blake2b::hasher h(64);
  h.update("", 0);
  h.update("a", 1);
  h.update("", 0);
  h.update("bc", 2);
  h.update("", 0);
  auto result = h.final_();

  ASSERT_BYTES_EQ(result.data(), ref.data(), 64);
}

TEST(blake2b_move_construct) {
  auto expected = tinyblake::blake2b::hash("abc", 3, 64);

  tinyblake::blake2b::hasher h1(64);
  h1.update("abc", 3);
  tinyblake::blake2b::hasher h2(std::move(h1));
  auto digest = h2.final_();

  ASSERT_BYTES_EQ(digest.data(), expected.data(), 64);

  /* Moved-from hasher should throw on final_ (state zeroed) */
  bool caught = false;
  try {
    h1.final_();
  } catch (const std::runtime_error &) {
    caught = true;
  }
  ASSERT_TRUE(caught);
}

TEST(blake2b_move_assign) {
  auto expected = tinyblake::blake2b::hash("hello", 5, 64);

  tinyblake::blake2b::hasher h1(64);
  h1.update("hello", 5);
  tinyblake::blake2b::hasher h2(64);
  h2 = std::move(h1);
  auto digest = h2.final_();

  ASSERT_BYTES_EQ(digest.data(), expected.data(), 64);

  /* Moved-from hasher should throw on final_ (state zeroed) */
  bool caught = false;
  try {
    h1.final_();
  } catch (const std::runtime_error &) {
    caught = true;
  }
  ASSERT_TRUE(caught);
}