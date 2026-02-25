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

#include "vectors_blake2b_keyed.inl"

/* Build input for keyed KAT: input(i) = 00 01 02 ... (i-1) */
static std::vector<uint8_t> make_input(size_t len) {
  std::vector<uint8_t> v(len);
  for (size_t i = 0; i < len; ++i) {
    v[i] = static_cast<uint8_t>(i & 0xFF);
  }
  return v;
}

TEST(blake2b_keyed_kat_0) {
  auto key = test::hex_to_bytes(keyed_kat_key_hex);
  auto expected = test::hex_to_bytes(keyed_kat_vectors[0].expected_hex);
  auto input = make_input(keyed_kat_vectors[0].input_len);

  uint8_t out[64];
  int rc = tinyblake_blake2b(out, 64, input.data(), input.size(), key.data(),
                             key.size());
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(blake2b_keyed_kat_1) {
  auto key = test::hex_to_bytes(keyed_kat_key_hex);
  auto expected = test::hex_to_bytes(keyed_kat_vectors[1].expected_hex);
  auto input = make_input(keyed_kat_vectors[1].input_len);

  uint8_t out[64];
  int rc = tinyblake_blake2b(out, 64, input.data(), input.size(), key.data(),
                             key.size());
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(blake2b_keyed_kat_2) {
  auto key = test::hex_to_bytes(keyed_kat_key_hex);
  auto expected = test::hex_to_bytes(keyed_kat_vectors[2].expected_hex);
  auto input = make_input(keyed_kat_vectors[2].input_len);

  uint8_t out[64];
  int rc = tinyblake_blake2b(out, 64, input.data(), input.size(), key.data(),
                             key.size());
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(blake2b_keyed_kat_3) {
  auto key = test::hex_to_bytes(keyed_kat_key_hex);
  auto expected = test::hex_to_bytes(keyed_kat_vectors[3].expected_hex);
  auto input = make_input(keyed_kat_vectors[3].input_len);

  uint8_t out[64];
  int rc = tinyblake_blake2b(out, 64, input.data(), input.size(), key.data(),
                             key.size());
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(blake2b_keyed_kat_63) {
  auto key = test::hex_to_bytes(keyed_kat_key_hex);
  auto expected = test::hex_to_bytes(keyed_kat_vectors[4].expected_hex);
  auto input = make_input(keyed_kat_vectors[4].input_len);

  uint8_t out[64];
  int rc = tinyblake_blake2b(out, 64, input.data(), input.size(), key.data(),
                             key.size());
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(blake2b_keyed_kat_64) {
  auto key = test::hex_to_bytes(keyed_kat_key_hex);
  auto expected = test::hex_to_bytes(keyed_kat_vectors[5].expected_hex);
  auto input = make_input(keyed_kat_vectors[5].input_len);

  uint8_t out[64];
  int rc = tinyblake_blake2b(out, 64, input.data(), input.size(), key.data(),
                             key.size());
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(blake2b_keyed_kat_128) {
  auto key = test::hex_to_bytes(keyed_kat_key_hex);
  auto expected = test::hex_to_bytes(keyed_kat_vectors[6].expected_hex);
  auto input = make_input(keyed_kat_vectors[6].input_len);

  uint8_t out[64];
  int rc = tinyblake_blake2b(out, 64, input.data(), input.size(), key.data(),
                             key.size());
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(blake2b_keyed_kat_255) {
  auto key = test::hex_to_bytes(keyed_kat_key_hex);
  auto expected = test::hex_to_bytes(keyed_kat_vectors[7].expected_hex);
  auto input = make_input(keyed_kat_vectors[7].input_len);

  uint8_t out[64];
  int rc = tinyblake_blake2b(out, 64, input.data(), input.size(), key.data(),
                             key.size());
  ASSERT_EQ(rc, 0);
  ASSERT_BYTES_EQ(out, expected.data(), 64);
}

TEST(blake2b_keyed_cpp_api) {
  auto key = test::hex_to_bytes(keyed_kat_key_hex);
  auto expected = test::hex_to_bytes(keyed_kat_vectors[0].expected_hex);

  auto digest =
      tinyblake::blake2b::keyed_hash(key.data(), key.size(), nullptr, 0, 64);
  ASSERT_BYTES_EQ(digest.data(), expected.data(), 64);
}

TEST(blake2b_keyed_incremental) {
  auto key = test::hex_to_bytes(keyed_kat_key_hex);
  auto expected = test::hex_to_bytes(keyed_kat_vectors[6].expected_hex);
  auto input = make_input(128);

  /* Feed incrementally */
  tinyblake::blake2b::hasher h(key.data(), key.size(), 64);
  h.update(input.data(), 50);
  h.update(input.data() + 50, 78);
  auto digest = h.final_();

  ASSERT_BYTES_EQ(digest.data(), expected.data(), 64);
}