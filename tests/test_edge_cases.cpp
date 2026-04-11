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

#include <cstring>
#include <tinyblake/blake2b.h>
#include <vector>

/* ─── boundary message lengths around the 128-byte block ───
 *
 * Each test feeds a deterministic pattern through one-shot and incremental
 * paths with a 17-byte chunk size (coprime with 128) so every phase of the
 * block-fill path is exercised. */

static void run_msglen_case(size_t N)
{
    std::vector<uint8_t> msg(N);
    for (size_t i = 0; i < N; ++i)
        msg[i] = static_cast<uint8_t>(i & 0xFF);

    uint8_t ref[64];
    int rc = tinyblake_blake2b(ref, 64, msg.data(), N, nullptr, 0);
    ASSERT_EQ(rc, 0);

    tinyblake::blake2b::hasher h(64);
    size_t pos = 0;
    while (pos < N)
    {
        size_t n = 17;
        if (pos + n > N)
            n = N - pos;
        h.update(msg.data() + pos, n);
        pos += n;
    }
    auto got = h.final_();
    ASSERT_BYTES_EQ(got.data(), ref, 64);
}

TEST(edge_msglen_65)
{
    run_msglen_case(65);
}
TEST(edge_msglen_127)
{
    run_msglen_case(127);
}
TEST(edge_msglen_129)
{
    run_msglen_case(129);
}
TEST(edge_msglen_256)
{
    run_msglen_case(256);
}
TEST(edge_msglen_1023)
{
    run_msglen_case(1023);
}
TEST(edge_msglen_1024)
{
    run_msglen_case(1024);
}
TEST(edge_msglen_1025)
{
    run_msglen_case(1025);
}

/* ─── every keylen 1..64 (unkeyed-incremental vs C-one-shot keyed) ───
 *
 * Catches any off-by-one in the key_block_ padding or in the keylen
 * parameter-block byte for every legal key length. */

TEST(blake2b_all_keylens_1_to_64)
{
    uint8_t key[64];
    for (int i = 0; i < 64; ++i)
        key[i] = static_cast<uint8_t>(i);

    const char *msg = "differential-keylen-test";
    const size_t msglen = std::strlen(msg);

    for (size_t keylen = 1; keylen <= 64; ++keylen)
    {
        uint8_t ref[64];
        int rc = tinyblake_blake2b(ref, 64, msg, msglen, key, keylen);
        ASSERT_EQ(rc, 0);

        tinyblake::blake2b::hasher h(key, keylen, 64);
        h.update(msg, msglen);
        auto got = h.final_();
        ASSERT_BYTES_EQ(got.data(), ref, 64);
    }
}

/* ─── every outlen 1..64 C API vs C++ API ───
 *
 * Covers the param[0] (digest_length) path plus the C++ wrapper's
 * vector-sizing path for every legal output length. */

TEST(blake2b_all_outlens_c_vs_cpp)
{
    const char *msg = "differential-outlen-test";
    const size_t msglen = std::strlen(msg);

    for (size_t outlen = 1; outlen <= 64; ++outlen)
    {
        uint8_t ref[64];
        int rc = tinyblake_blake2b(ref, outlen, msg, msglen, nullptr, 0);
        ASSERT_EQ(rc, 0);

        auto got = tinyblake::blake2b::hash(msg, msglen, outlen);
        ASSERT_EQ(got.size(), outlen);
        ASSERT_BYTES_EQ(got.data(), ref, outlen);
    }
}
