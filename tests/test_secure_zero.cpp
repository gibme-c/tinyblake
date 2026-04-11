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

#include <tinyblake/common.h>
#include <vector>

/* ─── tinyblake_secure_zero / tinyblake::secure_zero ─── */

TEST(secure_zero_c_api_zeroes_buffer)
{
    uint8_t buf[256];
    for (size_t i = 0; i < 256; ++i)
        buf[i] = 0xA5;

    tinyblake_secure_zero(buf, 256);

    /* Read through a volatile view so the compiler cannot prove the check
     * dead and remove it. */
    volatile const uint8_t *v = buf;
    for (size_t i = 0; i < 256; ++i)
        ASSERT_EQ(v[i], 0);
}

TEST(secure_zero_c_api_zero_length_noop)
{
    uint8_t buf[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    tinyblake_secure_zero(buf, 0);

    /* All 8 sentinel bytes must survive a zero-length zeroize. */
    ASSERT_EQ(buf[0], 0xDE);
    ASSERT_EQ(buf[1], 0xAD);
    ASSERT_EQ(buf[2], 0xBE);
    ASSERT_EQ(buf[3], 0xEF);
    ASSERT_EQ(buf[4], 0xCA);
    ASSERT_EQ(buf[5], 0xFE);
    ASSERT_EQ(buf[6], 0xBA);
    ASSERT_EQ(buf[7], 0xBE);
}

TEST(secure_zero_c_api_single_byte)
{
    uint8_t b = 0xFF;
    tinyblake_secure_zero(&b, 1);
    volatile const uint8_t *v = &b;
    ASSERT_EQ(*v, 0);
}

TEST(secure_zero_cpp_wrapper)
{
    std::vector<uint8_t> vec(1024, 0xFF);
    tinyblake::secure_zero(vec.data(), vec.size());
    for (size_t i = 0; i < vec.size(); ++i)
        ASSERT_EQ(vec[i], 0);
}

TEST(secure_zero_large_buffer)
{
    /* 1 MiB heap buffer — catches partial-loop / early-exit bugs. */
    const size_t N = 1024 * 1024;
    std::vector<uint8_t> big(N, 0xC3);
    tinyblake_secure_zero(big.data(), N);

    /* Spot-check every 4 KiB page plus the first and last byte. */
    volatile const uint8_t *v = big.data();
    ASSERT_EQ(v[0], 0);
    ASSERT_EQ(v[N - 1], 0);
    for (size_t i = 0; i < N; i += 4096)
        ASSERT_EQ(v[i], 0);
}

/* ─── tinyblake::constant_time_eq C++ wrapper ─── */

TEST(constant_time_eq_cpp_wrapper_equal)
{
    uint8_t a[64];
    uint8_t b[64];
    for (size_t i = 0; i < 64; ++i)
    {
        a[i] = static_cast<uint8_t>(i);
        b[i] = static_cast<uint8_t>(i);
    }
    ASSERT_TRUE(tinyblake::constant_time_eq(a, b, 64));
}

TEST(constant_time_eq_cpp_wrapper_differ_mid)
{
    uint8_t a[64];
    uint8_t b[64];
    for (size_t i = 0; i < 64; ++i)
    {
        a[i] = static_cast<uint8_t>(i);
        b[i] = static_cast<uint8_t>(i);
    }
    b[32] ^= 0x01; /* differ in the middle */
    ASSERT_TRUE(!tinyblake::constant_time_eq(a, b, 64));
}

TEST(constant_time_eq_cpp_wrapper_zero_len)
{
    uint8_t a[1] = {0xAA};
    uint8_t b[1] = {0xBB};
    /* Zero-length comparison is always "equal" (same contract as C API). */
    ASSERT_TRUE(tinyblake::constant_time_eq(a, b, 0));
}
