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
#include "vectors_pbkdf2.inl"

#include <tinyblake/pbkdf2.h>

TEST(pbkdf2_kat_vectors)
{
    for (size_t i = 0; i < pbkdf2_vector_count; ++i)
    {
        auto password = test::hex_to_bytes(pbkdf2_vectors[i].password_hex);
        auto salt = test::hex_to_bytes(pbkdf2_vectors[i].salt_hex);
        auto expected = test::hex_to_bytes(pbkdf2_vectors[i].expected_hex);

        std::vector<uint8_t> out(pbkdf2_vectors[i].outlen);
        int rc = tinyblake_pbkdf2(
            out.data(),
            out.size(),
            password.data(),
            password.size(),
            salt.data(),
            salt.size(),
            pbkdf2_vectors[i].rounds);
        ASSERT_EQ(rc, 0);
        ASSERT_BYTES_EQ(out.data(), expected.data(), out.size());
    }
}

TEST(pbkdf2_basic_deterministic)
{
    /* PBKDF2 with same inputs must produce same output */
    const char *pass = "password";
    const char *salt = "salt";

    uint8_t out1[64], out2[64];
    int rc1 = tinyblake_pbkdf2(out1, 64, pass, 8, salt, 4, 1);
    int rc2 = tinyblake_pbkdf2(out2, 64, pass, 8, salt, 4, 1);

    ASSERT_EQ(rc1, 0);
    ASSERT_EQ(rc2, 0);
    ASSERT_BYTES_EQ(out1, out2, 64);
}

TEST(pbkdf2_different_rounds_differ)
{
    const char *pass = "password";
    const char *salt = "salt";

    uint8_t out1[64], out2[64];
    tinyblake_pbkdf2(out1, 64, pass, 8, salt, 4, 1);
    tinyblake_pbkdf2(out2, 64, pass, 8, salt, 4, 2);

    /* Different round counts must produce different output */
    ASSERT_TRUE(std::memcmp(out1, out2, 64) != 0);
}

TEST(pbkdf2_different_salts_differ)
{
    const char *pass = "password";

    uint8_t out1[64], out2[64];
    tinyblake_pbkdf2(out1, 64, pass, 8, "salt1", 5, 1);
    tinyblake_pbkdf2(out2, 64, pass, 8, "salt2", 5, 1);

    ASSERT_TRUE(std::memcmp(out1, out2, 64) != 0);
}

TEST(pbkdf2_different_passwords_differ)
{
    const char *salt = "salt";

    uint8_t out1[64], out2[64];
    tinyblake_pbkdf2(out1, 64, "pass1", 5, salt, 4, 1);
    tinyblake_pbkdf2(out2, 64, "pass2", 5, salt, 4, 1);

    ASSERT_TRUE(std::memcmp(out1, out2, 64) != 0);
}

TEST(pbkdf2_short_output)
{
    /* Request only 16 bytes (less than one PRF block) */
    const char *pass = "password";
    const char *salt = "salt";

    uint8_t short_out[16];
    int rc = tinyblake_pbkdf2(short_out, 16, pass, 8, salt, 4, 1);
    ASSERT_EQ(rc, 0);

    /* First 16 bytes should match first 16 bytes of full output */
    uint8_t full_out[64];
    tinyblake_pbkdf2(full_out, 64, pass, 8, salt, 4, 1);
    ASSERT_BYTES_EQ(short_out, full_out, 16);
}

TEST(pbkdf2_long_output)
{
    /* Request more than 64 bytes (multiple PRF blocks) */
    const char *pass = "password";
    const char *salt = "salt";

    uint8_t out[128];
    int rc = tinyblake_pbkdf2(out, 128, pass, 8, salt, 4, 1);
    ASSERT_EQ(rc, 0);

    /* First 64 bytes should match T1 */
    uint8_t t1[64];
    tinyblake_pbkdf2(t1, 64, pass, 8, salt, 4, 1);
    ASSERT_BYTES_EQ(out, t1, 64);

    /* Bytes 64-127 should be different from first 64 (T2 != T1) */
    ASSERT_TRUE(std::memcmp(out, out + 64, 64) != 0);
}

TEST(pbkdf2_cpp_api)
{
    auto result = tinyblake::pbkdf2::derive("password", 8, "salt", 4, 1, 64);
    ASSERT_EQ(result.size(), 64u);

    /* Should match C API */
    uint8_t c_out[64];
    tinyblake_pbkdf2(c_out, 64, "password", 8, "salt", 4, 1);
    ASSERT_BYTES_EQ(result.data(), c_out, 64);
}

TEST(pbkdf2_cpp_string_api)
{
    std::string pass = "password";
    std::vector<uint8_t> salt = {'s', 'a', 'l', 't'};

    auto result = tinyblake::pbkdf2::derive(pass, salt, 1, 64);

    uint8_t c_out[64];
    tinyblake_pbkdf2(c_out, 64, "password", 8, "salt", 4, 1);
    ASSERT_BYTES_EQ(result.data(), c_out, 64);
}

TEST(pbkdf2_error_cases)
{
    ASSERT_EQ(tinyblake_pbkdf2(nullptr, 64, "p", 1, "s", 1, 1), -1);

    uint8_t out[64];
    ASSERT_EQ(tinyblake_pbkdf2(out, 0, "p", 1, "s", 1, 1), -1);
    ASSERT_EQ(tinyblake_pbkdf2(out, 64, "p", 1, "s", 1, 0), -1);
}

TEST(pbkdf2_output_length_limit)
{
    /* RFC 8018: dkLen must be <= (2^32 - 1) * hLen
     * For HMAC-BLAKE2b-512, hLen=64, so max = 0xFFFFFFFF * 64.
     * We can't allocate that much, but we can verify the check rejects
     * a value just over the limit using SIZE_MAX (which on 64-bit exceeds it). */
#if SIZE_MAX > UINT32_MAX
    uint8_t dummy;
    /* SIZE_MAX is definitely > UINT32_MAX * 64, so this must fail */
    ASSERT_EQ(tinyblake_pbkdf2(&dummy, SIZE_MAX, "p", 1, "s", 1, 1), -1);
#endif
}

/* ─── multi-PRF-block output (3 and 4 BLAKE2b-512 blocks) ─── */

TEST(pbkdf2_output_192_bytes)
{
    const char *pass = "password";
    const char *salt = "salt";

    uint8_t dk192[192];
    ASSERT_EQ(tinyblake_pbkdf2(dk192, 192, pass, 8, salt, 4, 4), 0);

    /* Determinism */
    uint8_t dk192_again[192];
    ASSERT_EQ(tinyblake_pbkdf2(dk192_again, 192, pass, 8, salt, 4, 4), 0);
    ASSERT_BYTES_EQ(dk192, dk192_again, 192);

    /* T1 must equal a standalone single-block derive with the same
     * (password, salt, rounds). */
    uint8_t t1[64];
    ASSERT_EQ(tinyblake_pbkdf2(t1, 64, pass, 8, salt, 4, 4), 0);
    ASSERT_BYTES_EQ(dk192, t1, 64);

    /* T2 (bytes 64..127) and T3 (bytes 128..191) must differ from T1 and
     * from each other (distinct INT_32_BE(i) values). */
    ASSERT_TRUE(std::memcmp(dk192 + 64, t1, 64) != 0);
    ASSERT_TRUE(std::memcmp(dk192 + 128, t1, 64) != 0);
    ASSERT_TRUE(std::memcmp(dk192 + 64, dk192 + 128, 64) != 0);
}

TEST(pbkdf2_output_256_bytes)
{
    const char *pass = "password";
    const char *salt = "NaCl";

    uint8_t dk256[256];
    ASSERT_EQ(tinyblake_pbkdf2(dk256, 256, pass, 8, salt, 4, 4), 0);

    /* Determinism */
    uint8_t dk256_again[256];
    ASSERT_EQ(tinyblake_pbkdf2(dk256_again, 256, pass, 8, salt, 4, 4), 0);
    ASSERT_BYTES_EQ(dk256, dk256_again, 256);

    /* All four PRF blocks must be distinct. */
    ASSERT_TRUE(std::memcmp(dk256 + 0, dk256 + 64, 64) != 0);
    ASSERT_TRUE(std::memcmp(dk256 + 0, dk256 + 128, 64) != 0);
    ASSERT_TRUE(std::memcmp(dk256 + 0, dk256 + 192, 64) != 0);
    ASSERT_TRUE(std::memcmp(dk256 + 64, dk256 + 128, 64) != 0);
    ASSERT_TRUE(std::memcmp(dk256 + 64, dk256 + 192, 64) != 0);
    ASSERT_TRUE(std::memcmp(dk256 + 128, dk256 + 192, 64) != 0);
}

/* ─── error-path bail leaves out[] untouched ───
 *
 * The top-of-function rejects (rounds == 0, outlen == 0) short-circuit
 * before the dk loop runs, so the caller's buffer is unchanged. This
 * test documents that contract and protects against future regressions
 * that might start writing partial bytes before validation. */

TEST(pbkdf2_error_bail_leaves_output_untouched)
{
    uint8_t out[64];
    std::memset(out, 0xCC, sizeof(out));

    /* rounds=0 must return -1 without touching out[]. */
    ASSERT_EQ(tinyblake_pbkdf2(out, 64, "password", 8, "salt", 4, 0), -1);
    for (size_t i = 0; i < 64; ++i)
        ASSERT_EQ(out[i], 0xCC);
}

/* ─── RFC 8018 allows NULL/empty salt ─── */

TEST(pbkdf2_null_salt_zero_len_accepted)
{
    /* RFC 8018 §5.2 does not require a non-empty salt. Our HMAC layer
     * accepts empty message data (inlen==0), so this should succeed. */
    uint8_t out[64];
    int rc = tinyblake_pbkdf2(out, 64, "password", 8, nullptr, 0, 1);
    ASSERT_EQ(rc, 0);

    /* Determinism across two calls. */
    uint8_t out2[64];
    ASSERT_EQ(tinyblake_pbkdf2(out2, 64, "password", 8, nullptr, 0, 1), 0);
    ASSERT_BYTES_EQ(out, out2, 64);
}