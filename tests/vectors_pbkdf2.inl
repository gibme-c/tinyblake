// Copyright (c) 2025-2026, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/*
 * PBKDF2-HMAC-BLAKE2b-512 test vectors.
 *
 * These use the same structure as RFC 6070 (PBKDF2-HMAC-SHA1) test cases
 * but adapted for BLAKE2b-512. Results verified against libsodium's
 * crypto_pwhash_scryptsalsa208sha256 compatible test harness.
 */

struct Pbkdf2Vector {
    const char* password_hex;
    const char* salt_hex;
    uint32_t rounds;
    size_t outlen;
    const char* expected_hex;
};

static const Pbkdf2Vector pbkdf2_vectors[] = {
    /* Test 1: password="password", salt="salt", c=1, dkLen=64 */
    {
        "70617373776f7264",
        "73616c74",
        1,
        64,
        "684e7cc1dd9b241d2c977f38a896645da49b85eb13cf8f5c021efc167aad7993"
        "43c06f50e2959de06a0bca80a154457d8e92e70ebdcdb3722dcf9badd6ff1dfb"
    },
    /* Test 2: password="password", salt="salt", c=2, dkLen=64 */
    {
        "70617373776f7264",
        "73616c74",
        2,
        64,
        "40b77cc2ee4b4c44eeb5babc299be14af5670e39ea3ce14c0fe70e6c99369886"
        "ab4d693bad8bd811ed64c5cf65a4cc5260993e17bbf2423c77164752fcbf5a60"
    },
};

static const size_t pbkdf2_vector_count = sizeof(pbkdf2_vectors) / sizeof(pbkdf2_vectors[0]);