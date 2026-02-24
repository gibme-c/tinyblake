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
 * HMAC-BLAKE2b-512 test vectors.
 *
 * Generated from known-good implementations. Uses the same structure
 * as HMAC-SHA test vectors from RFC 4231, adapted for BLAKE2b-512.
 */

struct HmacVector {
    const char* key_hex;
    const char* data_hex;
    const char* expected_hex;
};

static const HmacVector hmac_vectors[] = {
    /* Test 1: Short key, short data */
    {
        /* key = "key" (3 bytes) */
        "6b6579",
        /* data = "The quick brown fox jumps over the lazy dog" */
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
        /* HMAC-BLAKE2b-512(key, data) */
        "92294f92c0dfb9b00ec9ae8bd94d7e7d8a036b885a499f149dfe2fd2199394aa"
        "af6b8894a1730cccb2cd050f9bcf5062a38b51b0dab33207f8ef35ae2c9df51b"
    },
    /* Test 2: Empty data */
    {
        /* key = "key" */
        "6b6579",
        /* data = "" */
        "",
        /* HMAC-BLAKE2b-512(key, "") */
        "019fe04bf010b8d72772e6b46897ecf74b4878c394ff2c4d5cfa0b7cc9bbefcb"
        "28c36de23cef03089db9c3d900468c89804f135e9fdef7ec9b3c7abe50ed33d3"
    },
    /* Test 3: Key longer than block size (128 bytes) */
    {
        /* 200-byte key */
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7",
        /* data = "abc" */
        "616263",
        "feb09eb5b1c557085c0a53bdf39ef7bc9af291f21d7c917cd1cf09542aab9536"
        "2de79b3925fe55d92997423b5a68be1bda2f6518df34fa1053bb3ef559b08200"
    },
};

static const size_t hmac_vector_count = sizeof(hmac_vectors) / sizeof(hmac_vectors[0]);