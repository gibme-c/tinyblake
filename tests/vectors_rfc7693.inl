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
 * RFC 7693 Appendix A — BLAKE2b test vectors.
 *
 * Vector 1: BLAKE2b-512("abc")
 * Vector 2: empty string BLAKE2b-512("")
 *
 * These are the official test vectors from the RFC.
 */

struct Rfc7693Vector {
    const char* input_hex;
    size_t outlen;
    const char* expected_hex;
};

/*
 * RFC 7693 Section 2.7 — Self-test procedure.
 * The spec gives test vector for BLAKE2b-512("abc"):
 */
static const Rfc7693Vector rfc7693_vectors[] = {
    /* BLAKE2b-512("abc") */
    {
        "616263", /* "abc" */
        64,
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    },
    /* BLAKE2b-512("") — empty input */
    {
        "", /* empty */
        64,
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031"
        "afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    },
};

static const size_t rfc7693_vector_count = sizeof(rfc7693_vectors) / sizeof(rfc7693_vectors[0]);