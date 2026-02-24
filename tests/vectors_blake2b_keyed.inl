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
 * BLAKE2b keyed hash test vectors from the official blake2b reference
 * implementation (blake2b-kat.txt).
 *
 * Key = 00 01 02 ... 3f (64 bytes)
 * Input(i) = 00 01 02 ... (i-1)  for i = 0..255
 * Output = BLAKE2b-512(key, input(i))
 *
 * We include a subset: entries 0, 1, 2, 3, 63, 64, 128, 255.
 */

struct KeyedKatVector {
    size_t input_len;
    const char* expected_hex;
};

static const char* const keyed_kat_key_hex =
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f";

static const KeyedKatVector keyed_kat_vectors[] = {
    /* input_len=0: BLAKE2b-512(key, "") */
    {
        0,
        "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786"
        "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"
    },
    /* input_len=1: BLAKE2b-512(key, "\x00") */
    {
        1,
        "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4"
        "187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd"
    },
    /* input_len=2: BLAKE2b-512(key, "\x00\x01") */
    {
        2,
        "da2cfbe2d8409a0f38026113884f84b50156371ae304c4430173d08a99d9fb1b"
        "983164a3770706d537f49e0c916d9f32b95cc37a95b99d857436f0232c88a965"
    },
    /* input_len=3 */
    {
        3,
        "33d0825dddf7ada99b0e7e307104ad07ca9cfd9692214f1561356315e784f3e5"
        "a17e364ae9dbb14cb2036df932b77f4b292761365fb328de7afdc6d8998f5fc1"
    },
    /* input_len=63 */
    {
        63,
        "bd965bf31e87d70327536f2a341cebc4768eca275fa05ef98f7f1b71a0351298"
        "de006fba73fe6733ed01d75801b4a928e54231b38e38c562b2e33ea1284992fa"
    },
    /* input_len=64 */
    {
        64,
        "65676d800617972fbd87e4b9514e1c67402b7a331096d3bfac22f1abb95374ab"
        "c942f16e9ab0ead33b87c91968a6e509e119ff07787b3ef483e1dcdccf6e3022"
    },
    /* input_len=128 */
    {
        128,
        "72065ee4dd91c2d8509fa1fc28a37c7fc9fa7d5b3f8ad3d0d7a25626b57b1b44"
        "788d4caf806290425f9890a3a2a35a905ab4b37acfd0da6e4517b2525c9651e4"
    },
    /* input_len=255 */
    {
        255,
        "142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e9248"
        "4be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461"
    },
};

static const size_t keyed_kat_vector_count = sizeof(keyed_kat_vectors) / sizeof(keyed_kat_vectors[0]);