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

#include "backend/blake2b_compress.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <tinyblake/blake2b.h>

/*
 * Fuzz target: cross-backend consistency.
 *
 * Two modes selected by the low bit of data[0]:
 *
 *   Mode 0 (bit 0 == 0): raw single-block compress differential.
 *     Runs the portable compress path on one synthetic 128-B block with
 *     one synthetic state and compares against the dispatched path via
 *     the public API with the same state/block. Would have caught the
 *     AVX2 alignment crash.
 *
 *   Mode 1 (bit 0 == 1): multi-block public-API differential, keyed or
 *     unkeyed. Runs the public one-shot tinyblake_blake2b() (which uses
 *     the runtime-dispatched compress) and compares against a
 *     hand-rolled reference that drives blake2b_compress_portable
 *     directly through the full update+final state machine for
 *     arbitrary message lengths. Covers the update-buffer transitions
 *     across backend boundaries plus the keyed-mode key-block prefix.
 */

static const uint64_t CROSS_IV[8] = {
    0x6a09e667f3bcc908ULL,
    0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,
    0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,
    0x5be0cd19137e2179ULL,
};

/*
 * Hash (msg, key, outlen) by driving blake2b_compress_portable directly
 * through the full update+final state machine. Mirrors the logic in
 * src/blake2b.cpp exactly. Caller-supplied msglen is capped upstream so
 * the 64-bit counter never wraps (t[1] stays zero).
 */
static void portable_reference_hash(
    uint8_t *out,
    size_t outlen,
    const uint8_t *msg,
    size_t msglen,
    const uint8_t *key,
    size_t keylen)
{
    uint8_t param[64];
    std::memset(param, 0, 64);
    param[0] = static_cast<uint8_t>(outlen);
    param[1] = static_cast<uint8_t>(keylen);
    param[2] = 1;
    param[3] = 1;

    uint64_t h[8];
    for (int i = 0; i < 8; ++i)
    {
        uint64_t p = 0;
        for (int b = 0; b < 8; ++b)
            p |= static_cast<uint64_t>(param[i * 8 + b]) << (b * 8);
        h[i] = CROSS_IV[i] ^ p;
    }

    /* Assemble (padded 128-B key block if keyed) || message into a stack
     * scratch buffer. Caller caps msglen at 4096 so the total fits in 4224
     * bytes, avoiding any heap allocation on this billions-of-iterations
     * fuzzer hot path. */
    uint8_t full[4096 + 128];
    size_t total = 0;
    if (keylen > 0)
    {
        std::memset(full, 0, 128);
        std::memcpy(full, key, keylen);
        total = 128;
    }
    if (msglen > 0)
    {
        std::memcpy(full + total, msg, msglen);
        total += msglen;
    }

    uint64_t t0 = 0;
    uint8_t block[128];

    if (total == 0)
    {
        /* Unkeyed empty message: one compress on the zero block. */
        std::memset(block, 0, 128);
        tinyblake::blake2b_compress_portable(h, block, 0, 0, true);
    }
    else
    {
        size_t pos = 0;
        /* Non-final blocks: every full 128-B chunk EXCEPT the last one.
         * Mirrors `while (inlen > 128)` in src/blake2b.cpp. */
        while (total - pos > 128)
        {
            t0 += 128;
            tinyblake::blake2b_compress_portable(h, full + pos, t0, 0, false);
            pos += 128;
        }
        /* Final block (possibly a partial chunk, possibly exactly 128). */
        const size_t last_len = total - pos;
        t0 += last_len;
        std::memset(block, 0, 128);
        std::memcpy(block, full + pos, last_len);
        tinyblake::blake2b_compress_portable(h, block, t0, 0, true);
    }

    /* Extract the first outlen bytes of the digest, little-endian. */
    uint8_t buf[64];
    for (int i = 0; i < 8; ++i)
        for (int b = 0; b < 8; ++b)
            buf[i * 8 + b] = static_cast<uint8_t>(h[i] >> (b * 8));
    std::memcpy(out, buf, outlen);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;

    const bool mode1 = (data[0] & 1) != 0;

    if (mode1)
    {
        /* Multi-block public-API differential, keyed or unkeyed. */
        if (size < 4)
            return 0;

        size_t outlen = (data[1] % 64) + 1;
        size_t keylen = data[2] % 65; /* 0 = unkeyed, 1..64 = keyed */

        const uint8_t *rest = data + 3;
        size_t restlen = size - 3;

        if (keylen > restlen)
            return 0;
        const uint8_t *key = (keylen > 0) ? rest : nullptr;
        rest += keylen;
        restlen -= keylen;

        /* Cap message length so the counter cannot wrap into t[1]. */
        if (restlen > 4096)
            restlen = 4096;

        uint8_t out_pub[64];
        int rc_pub = tinyblake_blake2b(out_pub, outlen, rest, restlen, key, keylen);
        if (rc_pub != 0)
            __builtin_trap();

        uint8_t out_ref[64];
        portable_reference_hash(out_ref, outlen, rest, restlen, key, keylen);

        if (std::memcmp(out_pub, out_ref, outlen) != 0)
            __builtin_trap();

        return 0;
    }

    /* Mode 0: single-block differential. Hashes one 128-byte block via the
     * public API (dispatched compress) and via a hand-rolled portable path,
     * then asserts byte-equal outputs. */
    if (size < 193)
        return 0;

    const uint8_t *block = data + 64;

    /* Build a valid param block: outlen=64, fanout=1, depth=1 */
    uint8_t param[64];
    std::memset(param, 0, 64);
    param[0] = 64; /* digest_length */
    param[2] = 1; /* fanout */
    param[3] = 1; /* depth */

    /* State A: public API (dispatched compress) */
    tinyblake_blake2b_state Sa;
    tinyblake_blake2b_init_param(&Sa, param);
    tinyblake_blake2b_update(&Sa, block, 128);
    uint8_t out_a[64];
    tinyblake_blake2b_final(&Sa, out_a, 64);

    /* State B: portable compress, initialized from the same param block. */
    uint64_t h[8];
    for (int i = 0; i < 8; ++i)
    {
        uint64_t p = 0;
        for (int b = 0; b < 8; ++b)
        {
            p |= static_cast<uint64_t>(param[i * 8 + b]) << (b * 8);
        }
        h[i] = CROSS_IV[i] ^ p;
    }

    uint8_t padded[128];
    std::memcpy(padded, block, 128);
    tinyblake::blake2b_compress_portable(h, padded, 128, 0, true);

    /* Extract portable output */
    uint8_t out_b[64];
    for (int i = 0; i < 8; ++i)
    {
        for (int b = 0; b < 8; ++b)
        {
            out_b[i * 8 + b] = static_cast<uint8_t>(h[i] >> (b * 8));
        }
    }

    /* Both must produce identical output */
    if (std::memcmp(out_a, out_b, 64) != 0)
        __builtin_trap();

    return 0;
}
