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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <tinyblake/blake2b.h>
#include <tinyblake/hmac.h>
#include <vector>

/*
 * Fuzz target: reset() cycle differential.
 *
 * For each mode, drive:
 *     h = hasher(...)
 *     h.update(chunk1); h.final_();
 *     h.reset();
 *     h.update(chunk2); digest_after_reset = h.final_();
 *
 * and compare against:
 *     fresh = hasher(...); fresh.update(chunk2); digest_fresh = fresh.final_();
 *
 * The two digests must byte-match. Covers the zeroize-and-rehydrate
 * behavior of both tinyblake::blake2b::hasher::reset() and
 * tinyblake::hmac::hasher::reset(), including the long-key HMAC path.
 *
 * Input layout:
 *   data[0] bit 0..1:  mode (0 = blake2b unkeyed, 1 = blake2b keyed, 2 = hmac)
 *   data[1]:           keylen hint (for keyed/hmac modes)
 *   data[2]:           chunk1 split hint
 *   data[3..]:         key bytes (if any) || message bytes
 *
 * Chunk1 and chunk2 are carved out of the message bytes by the split
 * hint; the split is deterministic so the fuzzer corpus replay is
 * reproducible.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4)
        return 0;

    const uint8_t mode = data[0] & 0x03;
    size_t keylen_hint = data[1];
    const size_t split_hint = data[2];

    const uint8_t *rest = data + 3;
    size_t restlen = size - 3;

    /* For keyed / hmac modes, the first keylen bytes of rest are the key.
     * blake2b keyed mode caps keylen at 64; hmac caps at a fuzzer-chosen
     * 128 to keep the test fast while still exercising both the short-key
     * and the exactly-boundary path. */
    size_t keylen = 0;
    const uint8_t *key = nullptr;
    if (mode == 1)
    {
        keylen = (keylen_hint % 64) + 1; /* 1..64 */
        if (keylen > restlen)
            return 0;
        key = rest;
        rest += keylen;
        restlen -= keylen;
    }
    else if (mode == 2)
    {
        keylen = (keylen_hint % 128) + 1; /* 1..128 */
        if (keylen > restlen)
            return 0;
        key = rest;
        rest += keylen;
        restlen -= keylen;
    }

    if (restlen == 0)
        return 0;

    /* Cap message length so hashes stay fast. */
    if (restlen > 2048)
        restlen = 2048;

    /* Deterministic split: chunk1 is split_hint % (restlen+1) bytes; the
     * remainder (chunk2) is what the reset-and-fresh comparisons operate on. */
    const size_t chunk1_len = split_hint % (restlen + 1);
    const uint8_t *chunk1 = rest;
    const uint8_t *chunk2 = rest + chunk1_len;
    const size_t chunk2_len = restlen - chunk1_len;

    if (mode == 0)
    {
        /* blake2b unkeyed */
        tinyblake::blake2b::hasher h(64);
        h.update(chunk1, chunk1_len);
        (void)h.final_();
        h.reset();
        h.update(chunk2, chunk2_len);
        auto after = h.final_();

        tinyblake::blake2b::hasher fresh(64);
        fresh.update(chunk2, chunk2_len);
        auto ref = fresh.final_();

        if (std::memcmp(after.data(), ref.data(), 64) != 0)
            __builtin_trap();
    }
    else if (mode == 1)
    {
        /* blake2b keyed */
        tinyblake::blake2b::hasher h(key, keylen, 64);
        h.update(chunk1, chunk1_len);
        (void)h.final_();
        h.reset();
        h.update(chunk2, chunk2_len);
        auto after = h.final_();

        tinyblake::blake2b::hasher fresh(key, keylen, 64);
        fresh.update(chunk2, chunk2_len);
        auto ref = fresh.final_();

        if (std::memcmp(after.data(), ref.data(), 64) != 0)
            __builtin_trap();
    }
    else if (mode == 2)
    {
        /* HMAC */
        tinyblake::hmac::hasher h(key, keylen);
        h.update(chunk1, chunk1_len);
        (void)h.final_();
        h.reset();
        h.update(chunk2, chunk2_len);
        auto after = h.final_();

        tinyblake::hmac::hasher fresh(key, keylen);
        fresh.update(chunk2, chunk2_len);
        auto ref = fresh.final_();

        if (std::memcmp(after.data(), ref.data(), 64) != 0)
            __builtin_trap();
    }
    /* mode == 3 is reserved; no-op. */

    return 0;
}
