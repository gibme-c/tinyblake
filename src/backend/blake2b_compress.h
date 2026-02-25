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

#ifndef TINYBLAKE_BACKEND_BLAKE2B_COMPRESS_H
#define TINYBLAKE_BACKEND_BLAKE2B_COMPRESS_H

#include <cstdint>

namespace tinyblake {

/**
 * Compress function signature shared by all backends.
 *
 * @param state     8-word chaining value (modified in place)
 * @param block     128-byte message block
 * @param t0, t1    byte counter (low, high)
 * @param last      true if this is the final block
 */
using blake2b_compress_fn = void (*)(uint64_t state[8],
                                     const uint8_t block[128], uint64_t t0,
                                     uint64_t t1, bool last);

/* Backend implementations */
void blake2b_compress_portable(uint64_t state[8], const uint8_t block[128],
                               uint64_t t0, uint64_t t1, bool last);

void blake2b_compress_x64(uint64_t state[8], const uint8_t block[128],
                          uint64_t t0, uint64_t t1, bool last);

void blake2b_compress_avx2(uint64_t state[8], const uint8_t block[128],
                           uint64_t t0, uint64_t t1, bool last);

void blake2b_compress_avx512(uint64_t state[8], const uint8_t block[128],
                             uint64_t t0, uint64_t t1, bool last);

void blake2b_compress_neon(uint64_t state[8], const uint8_t block[128],
                           uint64_t t0, uint64_t t1, bool last);

} /* namespace tinyblake */

#endif /* TINYBLAKE_BACKEND_BLAKE2B_COMPRESS_H */