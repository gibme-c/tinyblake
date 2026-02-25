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

#ifndef TINYBLAKE_PBKDF2_H
#define TINYBLAKE_PBKDF2_H

#include "common.h"

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PBKDF2-HMAC-BLAKE2b-512.
 *
 * @param out       Output derived key buffer.
 * @param outlen    Desired derived key length in bytes.
 * @param password  Password bytes.
 * @param passlen   Password length.
 * @param salt      Salt bytes.
 * @param saltlen   Salt length.
 * @param rounds    Iteration count (must be >= 1).
 * @return 0 on success, -1 on error.
 */
TINYBLAKE_API int tinyblake_pbkdf2(void *out, size_t outlen,
                                   const void *password, size_t passlen,
                                   const void *salt, size_t saltlen,
                                   uint32_t rounds);

#ifdef __cplusplus
} /* extern "C" */
#endif

#ifdef __cplusplus

#include <string>
#include <vector>

namespace tinyblake::pbkdf2 {

inline constexpr size_t PRF_OUTPUT_BYTES = 64; /* HMAC-BLAKE2b-512 */

/**
 * Derive a key from a password.
 *
 * @param password  Password bytes.
 * @param passlen   Password length.
 * @param salt      Salt bytes.
 * @param saltlen   Salt length.
 * @param rounds    Iteration count.
 * @param outlen    Desired key length.
 * @return Derived key bytes.
 */
TINYBLAKE_API std::vector<uint8_t> derive(const void *password, size_t passlen,
                                          const void *salt, size_t saltlen,
                                          uint32_t rounds, size_t outlen);

TINYBLAKE_API std::vector<uint8_t> derive(const std::string &password,
                                          const std::vector<uint8_t> &salt,
                                          uint32_t rounds, size_t outlen);

} /* namespace tinyblake::pbkdf2 */

#endif /* __cplusplus */

#endif /* TINYBLAKE_PBKDF2_H */