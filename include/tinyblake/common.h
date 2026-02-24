// Copyright (c) 2025-2026, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list
//    of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be
//    used to endorse or promote products derived from this software without
//    specific prior written permission.
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

#ifndef TINYBLAKE_COMMON_H
#define TINYBLAKE_COMMON_H

#include <cstddef>
#include <cstdint>
#include <vector>

#if defined(TINYBLAKE_SHARED)
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(TINYBLAKE_BUILDING)
#define TINYBLAKE_API __declspec(dllexport)
#else
#define TINYBLAKE_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define TINYBLAKE_API __attribute__((visibility("default")))
#else
#define TINYBLAKE_API
#endif
#else
#define TINYBLAKE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Securely zero a memory region, guaranteed not to be optimized away.
 */
TINYBLAKE_API void tinyblake_secure_zero(void *ptr, size_t len);

/**
 * Constant-time comparison of two byte buffers.
 * Returns 1 if equal, 0 if not. Runs in time proportional to len
 * regardless of where the first difference occurs.
 */
TINYBLAKE_API int tinyblake_constant_time_eq(const void *a, const void *b,
                                             size_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#ifdef __cplusplus
namespace tinyblake {

inline void secure_zero(void *ptr, size_t len) {
  tinyblake_secure_zero(ptr, len);
}

inline bool constant_time_eq(const void *a, const void *b, size_t len) {
  return tinyblake_constant_time_eq(a, b, len) == 1;
}

} /* namespace tinyblake */
#endif

#endif /* TINYBLAKE_COMMON_H */