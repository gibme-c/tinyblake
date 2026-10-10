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

#ifndef TINYBLAKE_INTERNAL_SECURE_CLEAR_H
#define TINYBLAKE_INTERNAL_SECURE_CLEAR_H

#include <cstddef>
#include <cstring>

#if !(defined(__GNUC__) || defined(__clang__))
#include "tinyblake/common.h" /* tinyblake_secure_zero (non-GCC/Clang paths) */
#endif

namespace tinyblake::detail
{

    /*
     * Inlinable secure clear for hot-path working buffers — specifically the
     * per-block m[] message schedule in the compress backends, which must be
     * wiped on every 128-byte block so no message or key material survives on
     * the stack. The compiler is prevented from eliding the zeroing store as dead:
     *
     *   - GCC / Clang (including clang-cl and MinGW): a memory-clobber inline-asm
     *     barrier after the memset. Fully inlined, so there is no per-block
     *     out-of-line call in the hot path. Routing this through the external
     *     tinyblake_secure_zero instead would add a non-inlinable call per block
     *     (and degrade to a volatile byte sweep on platforms without
     *     explicit_bzero/memset_s), a large throughput cost on the bulk-hashing path.
     *   - Everything else (true MSVC, or any toolchain without GNU inline asm):
     *     delegate to tinyblake_secure_zero, the one authoritative out-of-line
     *     scrub (SecureZeroMemory / memset_s / explicit_bzero / volatile sweep),
     *     rather than re-implementing that slow path here.
     */
    inline void secure_clear(void *ptr, size_t len)
    {
#if defined(__GNUC__) || defined(__clang__)
        std::memset(ptr, 0, len);
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
        tinyblake_secure_zero(ptr, len);
#endif
    }

} /* namespace tinyblake::detail */

#endif /* TINYBLAKE_INTERNAL_SECURE_CLEAR_H */
