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

#ifndef TINYBLAKE_HMAC_H
#define TINYBLAKE_HMAC_H

#include "blake2b.h"
#include "common.h"

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HMAC-BLAKE2b-512 (block size = 128 bytes).
 */
typedef struct tinyblake_hmac_state {
  tinyblake_blake2b_state inner;
  tinyblake_blake2b_state outer;
} tinyblake_hmac_state;

TINYBLAKE_API int tinyblake_hmac_init(tinyblake_hmac_state *state,
                                      const void *key, size_t keylen);

TINYBLAKE_API int tinyblake_hmac_update(tinyblake_hmac_state *state,
                                        const void *in, size_t inlen);

TINYBLAKE_API int tinyblake_hmac_final(tinyblake_hmac_state *state, void *out,
                                       size_t outlen);

TINYBLAKE_API int tinyblake_hmac(void *out, size_t outlen, const void *key,
                                 size_t keylen, const void *in, size_t inlen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#ifdef __cplusplus

#include <string>
#include <vector>

namespace tinyblake::hmac {

inline constexpr size_t DIGEST_BYTES = 64;
inline constexpr size_t BLOCK_BYTES = 128;

class TINYBLAKE_API hasher {
public:
  hasher(const void *key, size_t keylen);
  explicit hasher(const std::vector<uint8_t> &key);
  ~hasher();

  hasher(const hasher &) = delete;
  hasher &operator=(const hasher &) = delete;

  hasher(hasher &&) noexcept;
  hasher &operator=(hasher &&) noexcept;

  void update(const void *data, size_t len);
  void update(const std::vector<uint8_t> &data);
  void update(const std::string &data);

  std::vector<uint8_t> final_();
  void final_(void *out, size_t outlen);

  void reset();

private:
  tinyblake_hmac_state state_;
  uint8_t key_pad_[128]; /* for reset: stores the (hashed) key */
};

/* ─── One-shot free function ─── */

TINYBLAKE_API std::vector<uint8_t> mac(const void *key, size_t keylen,
                                       const void *data, size_t datalen);

} /* namespace tinyblake::hmac */

#endif /* __cplusplus */

#endif /* TINYBLAKE_HMAC_H */