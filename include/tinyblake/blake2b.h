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

#ifndef TINYBLAKE_BLAKE2B_H
#define TINYBLAKE_BLAKE2B_H

#include "common.h"

#include <cstddef>
#include <cstdint>

/* ──────────────────────────── C API ──────────────────────────── */
#ifdef __cplusplus
extern "C" {
#endif

enum {
  TINYBLAKE_BLAKE2B_BLOCKBYTES = 128,
  TINYBLAKE_BLAKE2B_OUTBYTES = 64,
  TINYBLAKE_BLAKE2B_KEYBYTES = 64,
  TINYBLAKE_BLAKE2B_SALTBYTES = 16,
  TINYBLAKE_BLAKE2B_PERSONALBYTES = 16
};

typedef struct tinyblake_blake2b_state {
  uint64_t h[8];
  uint64_t t[2];
  uint8_t buf[128];
  size_t buflen;
  uint8_t outlen;
} tinyblake_blake2b_state;

TINYBLAKE_API int tinyblake_blake2b_init(tinyblake_blake2b_state *state,
                                         size_t outlen);

TINYBLAKE_API int tinyblake_blake2b_init_key(tinyblake_blake2b_state *state,
                                             size_t outlen, const void *key,
                                             size_t keylen);

TINYBLAKE_API int tinyblake_blake2b_init_param(tinyblake_blake2b_state *state,
                                               const uint8_t param[64]);

TINYBLAKE_API int tinyblake_blake2b_update(tinyblake_blake2b_state *state,
                                           const void *in, size_t inlen);

TINYBLAKE_API int tinyblake_blake2b_final(tinyblake_blake2b_state *state,
                                          void *out, size_t outlen);

/**
 * One-shot hashing convenience.
 */
TINYBLAKE_API int tinyblake_blake2b(void *out, size_t outlen, const void *in,
                                    size_t inlen, const void *key,
                                    size_t keylen);

#ifdef __cplusplus
} /* extern "C" */
#endif

/* ──────────────────────────── C++ API ──────────────────────────── */
#ifdef __cplusplus

#include <array>
#include <string>
#include <vector>

namespace tinyblake::blake2b {

inline constexpr size_t BLOCK_BYTES = 128;
inline constexpr size_t MAX_OUT_BYTES = 64;
inline constexpr size_t MAX_KEY_BYTES = 64;
inline constexpr size_t SALT_BYTES = 16;
inline constexpr size_t PERSONAL_BYTES = 16;

class TINYBLAKE_API hasher {
public:
  /**
   * Construct an unkeyed BLAKE2b hasher.
   * @param outlen  Digest length in bytes (1..64).
   */
  explicit hasher(size_t outlen = 64);

  /**
   * Construct a keyed BLAKE2b hasher.
   * @param key     Key data.
   * @param keylen  Key length in bytes (1..64).
   * @param outlen  Digest length in bytes (1..64).
   */
  hasher(const void *key, size_t keylen, size_t outlen = 64);

  /**
   * Construct with a full 64-byte parameter block.
   */
  explicit hasher(const uint8_t param[64]);

  ~hasher();

  hasher(const hasher &) = delete;
  hasher &operator=(const hasher &) = delete;
  hasher(hasher &&) noexcept;
  hasher &operator=(hasher &&) noexcept;

  /** Feed data. */
  void update(const void *data, size_t len);
  void update(const std::vector<uint8_t> &data);
  void update(const std::string &data);

  /** Finalize and return digest. */
  std::vector<uint8_t> final_();

  /** Finalize into caller-provided buffer. */
  void final_(void *out, size_t outlen);

  /** Reset to initial state (same parameters). */
  void reset();

private:
  tinyblake_blake2b_state state_;
  uint8_t param_[64];
  bool keyed_;
  uint8_t key_block_[128]; /* padded key for reset */
};

/* ─── One-shot free functions ─── */

TINYBLAKE_API std::vector<uint8_t> hash(const void *data, size_t len,
                                        size_t outlen = 64);
TINYBLAKE_API std::vector<uint8_t> hash(const std::vector<uint8_t> &data,
                                        size_t outlen = 64);

TINYBLAKE_API std::vector<uint8_t> keyed_hash(const void *key, size_t keylen,
                                              const void *data, size_t datalen,
                                              size_t outlen = 64);

} /* namespace tinyblake::blake2b */

#endif /* __cplusplus */

#endif /* TINYBLAKE_BLAKE2B_H */