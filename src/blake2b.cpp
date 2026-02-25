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

#include "tinyblake/blake2b.h"
#include "backend/blake2b_compress.h"
#include "cpu_features.h"
#include "internal/endian.h"

#include <atomic>
#include <cstring>
#include <stdexcept>

namespace tinyblake {

/* ─── BLAKE2b IV ─── */
static const uint64_t IV[8] = {0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
                               0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
                               0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
                               0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL};

/* ─── Dispatch (atomic function pointer, no mutex) ─── */

static blake2b_compress_fn resolve_compress() {
#if !defined(TINYBLAKE_FORCE_PORTABLE)
  const auto &feat = cpu::detect();
#endif

#if (defined(__x86_64__) || defined(_M_X64)) &&                                \
    !defined(TINYBLAKE_FORCE_PORTABLE)
  if (feat.avx512f && feat.avx512vl && feat.avx512vbmi2)
    return blake2b_compress_avx512;
  if (feat.avx2)
    return blake2b_compress_avx2;
  return blake2b_compress_x64;
#elif (defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)) &&    \
    !defined(TINYBLAKE_FORCE_PORTABLE)
  if (feat.neon)
    return blake2b_compress_neon;
  return blake2b_compress_portable;
#else
  return blake2b_compress_portable;
#endif
}

static std::atomic<blake2b_compress_fn> g_compress{nullptr};

static blake2b_compress_fn get_compress() {
  blake2b_compress_fn fn = g_compress.load(std::memory_order_acquire);
  if (!fn) {
    fn = resolve_compress();
    g_compress.store(fn, std::memory_order_release);
  }
  return fn;
}

/* ─── Parameter block helpers ─── */

static void build_default_param(uint8_t param[64], uint8_t outlen,
                                uint8_t keylen) {
  std::memset(param, 0, 64);
  param[0] = outlen; /* digest_length */
  param[1] = keylen; /* key_length */
  param[2] = 1;      /* fanout */
  param[3] = 1;      /* depth */
                     /* bytes 4..63 are zero (leaf_length, node_offset, etc.) */
}

static int init_from_param(tinyblake_blake2b_state *S,
                           const uint8_t param[64]) {
  if (param[0] == 0 || param[0] > 64)
    return -1;

  std::memset(S, 0, sizeof(*S));
  S->outlen = param[0];

  for (int i = 0; i < 8; ++i) {
    S->h[i] = IV[i] ^ detail::load_le64(param + i * 8);
  }
  return 0;
}

/* ─── Incremental compress helper ─── */

static void compress_block(tinyblake_blake2b_state *S, const uint8_t block[128],
                           bool last) {
  get_compress()(S->h, block, S->t[0], S->t[1], last);
}

/* ─── C API ─── */

} /* namespace tinyblake */

extern "C" {

int tinyblake_blake2b_init(tinyblake_blake2b_state *state, size_t outlen) {
  if (!state || outlen == 0 || outlen > 64)
    return -1;

  uint8_t param[64];
  tinyblake::build_default_param(param, static_cast<uint8_t>(outlen), 0);
  return tinyblake::init_from_param(state, param);
}

int tinyblake_blake2b_init_key(tinyblake_blake2b_state *state, size_t outlen,
                               const void *key, size_t keylen) {
  if (!state || outlen == 0 || outlen > 64)
    return -1;
  if (!key || keylen == 0 || keylen > 64)
    return -1;

  uint8_t param[64];
  tinyblake::build_default_param(param, static_cast<uint8_t>(outlen),
                                 static_cast<uint8_t>(keylen));
  if (tinyblake::init_from_param(state, param) != 0)
    return -1;

  /* Pad key to block size and feed through update.
   * This ensures correct handling when no message data follows:
   * the key block stays in the buffer and becomes the final block. */
  uint8_t block[128];
  std::memset(block, 0, 128);
  std::memcpy(block, key, keylen);

  tinyblake_blake2b_update(state, block, 128);

  tinyblake_secure_zero(block, 128);
  return 0;
}

int tinyblake_blake2b_init_param(tinyblake_blake2b_state *state,
                                 const uint8_t param[64]) {
  if (!state || !param)
    return -1;
  return tinyblake::init_from_param(state, param);
}

int tinyblake_blake2b_update(tinyblake_blake2b_state *state, const void *in,
                             size_t inlen) {
  if (!state)
    return -1;
  if (state->buflen > 128)
    return -1;
  if (inlen == 0)
    return 0;
  if (!in)
    return -1;

  const uint8_t *pin = static_cast<const uint8_t *>(in);

  /* If buffer has data, try to fill it */
  if (state->buflen > 0) {
    size_t left = 128 - state->buflen;
    if (inlen > left) {
      /* Fill buffer, compress it */
      std::memcpy(state->buf + state->buflen, pin, left);
      state->t[0] += 128;
      if (state->t[0] < 128)
        state->t[1]++;
      tinyblake::compress_block(state, state->buf, false);
      state->buflen = 0;
      pin += left;
      inlen -= left;
    } else {
      std::memcpy(state->buf + state->buflen, pin, inlen);
      state->buflen += inlen;
      return 0;
    }
  }

  /* Compress full blocks, keeping at least 1 byte for final */
  while (inlen > 128) {
    state->t[0] += 128;
    if (state->t[0] < 128)
      state->t[1]++;
    tinyblake::compress_block(state, pin, false);
    pin += 128;
    inlen -= 128;
  }

  /* Buffer remaining */
  if (inlen > 0) {
    std::memcpy(state->buf, pin, inlen);
    state->buflen = inlen;
  }

  return 0;
}

int tinyblake_blake2b_final(tinyblake_blake2b_state *state, void *out,
                            size_t outlen) {
  if (!state || !out)
    return -1;
  if (outlen < state->outlen)
    return -1;

  /* Advance counter by remaining bytes in buffer */
  state->t[0] += state->buflen;
  if (state->t[0] < state->buflen)
    state->t[1]++;

  /* Pad with zeros */
  if (state->buflen < 128) {
    std::memset(state->buf + state->buflen, 0, 128 - state->buflen);
  }

  tinyblake::compress_block(state, state->buf, true);

  /* Store output (little-endian) */
  uint8_t buffer[64];
  for (int i = 0; i < 8; ++i) {
    tinyblake::detail::store_le64(buffer + i * 8, state->h[i]);
  }
  std::memcpy(out, buffer, state->outlen);
  tinyblake_secure_zero(buffer, 64);

  tinyblake_secure_zero(state, sizeof(*state));
  return 0;
}

int tinyblake_blake2b(void *out, size_t outlen, const void *in, size_t inlen,
                      const void *key, size_t keylen) {
  tinyblake_blake2b_state S;
  int rc;

  if (keylen > 0) {
    rc = tinyblake_blake2b_init_key(&S, outlen, key, keylen);
  } else {
    rc = tinyblake_blake2b_init(&S, outlen);
  }
  if (rc != 0)
    return rc;

  rc = tinyblake_blake2b_update(&S, in, inlen);
  if (rc != 0)
    return rc;

  return tinyblake_blake2b_final(&S, out, outlen);
}

} /* extern "C" */

/* ─── C++ wrapper ─── */

namespace tinyblake::blake2b {

hasher::hasher(size_t outlen) : keyed_(false) {
  if (outlen == 0 || outlen > 64)
    throw std::invalid_argument("Blake2b: outlen must be 1..64");
  std::memset(key_block_, 0, 128);
  build_default_param(param_, static_cast<uint8_t>(outlen), 0);
  if (init_from_param(&state_, param_) != 0)
    throw std::runtime_error("Blake2b: init_from_param failed");
}

hasher::hasher(const void *key, size_t keylen, size_t outlen) : keyed_(true) {
  if (outlen == 0 || outlen > 64)
    throw std::invalid_argument("Blake2b: outlen must be 1..64");
  if (!key || keylen == 0 || keylen > 64)
    throw std::invalid_argument(
        "Blake2b: key must be non-null with keylen 1..64");
  std::memset(key_block_, 0, 128);
  std::memcpy(key_block_, key, keylen);
  build_default_param(param_, static_cast<uint8_t>(outlen),
                      static_cast<uint8_t>(keylen));
  if (init_from_param(&state_, param_) != 0)
    throw std::runtime_error("Blake2b: init_from_param failed");

  if (tinyblake_blake2b_update(&state_, key_block_, 128) != 0)
    throw std::runtime_error("Blake2b: key block update failed");
}

hasher::hasher(const uint8_t param[64]) : keyed_(false) {
  if (!param)
    throw std::invalid_argument("Blake2b: param must be non-null");
  std::memset(key_block_, 0, 128);
  std::memcpy(param_, param, 64);
  if (init_from_param(&state_, param_) != 0)
    throw std::invalid_argument(
        "Blake2b: invalid parameter block (outlen must be 1..64)");
}

hasher::~hasher() {
  tinyblake_secure_zero(&state_, sizeof(state_));
  tinyblake_secure_zero(key_block_, sizeof(key_block_));
}

hasher::hasher(hasher &&o) noexcept : state_(o.state_), keyed_(o.keyed_) {
  std::memcpy(param_, o.param_, 64);
  std::memcpy(key_block_, o.key_block_, 128);
  tinyblake_secure_zero(&o.state_, sizeof(o.state_));
  tinyblake_secure_zero(o.key_block_, 128);
}

hasher &hasher::operator=(hasher &&o) noexcept {
  if (this != &o) {
    tinyblake_secure_zero(&state_, sizeof(state_));
    tinyblake_secure_zero(key_block_, 128);
    state_ = o.state_;
    keyed_ = o.keyed_;
    std::memcpy(param_, o.param_, 64);
    std::memcpy(key_block_, o.key_block_, 128);
    tinyblake_secure_zero(&o.state_, sizeof(o.state_));
    tinyblake_secure_zero(o.key_block_, 128);
  }
  return *this;
}

void hasher::update(const void *data, size_t len) {
  if (tinyblake_blake2b_update(&state_, data, len) != 0)
    throw std::runtime_error("Blake2b::update failed");
}

void hasher::update(const std::vector<uint8_t> &data) {
  update(data.data(), data.size());
}

void hasher::update(const std::string &data) {
  update(data.data(), data.size());
}

std::vector<uint8_t> hasher::final_() {
  std::vector<uint8_t> out(state_.outlen);
  if (tinyblake_blake2b_final(&state_, out.data(), out.size()) != 0)
    throw std::runtime_error("Blake2b::final_ failed");
  return out;
}

void hasher::final_(void *out, size_t outlen) {
  if (tinyblake_blake2b_final(&state_, out, outlen) != 0)
    throw std::runtime_error("Blake2b::final_ failed");
}

void hasher::reset() {
  if (init_from_param(&state_, param_) != 0)
    throw std::runtime_error("Blake2b::reset failed");
  if (keyed_) {
    if (tinyblake_blake2b_update(&state_, key_block_, 128) != 0)
      throw std::runtime_error("Blake2b::reset key update failed");
  }
}

std::vector<uint8_t> hash(const void *data, size_t len, size_t outlen) {
  std::vector<uint8_t> out(outlen);
  if (tinyblake_blake2b(out.data(), outlen, data, len, nullptr, 0) != 0)
    throw std::runtime_error("tinyblake::blake2b::hash failed");
  return out;
}

std::vector<uint8_t> hash(const std::vector<uint8_t> &data, size_t outlen) {
  return hash(data.data(), data.size(), outlen);
}

std::vector<uint8_t> keyed_hash(const void *key, size_t keylen,
                                const void *data, size_t datalen,
                                size_t outlen) {
  std::vector<uint8_t> out(outlen);
  if (tinyblake_blake2b(out.data(), outlen, data, datalen, key, keylen) != 0)
    throw std::runtime_error("tinyblake::blake2b::keyed_hash failed");
  return out;
}

} /* namespace tinyblake::blake2b */