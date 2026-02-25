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

#include "tinyblake/hmac.h"

#include <cstring>
#include <stdexcept>

/*
 * HMAC-BLAKE2b-512
 *
 * Block size B = 128 (BLAKE2b block size)
 * Output size L = 64  (BLAKE2b-512)
 *
 * If key > B, key = BLAKE2b-512(key)
 * ipad = key XOR 0x36 (repeated to B bytes)
 * opad = key XOR 0x5c (repeated to B bytes)
 * HMAC = BLAKE2b-512(opad || BLAKE2b-512(ipad || message))
 */

static const size_t HMAC_BLOCK = 128;

static int derive_pads(const void *key, size_t keylen, uint8_t ipad[128],
                       uint8_t opad[128]) {
  uint8_t keybuf[128];
  std::memset(keybuf, 0, 128);

  if (keylen > HMAC_BLOCK) {
    /* Hash key down to 64 bytes */
    if (tinyblake_blake2b(keybuf, 64, key, keylen, nullptr, 0) != 0) {
      tinyblake_secure_zero(keybuf, 128);
      return -1;
    }
  } else if (keylen > 0) {
    std::memcpy(keybuf, key, keylen);
  }

  for (size_t i = 0; i < HMAC_BLOCK; ++i) {
    ipad[i] = keybuf[i] ^ 0x36;
    opad[i] = keybuf[i] ^ 0x5C;
  }

  tinyblake_secure_zero(keybuf, 128);
  return 0;
}

extern "C" {

int tinyblake_hmac_init(tinyblake_hmac_state *state, const void *key,
                        size_t keylen) {
  if (!state)
    return -1;
  if (!key || keylen == 0)
    return -1;

  uint8_t ipad[128], opad[128];
  if (derive_pads(key, keylen, ipad, opad) != 0) {
    tinyblake_secure_zero(ipad, 128);
    tinyblake_secure_zero(opad, 128);
    return -1;
  }

  /* Inner hash: init then update with ipad */
  if (tinyblake_blake2b_init(&state->inner, 64) != 0 ||
      tinyblake_blake2b_update(&state->inner, ipad, 128) != 0) {
    tinyblake_secure_zero(ipad, 128);
    tinyblake_secure_zero(opad, 128);
    tinyblake_secure_zero(state, sizeof(*state));
    return -1;
  }

  /* Outer hash: init then update with opad (will finish in final) */
  if (tinyblake_blake2b_init(&state->outer, 64) != 0 ||
      tinyblake_blake2b_update(&state->outer, opad, 128) != 0) {
    tinyblake_secure_zero(ipad, 128);
    tinyblake_secure_zero(opad, 128);
    tinyblake_secure_zero(state, sizeof(*state));
    return -1;
  }

  tinyblake_secure_zero(ipad, 128);
  tinyblake_secure_zero(opad, 128);
  return 0;
}

int tinyblake_hmac_update(tinyblake_hmac_state *state, const void *in,
                          size_t inlen) {
  if (!state)
    return -1;
  return tinyblake_blake2b_update(&state->inner, in, inlen);
}

int tinyblake_hmac_final(tinyblake_hmac_state *state, void *out,
                         size_t outlen) {
  if (!state || !out || outlen < 64)
    return -1;

  /* Finalize inner: inner_hash = BLAKE2b-512(ipad || message) */
  uint8_t inner_hash[64];
  if (tinyblake_blake2b_final(&state->inner, inner_hash, 64) != 0) {
    tinyblake_secure_zero(inner_hash, 64);
    tinyblake_secure_zero(state, sizeof(*state));
    return -1;
  }

  /* Finalize outer: BLAKE2b-512(opad || inner_hash) */
  if (tinyblake_blake2b_update(&state->outer, inner_hash, 64) != 0) {
    tinyblake_secure_zero(inner_hash, 64);
    tinyblake_secure_zero(state, sizeof(*state));
    return -1;
  }
  int rc = tinyblake_blake2b_final(&state->outer, out, outlen);

  tinyblake_secure_zero(inner_hash, 64);
  tinyblake_secure_zero(state, sizeof(*state));
  return rc;
}

int tinyblake_hmac(void *out, size_t outlen, const void *key, size_t keylen,
                   const void *in, size_t inlen) {
  tinyblake_hmac_state state;
  int rc = tinyblake_hmac_init(&state, key, keylen);
  if (rc != 0)
    return rc;
  rc = tinyblake_hmac_update(&state, in, inlen);
  if (rc != 0)
    return rc;
  return tinyblake_hmac_final(&state, out, outlen);
}

} /* extern "C" */

/* ─── C++ wrapper ─── */

namespace tinyblake::hmac {

hasher::hasher(const void *key, size_t keylen) {
  if (!key || keylen == 0)
    throw std::invalid_argument("Hmac: key must be non-null with keylen > 0");
  std::memset(key_pad_, 0, 128);
  if (keylen > 128) {
    tinyblake_blake2b(key_pad_, 64, key, keylen, nullptr, 0);
  } else {
    std::memcpy(key_pad_, key, keylen);
  }
  if (tinyblake_hmac_init(&state_, key, keylen) != 0)
    throw std::runtime_error("Hmac: init failed");
}

hasher::hasher(const std::vector<uint8_t> &key)
    : hasher(key.data(), key.size()) {}

hasher::~hasher() {
  tinyblake_secure_zero(&state_, sizeof(state_));
  tinyblake_secure_zero(key_pad_, 128);
}

hasher::hasher(hasher &&o) noexcept : state_(o.state_) {
  std::memcpy(key_pad_, o.key_pad_, 128);
  tinyblake_secure_zero(&o.state_, sizeof(o.state_));
  tinyblake_secure_zero(o.key_pad_, 128);
}

hasher &hasher::operator=(hasher &&o) noexcept {
  if (this != &o) {
    tinyblake_secure_zero(&state_, sizeof(state_));
    tinyblake_secure_zero(key_pad_, 128);
    state_ = o.state_;
    std::memcpy(key_pad_, o.key_pad_, 128);
    tinyblake_secure_zero(&o.state_, sizeof(o.state_));
    tinyblake_secure_zero(o.key_pad_, 128);
  }
  return *this;
}

void hasher::update(const void *data, size_t len) {
  if (tinyblake_hmac_update(&state_, data, len) != 0)
    throw std::runtime_error("Hmac::update failed");
}

void hasher::update(const std::vector<uint8_t> &data) {
  update(data.data(), data.size());
}

void hasher::update(const std::string &data) {
  update(data.data(), data.size());
}

std::vector<uint8_t> hasher::final_() {
  std::vector<uint8_t> out(64);
  if (tinyblake_hmac_final(&state_, out.data(), 64) != 0)
    throw std::runtime_error("Hmac::final_ failed");
  return out;
}

void hasher::final_(void *out, size_t outlen) {
  if (tinyblake_hmac_final(&state_, out, outlen) != 0)
    throw std::runtime_error("Hmac::final_ failed");
}

void hasher::reset() {
  if (tinyblake_hmac_init(&state_, key_pad_, 128) != 0)
    throw std::runtime_error("Hmac::reset failed");
}

std::vector<uint8_t> mac(const void *key, size_t keylen, const void *data,
                         size_t datalen) {
  std::vector<uint8_t> out(64);
  if (tinyblake_hmac(out.data(), 64, key, keylen, data, datalen) != 0)
    throw std::runtime_error("tinyblake::hmac::mac failed");
  return out;
}

} /* namespace tinyblake::hmac */