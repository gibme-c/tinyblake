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

#include "tinyblake/pbkdf2.h"
#include "tinyblake/hmac.h"

#include <climits>
#include <cstring>
#include <stdexcept>

/*
 * PBKDF2-HMAC-BLAKE2b-512 per RFC 2898 / RFC 8018.
 *
 * DK = T1 || T2 || ... || Tdklen/hlen
 * Ti = F(Password, Salt, c, i)
 * F(P, S, c, i) = U1 ^ U2 ^ ... ^ Uc
 * U1 = PRF(P, S || INT_32_BE(i))
 * Uj = PRF(P, U_{j-1})
 */

static const size_t HLEN = 64; /* HMAC-BLAKE2b-512 output */

static void store_be32(uint8_t dst[4], uint32_t v) {
  dst[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
  dst[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
  dst[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
  dst[3] = static_cast<uint8_t>((v)&0xFF);
}

extern "C" int tinyblake_pbkdf2(void *out, size_t outlen, const void *password,
                                size_t passlen, const void *salt,
                                size_t saltlen, uint32_t rounds) {
  if (!out || outlen == 0)
    return -1;
  if (rounds == 0)
    return -1;
  if (outlen > uint64_t{UINT32_MAX} * HLEN)
    return -1;

  uint8_t *dk = static_cast<uint8_t *>(out);
  size_t dk_remaining = outlen;
  uint32_t block_idx = 1;

  while (dk_remaining > 0) {
    size_t cplen = dk_remaining < HLEN ? dk_remaining : HLEN;
    uint8_t u[64];
    uint8_t t[64];
    int rc;

    /* U1 = HMAC(password, salt || INT_32_BE(block_idx)) */
    tinyblake_hmac_state hmac;
    rc = tinyblake_hmac_init(&hmac, password, passlen);
    if (rc != 0)
      return -1;
    rc = tinyblake_hmac_update(&hmac, salt, saltlen);
    if (rc != 0)
      return -1;

    uint8_t be_idx[4];
    store_be32(be_idx, block_idx);
    rc = tinyblake_hmac_update(&hmac, be_idx, 4);
    if (rc != 0)
      return -1;

    rc = tinyblake_hmac_final(&hmac, u, 64);
    if (rc != 0) {
      tinyblake_secure_zero(u, 64);
      return -1;
    }

    /* T = U1 */
    std::memcpy(t, u, 64);

    /* U2 .. Uc */
    for (uint32_t j = 1; j < rounds; ++j) {
      tinyblake_hmac_state hmac_j;
      rc = tinyblake_hmac_init(&hmac_j, password, passlen);
      if (rc != 0) {
        tinyblake_secure_zero(u, 64);
        tinyblake_secure_zero(t, 64);
        return -1;
      }
      rc = tinyblake_hmac_update(&hmac_j, u, 64);
      if (rc != 0) {
        tinyblake_secure_zero(u, 64);
        tinyblake_secure_zero(t, 64);
        return -1;
      }
      rc = tinyblake_hmac_final(&hmac_j, u, 64);
      if (rc != 0) {
        tinyblake_secure_zero(u, 64);
        tinyblake_secure_zero(t, 64);
        return -1;
      }

      for (size_t k = 0; k < 64; ++k) {
        t[k] ^= u[k];
      }
    }

    std::memcpy(dk, t, cplen);
    dk += cplen;
    dk_remaining -= cplen;
    block_idx++;

    tinyblake_secure_zero(u, 64);
    tinyblake_secure_zero(t, 64);
  }

  return 0;
}

/* ─── C++ wrapper ─── */

namespace tinyblake::pbkdf2 {

std::vector<uint8_t> derive(const void *password, size_t passlen,
                            const void *salt, size_t saltlen, uint32_t rounds,
                            size_t outlen) {
  std::vector<uint8_t> out(outlen);
  if (tinyblake_pbkdf2(out.data(), outlen, password, passlen, salt, saltlen,
                       rounds) != 0)
    throw std::runtime_error("tinyblake::pbkdf2::derive failed");
  return out;
}

std::vector<uint8_t> derive(const std::string &password,
                            const std::vector<uint8_t> &salt, uint32_t rounds,
                            size_t outlen) {
  return derive(password.data(), password.size(), salt.data(), salt.size(),
                rounds, outlen);
}

} /* namespace tinyblake::pbkdf2 */