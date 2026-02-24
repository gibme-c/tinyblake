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

#include <tinyblake/blake2b.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

/*
 * Fuzz target: state machine abuse.
 * Exercises init → update → final → update (should not crash), re-init
 * cycles, double-final, and other misuse patterns via an opcode interpreter.
 *
 * Opcodes (consume 1 byte unless noted):
 *   0: INIT         — init with outlen from next byte (1..64)
 *   1: INIT_KEY     — init_key with outlen + keylen + key bytes
 *   2: INIT_PARAM   — init_param with next 64 bytes as param block
 *   3: UPDATE       — update with next N bytes (N from next byte)
 *   4: FINAL        — finalize with outlen from state
 *   5: REINIT       — re-init (same as INIT, reusing the state)
 *
 * The fuzzer records all operations that succeed between the most recent
 * successful init and a successful final. It then replays the sequence
 * and verifies determinism.
 */

enum Opcode : uint8_t {
  OP_INIT = 0,
  OP_INIT_KEY = 1,
  OP_INIT_PARAM = 2,
  OP_UPDATE = 3,
  OP_FINAL = 4,
  OP_REINIT = 5,
  OP_COUNT = 6,
};

struct RecordedOp {
  Opcode op;
  std::vector<uint8_t> payload;
  size_t outlen;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return 0;

  tinyblake_blake2b_state S;
  bool initialized = false;
  size_t current_outlen = 0;

  std::vector<RecordedOp> ops;
  uint8_t last_hash[64];
  bool have_hash = false;

  size_t pos = 0;
  while (pos < size) {
    uint8_t opcode = data[pos++] % OP_COUNT;

    switch (opcode) {
    case OP_INIT: {
      if (pos >= size)
        goto done;
      size_t outlen = (data[pos++] % 64) + 1;
      int rc = tinyblake_blake2b_init(&S, outlen);
      if (rc == 0) {
        initialized = true;
        current_outlen = outlen;
        ops.clear();
        ops.push_back({OP_INIT, {}, outlen});
      }
      break;
    }

    case OP_INIT_KEY: {
      if (pos + 2 > size)
        goto done;
      size_t outlen = (data[pos] % 64) + 1;
      size_t keylen = (data[pos + 1] % 64) + 1;
      pos += 2;
      if (pos + keylen > size)
        goto done;
      std::vector<uint8_t> key(data + pos, data + pos + keylen);
      pos += keylen;
      int rc = tinyblake_blake2b_init_key(&S, outlen, key.data(), keylen);
      if (rc == 0) {
        initialized = true;
        current_outlen = outlen;
        ops.clear();
        ops.push_back({OP_INIT_KEY, key, outlen});
      }
      break;
    }

    case OP_INIT_PARAM: {
      if (pos + 64 > size)
        goto done;
      std::vector<uint8_t> param(data + pos, data + pos + 64);
      pos += 64;
      int rc = tinyblake_blake2b_init_param(&S, param.data());
      if (rc == 0) {
        initialized = true;
        current_outlen = param[0];
        ops.clear();
        ops.push_back({OP_INIT_PARAM, param, current_outlen});
      }
      break;
    }

    case OP_UPDATE: {
      if (pos >= size)
        goto done;
      size_t n = data[pos++];
      if (n > size - pos)
        n = size - pos;
      std::vector<uint8_t> chunk(data + pos, data + pos + n);
      pos += n;
      int rc = tinyblake_blake2b_update(&S, chunk.data(), n);
      if (rc == 0 && initialized) {
        ops.push_back({OP_UPDATE, chunk, 0});
      }
      /* rc != 0 is acceptable (e.g., update on uninitialized/zeroed state) */
      break;
    }

    case OP_FINAL: {
      if (!initialized || current_outlen == 0)
        break;
      uint8_t out[64];
      int rc = tinyblake_blake2b_final(&S, out, current_outlen);
      if (rc == 0 && ops.size() > 0) {
        /* Replay the same sequence and verify determinism */
        tinyblake_blake2b_state S2;
        bool replay_ok = true;

        for (const auto &op : ops) {
          int rrc = -1;
          switch (op.op) {
          case OP_INIT:
            rrc = tinyblake_blake2b_init(&S2, op.outlen);
            break;
          case OP_INIT_KEY:
            rrc = tinyblake_blake2b_init_key(&S2, op.outlen, op.payload.data(),
                                             op.payload.size());
            break;
          case OP_INIT_PARAM:
            rrc = tinyblake_blake2b_init_param(&S2, op.payload.data());
            break;
          case OP_UPDATE:
            rrc = tinyblake_blake2b_update(&S2, op.payload.data(),
                                           op.payload.size());
            break;
          default:
            break;
          }
          if (rrc != 0) {
            replay_ok = false;
            break;
          }
        }

        if (replay_ok) {
          uint8_t out2[64];
          int rc2 = tinyblake_blake2b_final(&S2, out2, current_outlen);
          if (rc2 != 0)
            __builtin_trap();
          if (std::memcmp(out, out2, current_outlen) != 0)
            __builtin_trap();
        }

        std::memcpy(last_hash, out, current_outlen);
        have_hash = true;
      }
      /* State is now zeroed by final — further ops exercise post-final misuse
       */
      initialized = false;
      ops.clear();
      break;
    }

    case OP_REINIT: {
      if (pos >= size)
        goto done;
      size_t outlen = (data[pos++] % 64) + 1;
      int rc = tinyblake_blake2b_init(&S, outlen);
      if (rc == 0) {
        initialized = true;
        current_outlen = outlen;
        ops.clear();
        ops.push_back({OP_INIT, {}, outlen});
      }
      break;
    }
    }
  }

done:
  (void)have_hash;
  (void)last_hash;
  return 0;
}
