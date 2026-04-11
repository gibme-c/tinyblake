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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <tinyblake/hmac.h>
#include <vector>

/*
 * Fuzz target: HMAC state machine abuse.
 *
 * Modelled on fuzz_blake2b_misuse. Exercises init → update → final →
 * post-final misuse, re-init cycles, and arbitrary opcode sequences via
 * an interpreter. Records all operations between the most recent
 * successful init and a successful final, then replays the sequence and
 * verifies determinism.
 *
 * Opcodes (each consumes 1 opcode byte; operand layout documented below):
 *   0: INIT    — next byte is keylen (1..128), then keylen bytes of key.
 *   1: UPDATE  — next byte is chunk length N, then N data bytes.
 *   2: FINAL   — finalize into a local 64-byte buffer.
 *   3: REINIT  — same as INIT, reusing the state slot.
 */

enum Opcode : uint8_t
{
    OP_INIT = 0,
    OP_UPDATE = 1,
    OP_FINAL = 2,
    OP_REINIT = 3,
    OP_COUNT = 4,
};

struct RecordedOp
{
    Opcode op;
    std::vector<uint8_t> payload;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;

    tinyblake_hmac_state S;
    bool initialized = false;

    std::vector<RecordedOp> ops;

    size_t pos = 0;
    while (pos < size)
    {
        uint8_t opcode = data[pos++] % OP_COUNT;

        switch (opcode)
        {
            case OP_INIT:
            case OP_REINIT:
            {
                if (pos >= size)
                    goto done;
                size_t keylen = (data[pos++] % 128) + 1; /* 1..128 */
                if (pos + keylen > size)
                    goto done;
                std::vector<uint8_t> key(data + pos, data + pos + keylen);
                pos += keylen;
                int rc = tinyblake_hmac_init(&S, key.data(), keylen);
                if (rc == 0)
                {
                    initialized = true;
                    ops.clear();
                    ops.push_back({OP_INIT, key});
                }
                break;
            }

            case OP_UPDATE:
            {
                if (pos >= size)
                    goto done;
                size_t n = data[pos++];
                if (n > size - pos)
                    n = size - pos;
                std::vector<uint8_t> chunk(data + pos, data + pos + n);
                pos += n;
                int rc = tinyblake_hmac_update(&S, chunk.data(), n);
                if (rc == 0 && initialized)
                {
                    ops.push_back({OP_UPDATE, chunk});
                }
                /* rc != 0 on a zeroed/post-final state is acceptable — we only
                 * care that nothing crashes or corrupts memory. */
                break;
            }

            case OP_FINAL:
            {
                if (!initialized)
                    break;
                uint8_t out[64];
                int rc = tinyblake_hmac_final(&S, out, 64);
                if (rc == 0 && !ops.empty())
                {
                    /* Replay the recorded sequence into a fresh state and verify
                     * the output byte-for-byte. */
                    tinyblake_hmac_state S2;
                    bool replay_ok = true;
                    for (const auto &op : ops)
                    {
                        int rrc = -1;
                        switch (op.op)
                        {
                            case OP_INIT:
                                rrc = tinyblake_hmac_init(&S2, op.payload.data(), op.payload.size());
                                break;
                            case OP_UPDATE:
                                rrc = tinyblake_hmac_update(&S2, op.payload.data(), op.payload.size());
                                break;
                            default:
                                break;
                        }
                        if (rrc != 0)
                        {
                            replay_ok = false;
                            break;
                        }
                    }
                    if (replay_ok)
                    {
                        uint8_t out2[64];
                        int rc2 = tinyblake_hmac_final(&S2, out2, 64);
                        if (rc2 != 0)
                            __builtin_trap();
                        if (std::memcmp(out, out2, 64) != 0)
                            __builtin_trap();
                    }
                }
                /* After final, state is zeroed — further ops exercise post-final
                 * misuse. */
                initialized = false;
                ops.clear();
                break;
            }
        }
    }

done:
    return 0;
}
