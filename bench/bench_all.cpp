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

#include <tinyblake.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

static double measure_throughput(const char *label,
                                 void (*fn)(const uint8_t *, size_t, size_t),
                                 size_t block_size, size_t iterations) {
  std::vector<uint8_t> data(block_size, 0xAB);

  auto start = std::chrono::high_resolution_clock::now();
  fn(data.data(), data.size(), iterations);
  auto end = std::chrono::high_resolution_clock::now();

  double secs = std::chrono::duration<double>(end - start).count();
  double total_bytes = static_cast<double>(block_size) * iterations;
  double mib_per_sec = (total_bytes / (1024.0 * 1024.0)) / secs;

  std::printf("%-30s %8zu bytes x %6zu iters = %8.2f MiB/s  (%.4f s)\n", label,
              block_size, iterations, mib_per_sec, secs);
  return mib_per_sec;
}

static void bench_blake2b_512(const uint8_t *data, size_t len, size_t iters) {
  uint8_t out[64];
  for (size_t i = 0; i < iters; ++i) {
    tinyblake_blake2b(out, 64, data, len, nullptr, 0);
  }
}

static void bench_blake2b_256(const uint8_t *data, size_t len, size_t iters) {
  uint8_t out[32];
  for (size_t i = 0; i < iters; ++i) {
    tinyblake_blake2b(out, 32, data, len, nullptr, 0);
  }
}

static void bench_blake2b_keyed(const uint8_t *data, size_t len, size_t iters) {
  uint8_t key[32];
  std::memset(key, 0x42, 32);
  uint8_t out[64];
  for (size_t i = 0; i < iters; ++i) {
    tinyblake_blake2b(out, 64, data, len, key, 32);
  }
}

static void bench_hmac(const uint8_t *data, size_t len, size_t iters) {
  uint8_t key[32];
  std::memset(key, 0x42, 32);
  uint8_t out[64];
  for (size_t i = 0; i < iters; ++i) {
    tinyblake_hmac(out, 64, key, 32, data, len);
  }
}

static void measure_pbkdf2(const char *label, uint32_t rounds,
                           size_t iterations) {
  uint8_t out[64];

  auto start = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < iterations; ++i) {
    tinyblake_pbkdf2(out, 64, "password", 8, "salt", 4, rounds);
  }
  auto end = std::chrono::high_resolution_clock::now();

  double secs = std::chrono::duration<double>(end - start).count();
  double calls_per_sec = iterations / secs;

  std::printf("%-30s %6zu calls  c=%-6u  %10.1f calls/s  (%.4f s)\n", label,
              iterations, rounds, calls_per_sec, secs);
}

int main() {
  std::printf("=== TinyBLAKE Benchmarks ===\n\n");

  /* BLAKE2b-512 */
  std::printf("--- BLAKE2b-512 (unkeyed) ---\n");
  measure_throughput("BLAKE2b-512  64B", bench_blake2b_512, 64, 100000);
  measure_throughput("BLAKE2b-512  256B", bench_blake2b_512, 256, 100000);
  measure_throughput("BLAKE2b-512  1KiB", bench_blake2b_512, 1024, 50000);
  measure_throughput("BLAKE2b-512  4KiB", bench_blake2b_512, 4096, 20000);
  measure_throughput("BLAKE2b-512  64KiB", bench_blake2b_512, 65536, 2000);
  measure_throughput("BLAKE2b-512  1MiB", bench_blake2b_512, 1048576, 100);

  std::printf("\n--- BLAKE2b-256 (unkeyed) ---\n");
  measure_throughput("BLAKE2b-256  1KiB", bench_blake2b_256, 1024, 50000);
  measure_throughput("BLAKE2b-256  64KiB", bench_blake2b_256, 65536, 2000);

  std::printf("\n--- BLAKE2b-512 (keyed, 32B key) ---\n");
  measure_throughput("BLAKE2b-keyed  1KiB", bench_blake2b_keyed, 1024, 50000);
  measure_throughput("BLAKE2b-keyed  64KiB", bench_blake2b_keyed, 65536, 2000);

  std::printf("\n--- HMAC-BLAKE2b-512 ---\n");
  measure_throughput("HMAC  64B", bench_hmac, 64, 50000);
  measure_throughput("HMAC  1KiB", bench_hmac, 1024, 20000);
  measure_throughput("HMAC  64KiB", bench_hmac, 65536, 1000);

  std::printf("\n--- PBKDF2-HMAC-BLAKE2b-512 ---\n");
  measure_pbkdf2("PBKDF2 c=1", 1, 50000);
  measure_pbkdf2("PBKDF2 c=1000", 1000, 50);

  std::printf("\nDone.\n");
  return 0;
}