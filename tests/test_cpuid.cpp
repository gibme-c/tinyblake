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

#include "../src/cpu_features.h"
#include "test_harness.h"

TEST(cpuid_detect_no_crash) {
  /* Just verify detect() doesn't crash and returns consistent results */
  const auto &f1 = tinyblake::cpu::detect();
  const auto &f2 = tinyblake::cpu::detect();

  ASSERT_EQ(f1.avx2, f2.avx2);
  ASSERT_EQ(f1.avx512f, f2.avx512f);
  ASSERT_EQ(f1.neon, f2.neon);
}

TEST(cpuid_feature_consistency) {
  const auto &f = tinyblake::cpu::detect();

  /* If AVX-512F is supported, AVX2 must also be supported */
  if (f.avx512f) {
    ASSERT_TRUE(f.avx2);
  }

  /* On x86, NEON should be false */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||             \
    defined(_M_IX86)
  ASSERT_TRUE(!f.neon);
#endif

  /* On AArch64, NEON should be true */
#if defined(__aarch64__) || defined(_M_ARM64)
  ASSERT_TRUE(f.neon);
#endif
}

TEST(cpuid_cached) {
  /* detect() returns references to the same static object */
  const auto *p1 = &tinyblake::cpu::detect();
  const auto *p2 = &tinyblake::cpu::detect();
  ASSERT_EQ(p1, p2);
}