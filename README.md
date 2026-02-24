# TinyBLAKE

A zero-dependency C++17 library for BLAKE2b cryptographic hashing, with SIMD-accelerated backends and runtime CPU dispatch.

TinyBLAKE implements BLAKE2b (RFC 7693), HMAC-BLAKE2b-512, and PBKDF2-HMAC-BLAKE2b-512. The core algorithm has a portable backend that compiles everywhere plus platform-specific backends (AVX2, AVX-512, NEON) that are selected automatically at runtime based on detected CPU features. All intermediate key material is securely zeroed using platform-specific mechanisms the compiler can't optimize away.

Both a C++ namespace API and a plain C API (`extern "C"`) are provided. The C++ API returns `std::vector<uint8_t>` and uses sub-namespaces (`tinyblake::blake2b`, `tinyblake::hmac`, `tinyblake::pbkdf2`). The C API uses caller-provided buffers and returns `int` (0 on success, -1 on error) with full input validation.

## Features

### Hash Function

| Algorithm | Digest Size | Block Size | Standard |
|-----------|-------------|------------|----------|
| BLAKE2b | 1..64 bytes (configurable) | 128 bytes | RFC 7693 |

BLAKE2b natively supports variable-length output without truncation — the output length is part of the parameter block and affects the hash. It also supports keyed hashing, salt, and personalization via the 64-byte parameter block.

### HMAC and PBKDF2

HMAC-BLAKE2b-512 follows RFC 2104 with a 128-byte block size and 64-byte output. PBKDF2-HMAC-BLAKE2b-512 follows RFC 2898 / RFC 8018 with 64-byte PRF output. Both the C and C++ APIs expose incremental (init/update/final) and one-shot interfaces.

### SIMD Backends

Backend availability by platform:

| Algorithm | Portable | x64 | AVX2 | AVX-512 | NEON |
|-----------|----------|-----|------|---------|------|
| BLAKE2b | yes | yes | yes | yes | yes |

HMAC and PBKDF2 use BLAKE2b internally and benefit from the same SIMD acceleration.

### Security

- **Secure memory erasure** — all intermediate state (hash state, HMAC keys, PBKDF2 intermediates) is zeroed via `tinyblake_secure_zero()`, which uses `SecureZeroMemory` (Windows), `memset_s` (C11), `explicit_bzero` (glibc), or a volatile function pointer to prevent dead-store elimination
- **Constant-time comparison** — `tinyblake_constant_time_eq()` for digest verification, with volatile accumulator to prevent short-circuit optimization
- **Input validation** — all C API functions validate pointers, lengths, and bounds before any computation; NULL inputs with non-zero length return -1
- **HMAC defense in depth** — all inner blake2b return codes are checked; state and pads are zeroed on any failure path
- **Build hardening** — stack protectors, control flow integrity (CET), ASLR, DEP, RELRO, Spectre mitigations, and symbol visibility hiding across GCC, Clang, MSVC, and MinGW

## Building

Requires CMake 3.10+ and a C++17 compiler.

```bash
# Configure and build
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build --config Release -j

# Run tests
./build/tinyblake_tests          # Linux / macOS / MinGW
./build/Release/tinyblake_tests  # Windows (MSVC)
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | `OFF` | Build the unit test executable (`tinyblake_tests`) |
| `BUILD_BENCH` | `OFF` | Build the benchmark tool (`tinyblake_bench`) |
| `BUILD_FUZZ` | `OFF` | Build fuzz targets (Clang only) |
| `BUILD_SHARED_LIBS` | `OFF` | Build as a shared library (`.so`/`.dll`/`.dylib`) |
| `FORCE_PORTABLE` | `OFF` | Disable all SIMD backends; use only portable C++ code |
| `CMAKE_BUILD_TYPE` | `Release` | `Debug`, `Release`, or `RelWithDebInfo` |

## Usage

Include individual headers:

```cpp
#include <tinyblake/blake2b.h>
#include <tinyblake/hmac.h>
#include <tinyblake/pbkdf2.h>
```

Link against the `tinyblake` library target in your CMake project:

```cmake
add_subdirectory(tinyblake)
target_link_libraries(your_target tinyblake)
```

### C++ API

```cpp
#include <tinyblake/blake2b.h>
#include <tinyblake/hmac.h>
#include <tinyblake/pbkdf2.h>

// One-shot hash
auto digest = tinyblake::blake2b::hash("data", 4);
auto short_digest = tinyblake::blake2b::hash("data", 4, 32);  // 32-byte output

// Keyed hash
auto keyed = tinyblake::blake2b::keyed_hash(key, keylen, data, datalen);

// Incremental hash
tinyblake::blake2b::hasher h(64);
h.update("hello ", 6);
h.update("world", 5);
auto result = h.final_();
h.reset();  // reuse with same parameters

// HMAC
auto mac = tinyblake::hmac::mac(key, keylen, data, datalen);

// Incremental HMAC
tinyblake::hmac::hasher hm(key, keylen);
hm.update("message", 7);
auto tag = hm.final_();

// PBKDF2
auto derived = tinyblake::pbkdf2::derive("password", 8, salt, saltlen, 100000, 32);

// Constant-time digest comparison
bool match = tinyblake::constant_time_eq(digest_a, digest_b, 64);
```

### C API

All C functions return 0 on success, -1 on error (NULL pointers, invalid lengths, etc.).

```c
#include <tinyblake/blake2b.h>
#include <tinyblake/hmac.h>
#include <tinyblake/pbkdf2.h>

/* One-shot hash */
uint8_t digest[64];
tinyblake_blake2b(digest, 64, data, data_len, NULL, 0);

/* Keyed hash */
uint8_t keyed[64];
tinyblake_blake2b(keyed, 64, data, data_len, key, key_len);

/* Incremental hash */
tinyblake_blake2b_state state;
tinyblake_blake2b_init(&state, 64);
tinyblake_blake2b_update(&state, data, data_len);
tinyblake_blake2b_final(&state, digest, 64);

/* HMAC */
uint8_t mac[64];
tinyblake_hmac(mac, 64, key, key_len, data, data_len);

/* PBKDF2 */
uint8_t derived[32];
tinyblake_pbkdf2(derived, 32, pw, pw_len, salt, salt_len, 100000);

/* Constant-time comparison */
int equal = tinyblake_constant_time_eq(digest_a, digest_b, 64);
```

## Architecture

### Dispatch

BLAKE2b uses `std::atomic<fn_ptr>` with acquire/release ordering for lazy runtime dispatch. On the first call, CPUID (x86) or feature detection (ARM) selects the best available compression function. The function pointer is stored atomically — no mutexes, no `std::call_once`. Redundant resolution under contention is harmless by design.

Dispatch priority on x86_64:

- **BLAKE2b**: AVX-512F+VL+VBMI2 > AVX2 > x64 baseline

Dispatch priority on ARM64:

- **BLAKE2b**: NEON > portable

All other platforms use the portable backend unconditionally.

### BLAKE2b Internals

BLAKE2b uses 64-bit state with 12-round compression over 128-byte blocks. The state consists of eight 64-bit chaining values initialized from the IV XORed with a 64-byte parameter block. The parameter block encodes digest length, key length, fanout, depth, salt, and personalization.

Little-endian byte order throughout: message words and state loaded/stored as little-endian `uint64_t`.

Backend implementations:

- **Portable** — reference C++ with standard bitwise rotations
- **x64** — unrolled rounds with compiler-friendly register usage
- **AVX2** — 256-bit vectorized G-function with `VPSHUFB` rotations and diagonal shuffles
- **AVX-512** — `VPRORQ` for constant-time 64-bit rotations, 512-bit vectorized message loading
- **NEON** — ARM NEON intrinsics for vectorized G-function with `VSRI`/`VSHL` rotations

### HMAC / PBKDF2

HMAC follows RFC 2104: derive a block-sized key (hash if > 128 bytes), XOR with `ipad` (0x36) and `opad` (0x5C), hash inner then outer. PBKDF2 follows RFC 2898: iterative HMAC with big-endian counter blocks, XOR accumulation across iterations.

All intermediate buffers — key blocks, ipad, opad, HMAC intermediates, PBKDF2 U-values — are securely zeroed after use. All inner BLAKE2b return codes are checked with state cleanup on failure.

## Testing

Build with `-DBUILD_TESTS=ON` to get the `tinyblake_tests` executable. The test suite covers:

- **Known-answer tests** — RFC 7693 test vectors for BLAKE2b (empty string, "abc")
- **Keyed hash vectors** — official BLAKE2b keyed KAT vectors across multiple input lengths
- **HMAC test vectors** — HMAC-BLAKE2b-512 vectors including long-key (>128 byte) cases
- **PBKDF2 tests** — PBKDF2-HMAC-BLAKE2b-512 derivation
- **Parameter block tests** — custom salt, personalization, and parameter block round-trip
- **Truncation tests** — variable output lengths 1..64, uniqueness verification
- **Move semantics tests** — move construction/assignment for both hasher and HMAC, moved-from state validation
- **Error path tests** — NULL pointers, invalid lengths, double-finalize, HMAC/PBKDF2 null key rejection
- **CPUID tests** — CPU feature detection runs without crashing

The test harness is a custom header-only framework (`test_harness.h`) with `TEST`/`ASSERT_EQ` macros — no external test dependencies.

## Fuzzing

Seven fuzz targets are provided:

```bash
cmake -S . -B build-fuzz -DBUILD_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz
./build-fuzz/fuzz_blake2b corpus/blake2b/
```

Fuzz targets cover BLAKE2b (unkeyed, keyed, parameter block), HMAC, PBKDF2, cross-backend consistency, and API misuse. Each links with `-fsanitize=fuzzer,address`.

## License

BSD-3-Clause. See [LICENSE](LICENSE) for the full text.
