// asan_test.cpp — standalone sanitizer test of the parser (works with Apple clang).
// Feeds many random buffers to parse_header under AddressSanitizer + UBSan.
//
// Build/run:
//   SODIUM=$(brew --prefix libsodium)
//   clang++ -std=c++17 -g -fsanitize=address,undefined \
//       -I cpp -I "$SODIUM/include" cpp/core.cpp cpp/asan_test.cpp \
//       -L "$SODIUM/lib" -lsodium -o build/asan_test
//   ./build/asan_test
#include "core.hpp"
#include <cstdio>
#include <random>
#include <string>

int main() {
    std::mt19937 rng(1234567);
    const int N = 300000;
    for (int i = 0; i < N; ++i) {
        size_t len = rng() % 300;               // 0..299 bytes, incl. the 40-byte boundary
        std::string data(len, '\0');
        for (size_t j = 0; j < len; ++j) data[j] = static_cast<char>(rng() & 0xff);
        try {
            nk::parse_header(data);
        } catch (...) {
        }
    }
    std::printf("asan_test: parsed %d random buffers, no memory/UB errors\n", N);
    return 0;
}
