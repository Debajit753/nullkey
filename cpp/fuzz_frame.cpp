// fuzz_frame.cpp — libFuzzer target for the untrusted header parser.
// The parser must survive ANY bytes: no crash, no memory error.
//
// Needs LLVM clang (Apple clang lacks libFuzzer). Build:
//   LLVM=$(brew --prefix llvm); SODIUM=$(brew --prefix libsodium)
//   "$LLVM/bin/clang++" -std=c++17 -O1 -g -fsanitize=fuzzer,address,undefined \
//       -I cpp -I "$SODIUM/include" cpp/core.cpp cpp/fuzz_frame.cpp \
//       -L "$SODIUM/lib" -lsodium -o build/fuzz_frame
//   ./build/fuzz_frame -runs=1000000
#include "core.hpp"
#include <string>
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string s(reinterpret_cast<const char*>(data), size);
    try {
        nk::parse_header(s);
    } catch (...) {
        // raising on bad input is correct; crashing/OOB is what we're hunting for.
    }
    return 0;
}
