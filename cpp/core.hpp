// core.hpp — Nullkey C++ crypto core (Phase 3). Mirrors the Python reference in
// ratchet.py / crypto.py, built on libsodium. Byte-for-byte compatible (verified
// by test_core_parity.py). Memory-safety is the whole point of doing this in C++:
// the frame parser is the untrusted-input surface, so it's fuzzed under sanitizers.
#pragma once
#include <string>
#include <utility>
#include <cstdint>

namespace nk {

// BLAKE2b(sorted(a,b)) -> "xxxxx-xxxxx-xxxxx-xxxxx" (matches crypto.safety_number)
std::string safety_number(const std::string& a, const std::string& b);

// HKDF-SHA256 (RFC 5869). salt must be 32 bytes (our usage always is).
std::string hkdf(const std::string& salt, const std::string& ikm,
                 const std::string& info, size_t length);

// chain KDF: ck(32) -> (next_ck, message_key)
std::pair<std::string, std::string> kdf_ck(const std::string& ck);

// message-key KDF: mk(32) -> (aead_key[32], nonce[24])
std::pair<std::string, std::string> msg_keys(const std::string& mk);

// the untrusted parser: 40-byte header -> (ratchet_pub[32], PN, N). Throws if short.
struct Header { std::string dh_pub; uint32_t pn; uint32_t n; };
Header parse_header(const std::string& data);

// XChaCha20-Poly1305 AEAD (interoperable with PyNaCl's bindings)
std::string aead_encrypt(const std::string& key, const std::string& nonce,
                         const std::string& pt, const std::string& ad);
std::string aead_decrypt(const std::string& key, const std::string& nonce,
                         const std::string& ct, const std::string& ad);  // throws on fail

}  // namespace nk
