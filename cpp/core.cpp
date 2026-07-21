// core.cpp — see core.hpp. Built on libsodium; mirrors ratchet.py / crypto.py.
#include "core.hpp"
#include <sodium.h>
#include <stdexcept>
#include <algorithm>

namespace {
// initialise libsodium exactly once
const int kSodiumInit = sodium_init();  // 0 = ok, 1 = already, -1 = fail

void require(bool cond, const char* msg) {
    if (!cond) throw std::invalid_argument(msg);
}

std::string hmac_sha256(const std::string& key32, const std::string& msg) {
    require(key32.size() == crypto_auth_hmacsha256_KEYBYTES, "hmac key must be 32 bytes");
    unsigned char out[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256(out,
                           reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                           reinterpret_cast<const unsigned char*>(key32.data()));
    return std::string(reinterpret_cast<char*>(out), sizeof out);
}
}  // namespace

namespace nk {

std::string safety_number(const std::string& a, const std::string& b) {
    const std::string& lo = (a <= b) ? a : b;
    const std::string& hi = (a <= b) ? b : a;
    std::string in = lo + hi;
    unsigned char digest[10];
    crypto_generichash(digest, sizeof digest,
                       reinterpret_cast<const unsigned char*>(in.data()), in.size(),
                       nullptr, 0);
    char hex[sizeof(digest) * 2 + 1];
    sodium_bin2hex(hex, sizeof hex, digest, sizeof digest);
    std::string h(hex);  // 20 hex chars
    std::string out;
    for (size_t i = 0; i < h.size(); i += 5) {
        if (i) out += '-';
        out += h.substr(i, 5);
    }
    return out;
}

std::string hkdf(const std::string& salt, const std::string& ikm,
                 const std::string& info, size_t length) {
    std::string s = salt.empty() ? std::string(32, '\0') : salt;
    require(s.size() == 32, "hkdf salt must be 32 bytes");
    std::string prk = hmac_sha256(s, ikm);          // extract
    std::string okm, t;                              // expand
    unsigned char counter = 1;
    while (okm.size() < length) {
        std::string blk = t + info + std::string(1, static_cast<char>(counter));
        t = hmac_sha256(prk, blk);
        okm += t;
        counter++;
    }
    return okm.substr(0, length);
}

std::pair<std::string, std::string> kdf_ck(const std::string& ck) {
    require(ck.size() == 32, "chain key must be 32 bytes");
    std::string mk = hmac_sha256(ck, std::string(1, '\x01'));
    std::string next = hmac_sha256(ck, std::string(1, '\x02'));
    return {next, mk};
}

std::pair<std::string, std::string> msg_keys(const std::string& mk) {
    std::string okm = hkdf(std::string(32, '\0'), mk, "NullkeyMsgKeys", 32 + 24);
    return {okm.substr(0, 32), okm.substr(32, 24)};
}

Header parse_header(const std::string& data) {
    if (data.size() < 40) throw std::runtime_error("header too short");
    Header h;
    h.dh_pub = data.substr(0, 32);
    auto u8 = [&](size_t i) { return static_cast<uint32_t>(static_cast<unsigned char>(data[i])); };
    h.pn = (u8(32) << 24) | (u8(33) << 16) | (u8(34) << 8) | u8(35);
    h.n  = (u8(36) << 24) | (u8(37) << 16) | (u8(38) << 8) | u8(39);
    return h;
}

std::string aead_encrypt(const std::string& key, const std::string& nonce,
                         const std::string& pt, const std::string& ad) {
    require(key.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "key must be 32 bytes");
    require(nonce.size() == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "nonce must be 24 bytes");
    std::string ct(pt.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES, '\0');
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(&ct[0]), &clen,
        reinterpret_cast<const unsigned char*>(pt.data()), pt.size(),
        reinterpret_cast<const unsigned char*>(ad.data()), ad.size(),
        nullptr,
        reinterpret_cast<const unsigned char*>(nonce.data()),
        reinterpret_cast<const unsigned char*>(key.data()));
    ct.resize(clen);
    return ct;
}

std::string aead_decrypt(const std::string& key, const std::string& nonce,
                         const std::string& ct, const std::string& ad) {
    require(key.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "key must be 32 bytes");
    require(nonce.size() == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "nonce must be 24 bytes");
    if (ct.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::runtime_error("ciphertext too short");
    std::string pt(ct.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES, '\0');
    unsigned long long plen = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        pt.empty() ? nullptr : reinterpret_cast<unsigned char*>(&pt[0]), &plen,
        nullptr,
        reinterpret_cast<const unsigned char*>(ct.data()), ct.size(),
        reinterpret_cast<const unsigned char*>(ad.data()), ad.size(),
        reinterpret_cast<const unsigned char*>(nonce.data()),
        reinterpret_cast<const unsigned char*>(key.data()));
    if (rc != 0) throw std::runtime_error("AEAD verification failed");
    pt.resize(plen);
    return pt;
}

}  // namespace nk
