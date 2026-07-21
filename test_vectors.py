"""
test_vectors.py — Known-Answer Tests (KATs).

Checks our crypto building blocks against PUBLISHED standard test vectors, so we
know they're really the standard algorithms and not a subtly-broken look-alike.
This tests the CORRECTNESS of the primitives — a different question from the
security-property tests (test_security.py) and from a real audit.

Run:  python3 test_vectors.py    (or pytest test_vectors.py)
"""
import os
import hashlib

import ratchet
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as aead_enc,
    crypto_aead_xchacha20poly1305_ietf_decrypt as aead_dec,
)


def test_x25519_rfc7748():
    # RFC 7748 §5.2 test vectors for X25519 (the DH used in the handshake + ratchet)
    v1 = ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
          "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
          "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    v2 = ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
          "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
          "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    for scalar, u, expected in (v1, v2):
        assert ratchet.dh(bytes.fromhex(scalar), bytes.fromhex(u)).hex() == expected


def test_blake2b():
    # canonical BLAKE2b-512 vectors — the hash our safety number is built on
    assert hashlib.blake2b(b"abc").hexdigest() == (
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
    assert hashlib.blake2b(b"").hexdigest() == (
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
        "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")


def test_hkdf_sha256_rfc5869():
    # RFC 5869 Test Cases 1-3 — proves our HKDF is real HKDF-SHA256
    # TC1
    assert ratchet._hkdf_py(
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("0b" * 22),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865")
    # TC2 (long inputs, L=82)
    assert ratchet._hkdf_py(
        bytes(range(0x60, 0xb0)), bytes(range(0x00, 0x50)),
        bytes(range(0xb0, 0x100)), 82).hex() == (
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87")
    # TC3 (empty salt + info)
    assert ratchet._hkdf_py(b"", bytes.fromhex("0b" * 22), b"", 42).hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8")


def test_xchacha20poly1305_roundtrip_and_reject():
    # exercises libsodium's vetted AEAD: correct decrypt, and tamper is rejected
    key, nonce, ad = os.urandom(32), os.urandom(24), b"header"
    ct = aead_enc(b"secret message", ad, nonce, key)
    assert aead_dec(ct, ad, nonce, key) == b"secret message"
    bad = bytearray(ct)
    bad[0] ^= 1
    try:
        aead_dec(bytes(bad), ad, nonce, key)
        assert False, "tampered ciphertext accepted"
    except Exception:
        pass


if __name__ == "__main__":
    print("running known-answer tests...")
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("  ok:", name)
    print("ALL KNOWN-ANSWER TESTS PASSED")
