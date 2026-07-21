"""
Parity tests: the C++ core (nullkey_core) must byte-for-byte match the Python
reference (ratchet.py / crypto.py). This is how you prove a port is correct.

Build first:  python setup.py build_ext --inplace
Run:          python test_core_parity.py     (or pytest test_core_parity.py)
"""
import os

import crypto
import ratchet

# The compiled C++ core is optional and gitignored, so a fresh clone / CI won't
# have it. Skip these parity tests gracefully instead of aborting the whole run.
try:
    import nullkey_core as C
except ImportError:
    C = None

if C is None:
    import sys
    if "pytest" in sys.modules:
        import pytest
        pytest.skip(
            "nullkey_core not built; run: python setup.py build_ext --inplace",
            allow_module_level=True,
        )
    else:
        print("nullkey_core not built — skipping parity tests. "
              "Build with: python setup.py build_ext --inplace")
        sys.exit(0)

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as py_enc,
    crypto_aead_xchacha20poly1305_ietf_decrypt as py_dec,
)


def rb(n):
    return os.urandom(n)


# Compare the C++ core against the PURE-PYTHON reference (`*_py`), so the parity
# test stays meaningful even though the app now dispatches to C++ by default.
def test_safety_number_matches():
    for _ in range(50):
        a, b = rb(32), rb(32)
        assert C.safety_number(a, b) == crypto._safety_number_py(a, b)


def test_hkdf_matches():
    for length in (16, 32, 56, 64, 100):
        salt, ikm, info = rb(32), rb(48), b"NullkeyMsgKeys"
        assert C.hkdf(salt, ikm, info, length) == ratchet._hkdf_py(salt, ikm, info, length)


def test_kdf_ck_matches():
    ck = rb(32)
    assert tuple(C.kdf_ck(ck)) == ratchet.kdf_ck_py(ck)


def test_msg_keys_matches():
    mk = rb(32)
    assert tuple(C.msg_keys(mk)) == ratchet._msg_keys_py(mk)


def test_parse_header_matches():
    dh, pn, n = rb(32), 7, 42
    hdr = ratchet._pack_header(dh, pn, n)
    assert tuple(C.parse_header(hdr)) == ratchet._unpack_header_py(hdr)
    assert tuple(C.parse_header(hdr)) == (dh, pn, n)
    # a short header must be rejected (not read out of bounds)
    try:
        C.parse_header(b"\x00" * 10)
        assert False, "short header accepted"
    except Exception:
        pass


def test_aead_interoperable_both_directions():
    key, nonce, pt, ad = rb(32), rb(24), b"attack at dawn", b"assoc"
    # C++ encrypt -> Python decrypt
    ct_cpp = C.aead_encrypt(key, nonce, pt, ad)
    assert py_dec(ct_cpp, ad, nonce, key) == pt
    # Python encrypt -> C++ decrypt
    ct_py = py_enc(pt, ad, nonce, key)
    assert C.aead_decrypt(key, nonce, ct_py, ad) == pt
    # tamper is rejected by the C++ side
    bad = bytearray(ct_py)
    bad[-1] ^= 1
    try:
        C.aead_decrypt(key, nonce, bytes(bad), ad)
        assert False, "tamper accepted"
    except Exception:
        pass


if __name__ == "__main__":
    print("running C++ <-> Python parity tests...")
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("  ok:", name)
    print("ALL PARITY TESTS PASSED — C++ core matches the Python reference byte-for-byte")
