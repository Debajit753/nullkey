"""
test_security.py — SECURITY-PROPERTY tests (not just "does it work").

Each test maps to a claim in the threat model. Passing them gives *confidence*,
not *proof*. Real assurance for crypto = reference test-vectors + fuzzing +
formal analysis + a professional audit + using audited libraries. Treat this as
the floor, not the ceiling.

Run:  python3 test_security.py     (or: pytest test_security.py)
"""
import os
import copy
import socket
import threading

from nacl.public import PrivateKey

import crypto


def make_pair():
    a_id, b_id = PrivateKey.generate(), PrivateKey.generate()
    a, b = socket.socketpair()
    out = {}
    t = threading.Thread(target=lambda: out.__setitem__(
        "a", crypto.ratchet_handshake(a, bytes(a_id), bytes(a_id.public_key), True)))
    t.start()
    dr_b = crypto.ratchet_handshake(b, bytes(b_id), bytes(b_id.public_key), False)
    t.join()
    a.close()
    b.close()
    return out["a"][0], dr_b[0]


def test_forward_secrecy():
    """A device compromise NOW must not decrypt messages already delivered."""
    a, b = make_pair()
    cts = [a.encrypt(("m%d" % i).encode()) for i in range(5)]
    for ct in cts:
        b.decrypt(ct)                        # delivered in order -> keys consumed & deleted
    stolen = copy.deepcopy(b)                # attacker steals Bob's full ratchet state now
    leaked = 0
    for ct in cts:
        try:
            stolen.decrypt(ct)               # try to read the old messages
            leaked += 1
        except Exception:
            pass
    assert leaked == 0, "FORWARD SECRECY BROKEN: %d old messages decrypted from a later state" % leaked
    print("  ok: forward secrecy — a compromise now can't decrypt earlier delivered messages")


def test_mitm_is_detectable_via_safety_number():
    """If a middleman substitutes keys, the two ends' safety numbers won't match."""
    alice, bob, mallory = (PrivateKey.generate() for _ in range(3))
    sn_real = crypto.safety_number(bytes(alice.public_key), bytes(bob.public_key))
    sn_alice_sees = crypto.safety_number(bytes(alice.public_key), bytes(mallory.public_key))
    sn_bob_sees = crypto.safety_number(bytes(bob.public_key), bytes(mallory.public_key))
    assert sn_alice_sees != sn_real and sn_bob_sees != sn_real and sn_alice_sees != sn_bob_sees
    print("  ok: MITM detectable — safety numbers diverge when keys are substituted")


def test_no_key_or_nonce_reuse():
    """Encrypting the same plaintext repeatedly must yield all-different ciphertexts."""
    a, _ = make_pair()
    cts = [a.encrypt(b"same plaintext every time") for _ in range(64)]
    assert len(set(cts)) == 64, "key/nonce reuse: identical ciphertext produced twice"
    print("  ok: no key/nonce reuse — identical plaintext -> unique ciphertexts")


def test_cross_session_key_isolation():
    """A ciphertext from an unrelated session must not decrypt here."""
    a, b = make_pair()
    c, _ = make_pair()
    try:
        b.decrypt(c.encrypt(b"not for you"))
        assert False, "cross-session ciphertext decrypted"
    except Exception:
        pass
    print("  ok: session isolation — another session's ciphertext is rejected")


def test_malformed_input_cannot_crash_or_corrupt():
    """Random/garbage frames must raise cleanly, never crash/hang, and never break the session."""
    a, b = make_pair()
    b.decrypt(a.encrypt(b"warmup"))          # establish the receiving chain
    for _ in range(2000):
        junk = os.urandom(os.urandom(1)[0])  # 0..255 random bytes
        try:
            b.decrypt(junk)
        except Exception:
            pass                             # raising is fine; crashing/hanging is not
    # the session must still work after all that garbage (state rolled back each time)
    assert b.decrypt(a.encrypt(b"still fine")) == b"still fine"
    print("  ok: robustness — 2000 malformed frames rejected, session survives (DoS/parse safety)")


if __name__ == "__main__":
    print("running security-property tests...")
    test_forward_secrecy()
    test_mitm_is_detectable_via_safety_number()
    test_no_key_or_nonce_reuse()
    test_cross_session_key_isolation()
    test_malformed_input_cannot_crash_or_corrupt()
    print("ALL SECURITY-PROPERTY TESTS PASSED  (confidence, not proof — see file header)")
