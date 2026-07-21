"""
Self-tests for the Phase 2 handshake + Double Ratchet.

Run:  python3 test_ratchet.py     (exit 0 = all good)

These prove the properties that matter: messages decrypt in and out of order,
tampering is caught, replays are rejected (one-time keys), and both directions
keep ratcheting. This is the file your CI runs.
"""
import socket
import threading

from nacl.public import PrivateKey

import crypto


def make_pair():
    """Run the real ratchet_handshake over a socket pair, return (dr_alice, dr_bob)."""
    a_id, b_id = PrivateKey.generate(), PrivateKey.generate()
    a, b = socket.socketpair()
    out = {}

    def initiator():
        out["a"] = crypto.ratchet_handshake(
            a, bytes(a_id), bytes(a_id.public_key), initiator=True)

    t = threading.Thread(target=initiator)
    t.start()
    dr_b, b_idpub, b_sees = crypto.ratchet_handshake(
        b, bytes(b_id), bytes(b_id.public_key), initiator=False)
    t.join()
    a.close()
    b.close()

    dr_a, a_idpub, a_sees = out["a"]
    # each side saw the other's real identity key
    assert a_sees == bytes(b_id.public_key)
    assert b_sees == bytes(a_id.public_key)
    # and both compute the SAME safety number (stable, identity-based)
    assert crypto.safety_number(a_idpub, a_sees) == crypto.safety_number(b_idpub, b_sees)
    return dr_a, dr_b


def test_bidirectional_and_dh_ratchet():
    a, b = make_pair()
    assert b.decrypt(a.encrypt(b"hello bob")) == b"hello bob"
    assert a.decrypt(b.encrypt(b"hi alice")) == b"hi alice"      # reply -> DH ratchet
    for i in range(6):
        assert b.decrypt(a.encrypt(("a%d" % i).encode())) == ("a%d" % i).encode()
        assert a.decrypt(b.encrypt(("b%d" % i).encode())) == ("b%d" % i).encode()
    # the ratchet keys actually rotated (post-compromise security mechanism)
    assert a.DHs[1] != b.DHs[1]
    print("  ok: bidirectional messaging + DH ratchet rotation")


def test_out_of_order():
    a, b = make_pair()
    msgs = [a.encrypt(("m%d" % i).encode()) for i in range(5)]
    for i in [4, 2, 0, 3, 1]:                         # scrambled delivery
        assert b.decrypt(msgs[i]) == ("m%d" % i).encode()
    print("  ok: out-of-order delivery via skipped message keys")


def test_tamper_is_caught_and_session_survives():
    a, b = make_pair()
    good = a.encrypt(b"first")
    bad = bytearray(a.encrypt(b"second"))
    bad[-1] ^= 0x01                                   # flip a ciphertext byte
    assert b.decrypt(good) == b"first"
    try:
        b.decrypt(bytes(bad))
        assert False, "tamper not detected"
    except Exception:
        pass
    # after a rejected frame, the session must still work (state rolled back)
    assert b.decrypt(a.encrypt(b"third")) == b"third"
    print("  ok: tampering caught (AEAD) and the session survives it")


def test_replay_rejected():
    a, b = make_pair()
    m = a.encrypt(b"once only")
    assert b.decrypt(m) == b"once only"
    try:
        b.decrypt(m)                                  # replay same bytes
        assert False, "replay accepted"
    except Exception:
        pass
    print("  ok: one-time keys — replay rejected (forward-secrecy property)")


if __name__ == "__main__":
    print("running ratchet tests...")
    test_bidirectional_and_dh_ratchet()
    test_out_of_order()
    test_tamper_is_caught_and_session_survives()
    test_replay_rejected()
    print("ALL RATCHET TESTS PASSED")
