"""
Tests for the CPU DoS and memory exhaustion mitigations added to ratchet.py / net.py.

Run:  python3 test_dos_mitigation.py   or   pytest test_dos_mitigation.py
"""
import os
import time
import socket
import threading

from nacl.public import PrivateKey

import crypto
import ratchet
import net


# ─── helpers ─────────────────────────────────────────────────────────────── #

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
    dr_b, _, _ = crypto.ratchet_handshake(
        b, bytes(b_id), bytes(b_id.public_key), initiator=False)
    t.join()
    a.close()
    b.close()
    dr_a, _, _ = out["a"]
    return dr_a, dr_b


# ─── 1. Transport MAC ────────────────────────────────────────────────────── #

def test_transport_mac_rejects_garbage():
    """Forged frames (random bytes) must be rejected before any DH computation."""
    alice, bob = make_pair()
    # both sides have a mac_key after the new handshake
    assert alice.mac_key is not None
    assert bob.mac_key is not None

    ct = alice.encrypt(b"legitimate")
    assert bob.decrypt(ct) == b"legitimate"

    # garbage frame: wrong MAC -> rejected immediately
    garbage = os.urandom(len(ct))
    try:
        bob.decrypt(garbage)
        assert False, "garbage frame should have been rejected"
    except ValueError as e:
        assert "transport MAC" in str(e).lower() or "mac" in str(e).lower()

    # session survives the rejection
    assert bob.decrypt(alice.encrypt(b"still works")) == b"still works"
    print("  ok: transport MAC rejects garbage, session survives")


def test_transport_mac_too_short():
    """Frames shorter than MAC + HEADER must be rejected."""
    alice, bob = make_pair()
    try:
        bob.decrypt(b"\x00" * 10)
        assert False, "short frame should have been rejected"
    except ValueError as e:
        assert "too short" in str(e)
    print("  ok: short frames rejected")


# ─── 2. MKSKIPPED cap + LRU eviction ─────────────────────────────────────── #

def test_mkskipped_cap():
    """
    When we skip more than MAX_STORED_SKIPPED_KEYS messages, the store must
    stay bounded by evicting the oldest entries.
    """
    alice, bob = make_pair()
    # prime the ratchet so bob can receive
    ct0 = alice.encrypt(b"prime")
    bob.decrypt(ct0)

    # generate many skipped messages
    n = min(ratchet.MAX_STORED_SKIPPED_KEYS + 500, ratchet.MAX_SKIP)
    msgs = [alice.encrypt(("skip%d" % i).encode()) for i in range(n)]

    # deliver only the LAST one — forces bob to skip all preceding
    bob.decrypt(msgs[-1])
    assert len(bob.MKSKIPPED) <= ratchet.MAX_STORED_SKIPPED_KEYS, \
        "MKSKIPPED grew beyond cap: %d" % len(bob.MKSKIPPED)
    print("  ok: MKSKIPPED capped at %d entries" % ratchet.MAX_STORED_SKIPPED_KEYS)


def test_dh_ratchet_prunes_old_keys():
    """
    After enough DH ratchet steps, skipped keys from old DH epochs get purged.
    The pruning keeps keys from the current and incoming DH pub only.
    """
    alice, bob = make_pair()

    # alice sends 3 messages, bob receives only the last → 2 skipped keys in epoch-0
    m0 = alice.encrypt(b"a0")
    m1 = alice.encrypt(b"a1")
    m2 = alice.encrypt(b"a2")
    bob.decrypt(m2)
    epoch0_skipped = len(bob.MKSKIPPED)
    assert epoch0_skipped == 2  # m0, m1 still cached

    # bob replies → alice does a DH ratchet
    ct = bob.encrypt(b"b0")
    alice.decrypt(ct)

    # alice sends with new DH key → bob does a DH ratchet (epoch-0 DHr → now old)
    ct2 = alice.encrypt(b"a3")
    bob.decrypt(ct2)
    # at this point bob keeps epoch-0 keys because self.DHr was just the epoch-0 key

    # bob replies again → another DH ratchet on alice
    ct3 = bob.encrypt(b"b1")
    alice.decrypt(ct3)

    # alice sends again → bob does ANOTHER DH ratchet. Now epoch-0 is 2 epochs back,
    # so it should be pruned (allowed = {new_dh_pub, previous_DHr}, neither is epoch-0)
    ct4 = alice.encrypt(b"a4")
    bob.decrypt(ct4)

    assert len(bob.MKSKIPPED) == 0, \
        "old-epoch skipped keys not pruned: %d left" % len(bob.MKSKIPPED)
    print("  ok: DH ratchet prunes old-epoch skipped keys")


# ─── 3. DecryptionRateLimiter ─────────────────────────────────────────────── #

def test_rate_limiter_allows_then_blocks():
    """Token bucket starts with capacity tokens, then blocks."""
    rl = net.DecryptionRateLimiter(capacity=5, refill_per_sec=0.0)
    for i in range(5):
        assert rl.allow(), "should allow token %d" % i
    assert not rl.allow(), "should block after capacity exhausted"
    print("  ok: rate limiter blocks after capacity")


def test_rate_limiter_refills():
    """After some time, tokens refill and allow() returns True again."""
    rl = net.DecryptionRateLimiter(capacity=2, refill_per_sec=100.0)
    assert rl.allow()
    assert rl.allow()
    assert not rl.allow()
    # simulate time passing by adjusting the internal last_refill
    rl._last_refill -= 1.0  # pretend 1s elapsed → 100 tokens refilled (capped at 2)
    assert rl.allow()
    print("  ok: rate limiter refills tokens over time")


# ─── 4. Verify normal operation is unaffected ─────────────────────────────── #

def test_normal_session_with_mac():
    """Full bidirectional conversation works with transport MAC enabled."""
    alice, bob = make_pair()
    for i in range(20):
        assert bob.decrypt(alice.encrypt(("a%d" % i).encode())) == ("a%d" % i).encode()
        assert alice.decrypt(bob.encrypt(("b%d" % i).encode())) == ("b%d" % i).encode()
    print("  ok: full bidirectional session works with transport MAC")


if __name__ == "__main__":
    print("running DoS mitigation tests...")
    test_transport_mac_rejects_garbage()
    test_transport_mac_too_short()
    test_mkskipped_cap()
    test_dh_ratchet_prunes_old_keys()
    test_rate_limiter_allows_then_blocks()
    test_rate_limiter_refills()
    test_normal_session_with_mac()
    print("ALL DoS MITIGATION TESTS PASSED")
