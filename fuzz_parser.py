"""
fuzz_parser.py — throw garbage at the code that parses attacker-controlled bytes.

A parser fed hostile input must only ever RAISE — never crash the process, hang,
or corrupt session state. We fuzz the two places an attacker fully controls:
  * ratchet.DoubleRatchet.decrypt (the whole frame)
  * ratchet._unpack_header       (the header parse)

If `atheris` is installed you get coverage-guided fuzzing (best). Otherwise it
falls back to a stdlib random fuzzer so it always runs (and runs in CI).

Run:            python3 fuzz_parser.py           # fallback random fuzz
With atheris:   python3 fuzz_parser.py            # coverage-guided (auto-detected)
"""
import os
import sys
import socket
import threading

from nacl.public import PrivateKey

import crypto
import ratchet


def _victim():
    """A responder ratchet that has already processed one message (has a recv chain)."""
    a_id, b_id = PrivateKey.generate(), PrivateKey.generate()
    a, b = socket.socketpair()
    out = {}
    t = threading.Thread(target=lambda: out.__setitem__(
        "a", crypto.ratchet_handshake(a, bytes(a_id), bytes(a_id.public_key), True)))
    t.start()
    drb = crypto.ratchet_handshake(b, bytes(b_id), bytes(b_id.public_key), False)[0]
    t.join()
    a.close()
    b.close()
    dra = out["a"][0]
    drb.decrypt(dra.encrypt(b"warmup"))
    return dra, drb


DRA, VICTIM = _victim()


def one_input(data: bytes):
    try:
        VICTIM.decrypt(data)        # must never crash; only raise
    except Exception:
        pass
    try:
        if len(data) >= ratchet.HEADER_LEN:
            ratchet._unpack_header(data[:ratchet.HEADER_LEN])
    except Exception:
        pass


def _fallback(rounds=50000):
    for _ in range(rounds):
        one_input(os.urandom(os.urandom(1)[0]))     # random length 0..255
    # the victim must still work after all that garbage (state rolled back each time)
    assert VICTIM.decrypt(DRA.encrypt(b"still alive")) == b"still alive"
    print("fallback fuzz: %d random inputs handled cleanly; session intact" % rounds)


if __name__ == "__main__":
    try:
        import atheris  # noqa: F401
        def _t(data):
            one_input(bytes(data))
        atheris.Setup(sys.argv, _t)
        atheris.Fuzz()
    except ImportError:
        _fallback()
