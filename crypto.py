"""
crypto.py — framing + X25519 handshake + safety number.

This is the Phase 0 crypto, factored out so the app can reuse it.
It is STATIC X25519 (one shared key per session) — good enough to learn on,
but with NO forward secrecy. Phase 2 replaces the `Box` here with a Double
Ratchet. Don't call this "secure" until then.
"""
import struct
import hashlib
from nacl.public import PrivateKey, PublicKey, Box

import ratchet

MAX_FRAME = 1 << 20  # 1 MB cap so a peer can't make us allocate unbounded memory


# ------------------------------ framing ----------------------------------- #
def send_frame(sock, data: bytes):
    """Length-prefixed frame: 4-byte big-endian length, then the bytes."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None  # socket closed (by peer or by us) — treat as clean disconnect
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock):
    """Read one whole frame, or None if the peer closed / sent garbage."""
    hdr = _recv_exact(sock, 4)
    if hdr is None:
        return None
    (length,) = struct.unpack(">I", hdr)
    if length == 0 or length > MAX_FRAME:
        return None
    return _recv_exact(sock, length)


# ------------------------------ crypto ------------------------------------ #
def _safety_number_py(pub_a: bytes, pub_b: bytes) -> str:
    lo, hi = sorted([pub_a, pub_b])
    digest = hashlib.blake2b(lo + hi, digest_size=10).hexdigest()
    return "-".join(digest[i:i + 5] for i in range(0, len(digest), 5))


def safety_number(pub_a: bytes, pub_b: bytes) -> str:
    """Order-independent fingerprint of both public keys, to compare out of band."""
    if ratchet.CORE is not None:
        return ratchet.CORE.safety_number(pub_a, pub_b)
    return _safety_number_py(pub_a, pub_b)


def handshake(sock, my_priv: PrivateKey, initiator: bool):
    """
    PHASE 0/legacy: exchange raw 32-byte X25519 public keys and build a static Box.
    Kept for reference (chat.py). The app now uses ratchet_handshake (Phase 2).
    """
    my_pub = bytes(my_priv.public_key)
    if initiator:
        sock.sendall(my_pub)
        their_pub = _recv_exact(sock, 32)
    else:
        their_pub = _recv_exact(sock, 32)
        sock.sendall(my_pub)
    if not their_pub or len(their_pub) != 32:
        raise ConnectionError("handshake failed (bad peer key)")
    box = Box(my_priv, PublicKey(their_pub))
    return box, my_pub, their_pub


# ------------------------- Phase 2 handshake ------------------------------ #
def ratchet_handshake(sock, id_priv: bytes, id_pub: bytes, initiator: bool):
    """
    Authenticated key agreement that bootstraps a Double Ratchet.

    A compact, synchronous X3DH-style handshake (both peers are online): we mix
    three DHs so the shared secret is authenticated by both LONG-TERM identity
    keys AND made forward-secret by fresh EPHEMERAL keys:

        DH1 = DH(IK_initiator, EK_responder)
        DH2 = DH(EK_initiator, IK_responder)
        DH3 = DH(EK_initiator, EK_responder)
        SK  = HKDF(DH1 || DH2 || DH3)

    Each side also sends a fresh RATCHET public key; the responder's seeds the
    ratchet. Wire message (each side): IK_pub(32) || EK_pub(32) || RATCHET_pub(32).

    Returns (DoubleRatchet, my_identity_pub, their_identity_pub).
    """
    ek_priv, ek_pub = ratchet.generate_dh()
    rk_priv, rk_pub = ratchet.generate_dh()
    my_blob = id_pub + ek_pub + rk_pub

    if initiator:
        sock.sendall(my_blob)
        peer = _recv_exact(sock, 96)
    else:
        peer = _recv_exact(sock, 96)
        sock.sendall(my_blob)
    if not peer or len(peer) != 96:
        raise ConnectionError("handshake failed (bad peer handshake)")

    p_ik, p_ek, p_rk = peer[0:32], peer[32:64], peer[64:96]

    if initiator:
        dh1 = ratchet.dh(id_priv, p_ek)   # DH(IK_i, EK_r)
        dh2 = ratchet.dh(ek_priv, p_ik)   # DH(EK_i, IK_r)
        dh3 = ratchet.dh(ek_priv, p_ek)   # DH(EK_i, EK_r)
    else:
        dh1 = ratchet.dh(ek_priv, p_ik)   # DH(EK_r, IK_i) == DH(IK_i, EK_r)
        dh2 = ratchet.dh(id_priv, p_ek)   # DH(IK_r, EK_i) == DH(EK_i, IK_r)
        dh3 = ratchet.dh(ek_priv, p_ek)   # DH(EK_r, EK_i) == DH(EK_i, EK_r)

    sk = ratchet.kdf_sk(dh1 + dh2 + dh3)

    if initiator:
        dr = ratchet.DoubleRatchet.init_initiator(sk, p_rk)
    else:
        dr = ratchet.DoubleRatchet.init_responder(sk, (rk_priv, rk_pub))
    return dr, id_pub, p_ik
