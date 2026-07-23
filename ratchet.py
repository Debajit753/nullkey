"""
ratchet.py — the Double Ratchet (Signal spec), educational implementation.

WHAT IT GIVES YOU
  * Forward secrecy:  every message uses a fresh, one-time key that's thrown
    away after use, so stealing today's keys does NOT decrypt yesterday's
    messages.
  * Post-compromise security ("self-healing"):  the DH ratchet mixes in new
    key material as messages flow back and forth, so a session recovers its
    secrecy after a temporary compromise.

HOW (three sub-ratchets, per the spec):
  1. DH ratchet   — a new X25519 key pair each time the conversation "turns"
                    (you reply), feeding fresh randomness into the root key.
  2. Root chain   — KDF that turns (old root key, DH output) -> (new root key,
                    new sending/receiving chain key).
  3. Symmetric chains — KDF that turns a chain key -> (next chain key, one
                    message key). One-way, so old message keys can't be
                    recomputed from a newer chain key = forward secrecy.

Primitives: X25519 (DH) + HKDF/HMAC-SHA256 (KDFs) + XChaCha20-Poly1305 (AEAD),
all from libsodium via PyNaCl. We do NOT invent crypto — we compose vetted
primitives following the published spec.

⚠️  EDUCATIONAL. It follows the spec and passes the tests in test_ratchet.py,
but for anything real: use a professionally reviewed library
(e.g. python-doubleratchet) and get a security audit. Ref: Signal's
"The Double Ratchet Algorithm" specification.
"""
import os
import hmac
import hashlib
import struct
from collections import OrderedDict

from nacl.bindings import (
    crypto_scalarmult,
    crypto_scalarmult_base,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)

# ---- optional C++ core (Phase 3) ----
# The primitives below dispatch to the compiled C++ module `nullkey_core` when it's
# available (built via `make core`), and fall back to pure Python otherwise. The
# pure-Python versions are kept as `*_py` so the parity test can compare the two.
# Set NULLKEY_FORCE_PYTHON=1 to force the Python path.
if os.environ.get("NULLKEY_FORCE_PYTHON"):
    CORE = None
else:
    try:
        import nullkey_core as CORE
    except ImportError:
        CORE = None
BACKEND = "c++ (nullkey_core)" if CORE is not None else "python"

MAX_SKIP = 1000          # tolerate this many out-of-order/skipped messages per chain
MAX_STORED_SKIPPED_KEYS = 3000   # global cap on cached skipped keys (prevents OOM)
HEADER_LEN = 40          # 32-byte ratchet pubkey + 4-byte PN + 4-byte N
MAC_LEN = 16             # transport MAC length (BLAKE2b-128)


# ------------------------------ primitives -------------------------------- #
def generate_dh():
    """A fresh X25519 key pair. Returns (private_32, public_32)."""
    priv = os.urandom(32)                 # libsodium clamps the scalar internally
    return priv, crypto_scalarmult_base(priv)


def dh(priv, pub):
    """X25519 Diffie-Hellman -> 32-byte shared secret."""
    return crypto_scalarmult(priv, pub)


# -- pure-Python reference implementations (kept for parity testing) -- #
def _hkdf_py(salt, ikm, info, length):
    """HKDF-SHA256 (RFC 5869): extract-then-expand."""
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def kdf_ck_py(ck):
    """Chain KDF: chain key -> (next chain key, one message key). One-way."""
    mk = hmac.new(ck, b"\x01", hashlib.sha256).digest()
    next_ck = hmac.new(ck, b"\x02", hashlib.sha256).digest()
    return next_ck, mk


def _msg_keys_py(mk):
    out = _hkdf_py(b"\x00" * 32, mk, b"NullkeyMsgKeys", 32 + 24)
    return out[:32], out[32:56]


def _aead_encrypt_py(key, nonce, pt, ad):
    return crypto_aead_xchacha20poly1305_ietf_encrypt(pt, ad, nonce, key)


def _aead_decrypt_py(key, nonce, ct, ad):
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ct, ad, nonce, key)


# -- dispatchers: C++ core when available, else pure Python -- #
def _hkdf(salt, ikm, info, length):
    return CORE.hkdf(salt, ikm, info, length) if CORE else _hkdf_py(salt, ikm, info, length)


def kdf_ck(ck):
    return tuple(CORE.kdf_ck(ck)) if CORE else kdf_ck_py(ck)


def _msg_keys(mk):
    return tuple(CORE.msg_keys(mk)) if CORE else _msg_keys_py(mk)


def _aead_encrypt(key, nonce, pt, ad):
    return CORE.aead_encrypt(key, nonce, pt, ad) if CORE else _aead_encrypt_py(key, nonce, pt, ad)


def _aead_decrypt(key, nonce, ct, ad):
    return CORE.aead_decrypt(key, nonce, ct, ad) if CORE else _aead_decrypt_py(key, nonce, ct, ad)


def kdf_sk(ikm):
    """Handshake KDF: raw DH concatenation -> (SK_32, transport_mac_key_32)."""
    out = _hkdf(b"\x00" * 32, ikm, b"NullkeyHandshakeKeys", 64)
    return out[:32], out[32:64]


def kdf_rk(rk, dh_out):
    """Root KDF: (old root key, DH output) -> (new root key, chain key)."""
    out = _hkdf(rk, dh_out, b"NullkeyRatchetRoot", 64)
    return out[:32], out[32:64]           # (key_32, nonce_24)


def _pack_header(dh_pub, pn, n):
    return dh_pub + struct.pack(">II", pn, n)


def _unpack_header_py(data):
    if len(data) < HEADER_LEN:
        raise ValueError("header too short")
    pn, n = struct.unpack(">II", data[32:40])
    return data[:32], pn, n


def _unpack_header(data):
    return tuple(CORE.parse_header(data)) if CORE else _unpack_header_py(data)


# ------------------------------- ratchet ---------------------------------- #
class DoubleRatchet:
    def __init__(self):
        self.DHs = None       # our current ratchet key pair (priv, pub)
        self.DHr = None       # peer's current ratchet public key (bytes)
        self.RK = None        # root key
        self.CKs = None       # sending chain key
        self.CKr = None       # receiving chain key
        self.Ns = 0           # messages sent in current sending chain
        self.Nr = 0           # messages received in current receiving chain
        self.PN = 0           # messages sent in the PREVIOUS sending chain
        self.MKSKIPPED = OrderedDict()  # (ratchet_pub, N) -> message key, LRU-capped
        self.mac_key = None   # per-session transport MAC key (set by handshake)

    # -- initialisation (from the handshake's shared secret SK) -- #
    @classmethod
    def init_initiator(cls, sk, peer_ratchet_pub):
        self = cls()
        self.DHs = generate_dh()
        self.DHr = peer_ratchet_pub
        self.RK, self.CKs = kdf_rk(sk, dh(self.DHs[0], self.DHr))
        return self

    @classmethod
    def init_responder(cls, sk, ratchet_keypair):
        self = cls()
        self.DHs = ratchet_keypair
        self.DHr = None
        self.RK = sk
        return self

    # ------------------------------ encrypt ------------------------------- #
    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        self.CKs, mk = kdf_ck(self.CKs)
        header = _pack_header(self.DHs[1], self.PN, self.Ns)
        self.Ns += 1
        key, nonce = _msg_keys(mk)
        ct = _aead_encrypt(key, nonce, plaintext, associated_data + header)
        payload = header + ct
        if self.mac_key:
            mac = hmac.new(self.mac_key, payload, hashlib.blake2b).digest()[:MAC_LEN]
            return mac + payload
        return payload

    # ------------------------------ decrypt ------------------------------- #
    def decrypt(self, message: bytes, associated_data: bytes = b"") -> bytes:
        # --- transport MAC pre-check: reject garbage in microseconds --- #
        if self.mac_key:
            if len(message) < MAC_LEN + HEADER_LEN:
                raise ValueError("message too short for transport MAC")
            mac, payload = message[:MAC_LEN], message[MAC_LEN:]
            expected = hmac.new(self.mac_key, payload, hashlib.blake2b).digest()[:MAC_LEN]
            if not hmac.compare_digest(mac, expected):
                raise ValueError("invalid transport MAC — forged/corrupted frame")
        else:
            payload = message
        # Snapshot state and roll back if anything fails, so a single bad/tampered
        # frame can be dropped without corrupting the whole session.
        snap = self._snapshot()
        try:
            return self._decrypt(payload, associated_data)
        except Exception:
            self._restore(snap)
            raise

    def _decrypt(self, message, ad):
        header, ct = message[:HEADER_LEN], message[HEADER_LEN:]
        dh_pub, pn, n = _unpack_header(header)

        # 1) maybe this is a message we skipped earlier
        keyid = (dh_pub, n)
        if keyid in self.MKSKIPPED:
            mk = self.MKSKIPPED[keyid]
            pt = self._aead_open(ct, ad + header, mk)
            del self.MKSKIPPED[keyid]      # only remove once we KNOW it decrypts
            return pt

        # 2) new ratchet key from the peer? take a DH ratchet step
        if self.DHr is None or dh_pub != self.DHr:
            self._skip(pn)
            self._dh_ratchet(dh_pub)

        # 3) advance the receiving chain up to this message
        self._skip(n)
        self.CKr, mk = kdf_ck(self.CKr)
        self.Nr += 1
        return self._aead_open(ct, ad + header, mk)

    # -- helpers -- #
    def _aead_open(self, ct, ad, mk):
        key, nonce = _msg_keys(mk)
        return _aead_decrypt(key, nonce, ct, ad)

    def _skip(self, until):
        if self.CKr is None:
            return
        if self.Nr + MAX_SKIP < until:
            raise ValueError("too many skipped messages")
        while self.Nr < until:
            self.CKr, mk = kdf_ck(self.CKr)
            if len(self.MKSKIPPED) >= MAX_STORED_SKIPPED_KEYS:
                self.MKSKIPPED.popitem(last=False)   # evict oldest
            self.MKSKIPPED[(self.DHr, self.Nr)] = mk
            self.Nr += 1

    def _dh_ratchet(self, dh_pub):
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0
        # prune skipped keys from DH epochs older than the outgoing self.DHr
        # and the incoming dh_pub — keys from earlier epochs are unreachable
        allowed = {dh_pub}
        if self.DHr is not None:
            allowed.add(self.DHr)
        for k in list(self.MKSKIPPED):
            if k[0] not in allowed:
                del self.MKSKIPPED[k]
        self.DHr = dh_pub
        self.RK, self.CKr = kdf_rk(self.RK, dh(self.DHs[0], self.DHr))
        self.DHs = generate_dh()
        self.RK, self.CKs = kdf_rk(self.RK, dh(self.DHs[0], self.DHr))

    def _snapshot(self):
        return (self.DHs, self.DHr, self.RK, self.CKs, self.CKr,
                self.Ns, self.Nr, self.PN, OrderedDict(self.MKSKIPPED))

    def _restore(self, s):
        (self.DHs, self.DHr, self.RK, self.CKs, self.CKr,
         self.Ns, self.Nr, self.PN, mkskipped) = s
        self.MKSKIPPED = mkskipped
