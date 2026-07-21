"""
wire.py — the message layer BELOW the ratchet: message types + length padding.

Metadata hardening (Phase 5). Before a message is encrypted, we:
  1. tag it REAL or DECOY, and
  2. pad it up to a fixed BUCKET size.

So on the wire:
  * a real message and a decoy look identical (both are ciphertext), and
  * message length is hidden — everything in a bucket is the same size, so an
    observer can't tell a one-word reply from a paragraph.

Decoys are dropped silently by the receiver (see --cover in nullkey.py).
"""
import struct

REAL = 1
DECOY = 0
BUCKET = 256   # pad every message up to a multiple of this many bytes


def pad(body: bytes) -> bytes:
    data = struct.pack(">I", len(body)) + body          # 4-byte true length + body
    pad_len = (-len(data)) % BUCKET
    return data + b"\x00" * pad_len


def unpad(padded: bytes) -> bytes:
    if len(padded) < 4:
        raise ValueError("padded message too short")
    (length,) = struct.unpack(">I", padded[:4])
    if 4 + length > len(padded):
        raise ValueError("bad padding length")
    return padded[4:4 + length]


def encode(msg_type: int, text: bytes) -> bytes:
    """(type, text) -> padded plaintext ready for the ratchet."""
    return pad(bytes([msg_type]) + text)


def decode(padded: bytes):
    """padded plaintext -> (type, text)."""
    body = unpad(padded)
    if not body:
        raise ValueError("empty message")
    return body[0], body[1:]
