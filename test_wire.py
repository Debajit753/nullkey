"""Tests for the padding / message-type layer.  Run: pytest test_wire.py"""
import wire


def test_roundtrip_all_types_and_sizes():
    for t in [b"", b"hi", b"x" * 300, "café ☕".encode()]:
        mt, txt = wire.decode(wire.encode(wire.REAL, t))
        assert mt == wire.REAL and txt == t


def test_padding_hides_length_within_a_bucket():
    a = wire.encode(wire.REAL, b"a")
    b = wire.encode(wire.REAL, b"a much longer message but still under a bucket")
    assert len(a) == len(b) == wire.BUCKET      # indistinguishable lengths
    assert len(a) % wire.BUCKET == 0


def test_larger_message_rounds_up_to_next_bucket():
    big = wire.encode(wire.REAL, b"x" * 600)
    assert len(big) % wire.BUCKET == 0 and len(big) >= 600


def test_decoy_tag_survives():
    mt, txt = wire.decode(wire.encode(wire.DECOY, b""))
    assert mt == wire.DECOY and txt == b""


if __name__ == "__main__":
    for fn in [test_roundtrip_all_types_and_sizes,
               test_padding_hides_length_within_a_bucket,
               test_larger_message_rounds_up_to_next_bucket,
               test_decoy_tag_survives]:
        fn()
        print("  ok:", fn.__name__)
    print("ALL WIRE TESTS PASSED")
