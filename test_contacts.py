"""
Unit tests for the contacts book.  Run:  pytest test_contacts.py
"""
import os
import tempfile

from contacts import Contacts


def _fresh():
    d = tempfile.mkdtemp()
    return Contacts(os.path.join(d, "contacts.json"))


def test_add_and_get():
    c = _fresh()
    c.add("alice", "abcd.onion")
    assert c.get("alice")["address"] == "abcd.onion"
    assert c.get("alice")["verified"] is False
    assert c.get("nope") is None


def test_resolve_name_address_and_unknown():
    c = _fresh()
    c.add("alice", "abcd.onion")
    assert c.resolve("alice") == ("alice", "abcd.onion")        # by name
    assert c.resolve("abcd.onion") == ("alice", "abcd.onion")   # by address
    assert c.resolve("zzz.onion") == (None, "zzz.onion")        # unknown -> raw address


def test_verify_and_find_by_pubkey():
    c = _fresh()
    c.add("bob", "b.onion")
    c.set_pubkey("bob", "deadbeef")
    c.set_verified("bob", True)
    assert c.find_by_pubkey("deadbeef") == "bob"
    assert c.find_by_pubkey("nope") is None
    assert c.get("bob")["verified"] is True


def test_persistence_across_reload():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "contacts.json")
    c = Contacts(p)
    c.add("x", "x.onion")
    c.set_pubkey("x", "ab12")
    c.set_verified("x")
    c2 = Contacts(p)                       # reload from disk
    assert c2.get("x")["address"] == "x.onion"
    assert c2.get("x")["pubkey"] == "ab12"
    assert c2.get("x")["verified"] is True


def test_contacts_file_is_private_0600():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "contacts.json")
    Contacts(p).add("x", "x.onion")
    if os.name != "nt":
        assert oct(os.stat(p).st_mode & 0o777) == "0o600"


def test_delete_and_clear_all():
    c = _fresh()
    c.add("a", "a.onion")
    c.add("b", "b.onion")
    assert c.delete("a") is True
    assert c.get("a") is None and c.get("b") is not None
    assert c.delete("nope") is False        # deleting a missing name is a no-op
    c.clear_all()
    assert c.all() == {}


if __name__ == "__main__":
    for fn in [test_add_and_get, test_resolve_name_address_and_unknown,
               test_verify_and_find_by_pubkey, test_persistence_across_reload,
               test_contacts_file_is_private_0600, test_delete_and_clear_all]:
        fn()
        print("  ok:", fn.__name__)
    print("ALL CONTACTS TESTS PASSED")
