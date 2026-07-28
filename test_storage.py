"""
Tests for how secrets hit the disk: permissions, atomicity, corruption recovery,
plus the wall-clock handshake deadline.

These pin down the "quiet" failures — the ones that don't crash, they just leave
your key readable or your contact book destroyed.
"""
import os
import json
import time
import socket
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

import crypto
import identity
from contacts import Contacts


class TestKeyFilePermissions(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    @unittest.skipIf(os.name == "nt", "POSIX permissions only")
    def test_key_is_never_world_readable_even_briefly(self):
        """
        The key must be CREATED 0600, not written world-readable and chmod'd
        after — that window is enough for another local user to read your identity.

        We clear the umask so a naive open() would produce 0666/0644. Anything
        relying on the umask to be safe fails here, which is the point: you
        cannot depend on the user's umask to protect a private key.
        """
        old_umask = os.umask(0)
        try:
            identity.load_or_create_x25519(self.d)
            path = os.path.join(self.d, "crypto_identity.key")
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode & 0o077, 0,
                             "identity key is group/other-accessible (mode %o)" % mode)
            self.assertEqual(mode, 0o600)

            # same guarantee for the onion key path and for any later rewrite
            p2 = os.path.join(self.d, "onion_identity.key")
            identity.write_secret(p2, "ED25519-V3:abc")
            self.assertEqual(os.stat(p2).st_mode & 0o777, 0o600)
        finally:
            os.umask(old_umask)

    @unittest.skipIf(os.name == "nt", "POSIX permissions only")
    def test_secret_is_created_0600_not_chmodded_afterwards(self):
        """
        Catches the TRANSIENT window that a final-state check cannot see.

        write-then-chmod ends up at 0600 too, so checking the finished file passes
        either way. Here we record the mode at the instant chmod is called: if the
        secret was already on disk world-readable, that window was real.
        """
        observed = {}
        real_chmod = os.chmod

        def spy_chmod(path, mode, *a, **kw):
            try:
                observed[str(path)] = os.stat(path).st_mode & 0o777
            except (OSError, TypeError):
                pass
            return real_chmod(path, mode, *a, **kw)

        old_umask = os.umask(0)
        try:
            with patch("os.chmod", spy_chmod):
                identity.load_or_create_x25519(self.d)
                Contacts(os.path.join(self.d, "contacts.json")).add("a", "a.onion")
        finally:
            os.umask(old_umask)

        for path, mode_at_chmod in observed.items():
            self.assertEqual(mode_at_chmod & 0o077, 0,
                             "%s existed as %o before being chmod'd — readable window"
                             % (path, mode_at_chmod))

    @unittest.skipIf(os.name == "nt", "POSIX permissions only")
    def test_contacts_file_is_never_world_readable(self):
        old_umask = os.umask(0)
        try:
            p = os.path.join(self.d, "contacts.json")
            Contacts(p).add("alice", "a.onion")
            mode = os.stat(p).st_mode & 0o777
            self.assertEqual(mode & 0o077, 0,
                             "contact book is group/other-readable (mode %o)" % mode)
        finally:
            os.umask(old_umask)

    @unittest.skipIf(os.name == "nt", "POSIX permissions only")
    def test_contacts_file_is_0600(self):
        p = os.path.join(self.d, "contacts.json")
        c = Contacts(p)
        c.add("alice", "a.onion")
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)

    def test_write_secret_is_atomic_on_failure(self):
        """A failed write must leave the PREVIOUS file intact, never a truncated one."""
        path = os.path.join(self.d, "k.key")
        identity.write_secret(path, b"A" * 32)
        with patch("os.fsync", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                identity.write_secret(path, b"B" * 32)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"A" * 32, "old key was destroyed by a failed write")
        leftovers = [n for n in os.listdir(self.d) if n.startswith(".tmp-")]
        self.assertEqual(leftovers, [], "temp file left behind: %s" % leftovers)


class TestCorruptionRecovery(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_zero_byte_key_is_regenerated(self):
        """0 bytes = an interrupted create. Nothing was ever there, so redo it."""
        path = os.path.join(self.d, "crypto_identity.key")
        open(path, "wb").close()
        key = identity.load_or_create_x25519(self.d)
        self.assertEqual(len(bytes(key)), 32)

    def test_truncated_key_is_quarantined_not_silently_rotated(self):
        """
        A half-written key must NOT be silently replaced: that would change the
        safety number and quietly break everyone who verified you.
        """
        path = os.path.join(self.d, "crypto_identity.key")
        with open(path, "wb") as f:
            f.write(b"\x01" * 17)
        with self.assertRaises(SystemExit):
            identity.load_or_create_x25519(self.d)
        self.assertTrue(os.path.exists(path + ".corrupt"), "damaged key was not preserved")

    def test_corrupt_contacts_json_does_not_crash_startup(self):
        p = os.path.join(self.d, "contacts.json")
        with open(p, "w") as f:
            f.write("{not valid json")
        c = Contacts(p)                       # must not raise
        self.assertEqual(c.all(), {})
        self.assertTrue(os.path.exists(p + ".corrupt"), "bad file was not kept for recovery")

    def test_interrupted_save_does_not_destroy_contacts(self):
        p = os.path.join(self.d, "contacts.json")
        c = Contacts(p)
        c.add("alice", "a.onion")
        c.add("bob", "b.onion")
        c.data["carol"] = {"address": "c.onion"}
        with patch("json.dump", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                c.save()
        with open(p) as f:
            still_there = json.load(f)
        self.assertIn("alice", still_there)
        self.assertIn("bob", still_there)      # the old book survived the failed write


class TestHandshakeDeadline(unittest.TestCase):
    """
    settimeout() is PER-recv. A peer dribbling one byte at a time resets it
    forever, so the handshake needs a wall-clock deadline it cannot refresh.
    """

    def test_recv_exact_honours_wall_clock_deadline(self):
        a, b = socket.socketpair()
        stop = threading.Event()

        def dribble():
            # one byte at a time, slower than the deadline we set
            for _ in range(96):
                if stop.is_set():
                    return
                try:
                    b.sendall(b"\x00")
                except OSError:
                    return
                time.sleep(0.05)

        t = threading.Thread(target=dribble, daemon=True)
        t.start()
        try:
            started = time.monotonic()
            got = crypto._recv_exact(a, 96, deadline=time.monotonic() + 0.3)
            elapsed = time.monotonic() - started
            self.assertIsNone(got, "dribbling peer was allowed to stall us")
            self.assertLess(elapsed, 2.0, "deadline did not bound the whole read")
        finally:
            stop.set()
            a.close()
            b.close()

    def test_recv_exact_still_returns_data_within_deadline(self):
        a, b = socket.socketpair()
        try:
            b.sendall(b"hello world")
            self.assertEqual(crypto._recv_exact(a, 11, deadline=time.monotonic() + 5), b"hello world")
        finally:
            a.close()
            b.close()

    def test_no_deadline_keeps_old_blocking_behaviour(self):
        a, b = socket.socketpair()
        try:
            b.sendall(b"abc")
            self.assertEqual(crypto._recv_exact(a, 3), b"abc")
        finally:
            a.close()
            b.close()


if __name__ == "__main__":
    unittest.main()
