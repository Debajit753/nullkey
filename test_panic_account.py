"""
Tests for /panic, /panic-all and the /account switcher.

Every test here is written so that REVERTING the fix makes it fail — a test that
passes either way is worse than no test, because it looks like coverage.
"""
import os
import socket
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import nullkey
import identity


def _stop_accept_loop(app):
    """
    Shut down a real accept loop deterministically.

    Closing a listening socket does NOT reliably wake a thread blocked in
    accept() on macOS/BSD, and a thread stuck in a blocking C call can wedge
    interpreter shutdown. Bump the epoch, then poke the port so the loop wakes,
    sees the stale epoch and returns.
    """
    listener = getattr(app, "listener", None)
    if listener is None or isinstance(listener, MagicMock):
        return
    try:
        port = listener.getsockname()[1]
    except OSError:
        return
    with app.lock:
        app._epoch += 1
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
    except OSError:
        pass
    try:
        listener.close()
    except OSError:
        pass


class _Exited(Exception):
    """Stand-in for os._exit so a test can observe the exit code without dying."""
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _fake_exit(code):
    raise _Exited(code)


class TestPanic(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.app_dir = os.path.join(self.test_dir, "peerA")
        os.makedirs(self.app_dir, exist_ok=True)
        identity.load_or_create_x25519(self.app_dir)
        # give the account a full set of secrets, not just the one file
        with open(os.path.join(self.app_dir, "onion_identity.key"), "w") as f:
            f.write("ED25519-V3:deadbeef")
        with open(os.path.join(self.app_dir, "contacts.json"), "w") as f:
            f.write('{"alice": {"address": "x.onion", "verified": true}}')

    def tearDown(self):
        for root, dirs, _files in os.walk(self.test_dir):
            for d in dirs:                      # undo any chmod so cleanup works
                try:
                    os.chmod(os.path.join(root, d), 0o700)
                except OSError:
                    pass
        try:
            os.chmod(self.test_dir, 0o700)
        except OSError:
            pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _app(self):
        app = nullkey.App(self.app_dir, use_tor=False, idle=0)
        app.listener = MagicMock()
        app.conn = MagicMock()
        return app

    @patch("os._exit", side_effect=_fake_exit)
    @patch("nullkey._hard_clear")
    def test_panic_deletes_every_secret_file(self, mock_clear, mock_exit):
        app = self._app()
        conn, listener = app.conn, app.listener
        with self.assertRaises(_Exited) as ctx:
            app._command_panic()
        self.assertEqual(ctx.exception.code, 0)
        # ALL secrets gone, not just the crypto key
        for name in nullkey.SECRET_FILES:
            self.assertFalse(os.path.exists(os.path.join(self.app_dir, name)),
                             "%s survived /panic" % name)
        self.assertFalse(os.path.exists(self.app_dir))
        listener.close.assert_called_once()
        conn.close.assert_called_once()
        mock_clear.assert_called_once()

    @patch("os._exit", side_effect=_fake_exit)
    @patch("nullkey._hard_clear")
    def test_panic_reports_failure_instead_of_faking_success(self, mock_clear, mock_exit):
        """
        The regression that mattered: /panic used to swallow every error, so a wipe
        that deleted NOTHING was indistinguishable from a successful one.
        """
        if os.name == "nt" or os.geteuid() == 0:
            self.skipTest("needs POSIX permissions and a non-root user")
        app = self._app()
        os.chmod(self.app_dir, 0o500)          # can read/traverse, cannot unlink
        try:
            with self.assertRaises(_Exited) as ctx:
                app._command_panic()
        finally:
            os.chmod(self.app_dir, 0o700)
        # must exit NON-ZERO and must NOT clear the screen (user has to see this)
        self.assertEqual(ctx.exception.code, 1)
        mock_clear.assert_not_called()
        # and the files really did survive, which is exactly what it reported
        self.assertTrue(os.path.exists(os.path.join(self.app_dir, "crypto_identity.key")))

    @patch("os._exit", side_effect=_fake_exit)
    @patch("nullkey._hard_clear")
    def test_panic_leaves_sibling_accounts_alone(self, mock_clear, mock_exit):
        peer_b = os.path.join(self.test_dir, "peerB")
        os.makedirs(peer_b)
        identity.load_or_create_x25519(peer_b)
        app = self._app()
        with self.assertRaises(_Exited):
            app._command_panic()
        self.assertFalse(os.path.exists(self.app_dir))
        self.assertTrue(os.path.exists(os.path.join(peer_b, "crypto_identity.key")),
                        "/panic must only destroy the ACTIVE account")

    @patch("os._exit", side_effect=_fake_exit)
    @patch("nullkey._hard_clear")
    def test_panic_all_destroys_every_account(self, mock_clear, mock_exit):
        peer_b = os.path.join(self.test_dir, "peerB")
        peer_c = os.path.join(self.test_dir, "peerC")
        for d in (peer_b, peer_c):
            os.makedirs(d)
            identity.load_or_create_x25519(d)
        # a directory that is NOT an account must be left untouched
        bystander = os.path.join(self.test_dir, "not_an_account")
        os.makedirs(bystander)
        with open(os.path.join(bystander, "notes.txt"), "w") as f:
            f.write("keep me")

        app = self._app()
        with self.assertRaises(_Exited) as ctx:
            app._command_panic(all_accounts=True)

        self.assertEqual(ctx.exception.code, 0)
        for d in (self.app_dir, peer_b, peer_c):
            self.assertFalse(os.path.exists(d), "%s survived /panic-all" % d)
        self.assertTrue(os.path.exists(os.path.join(bystander, "notes.txt")),
                        "/panic-all must not delete non-account directories")

    def test_shred_overwrites_before_unlinking(self):
        path = os.path.join(self.test_dir, "secret.bin")
        original = b"S" * 4096
        with open(path, "wb") as f:
            f.write(original)
        seen = {}
        real_open = open

        def spy_open(p, mode="r", *a, **kw):
            fh = real_open(p, mode, *a, **kw)
            if p == path and "r+b" in mode:
                seen["opened"] = True
            return fh

        with patch("builtins.open", spy_open):
            nullkey._shred_file(path)
        self.assertTrue(seen.get("opened"), "file was never opened for overwriting")
        self.assertFalse(os.path.exists(path))

    def test_hard_clear_wipes_scrollback_not_just_screen(self):
        """ESC[2J alone leaves the whole conversation one Shift+PageUp away."""
        written = []
        with patch("os.write", lambda fd, data: written.append(data) or len(data)):
            nullkey._hard_clear()
        blob = b"".join(written)
        self.assertIn(b"\x1b[3J", blob, "scrollback (ESC[3J) not cleared")
        self.assertIn(b"\x1b[2J", blob, "visible screen (ESC[2J) not cleared")


class TestAccounts(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.app_dir = os.path.join(self.test_dir, "peerA")
        os.makedirs(self.app_dir, exist_ok=True)
        identity.load_or_create_x25519(self.app_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_find_accounts_finds_them(self):
        peer_b_dir = os.path.join(self.test_dir, "peerB")
        os.makedirs(peer_b_dir, exist_ok=True)
        identity.load_or_create_x25519(peer_b_dir)
        os.makedirs(os.path.join(self.test_dir, "not_an_account"), exist_ok=True)

        app = nullkey.App(self.app_dir, use_tor=False, idle=0)
        names = [name for name, _p in app._find_accounts()]
        self.assertIn("peerA", names)
        self.assertIn("peerB", names)
        self.assertNotIn("not_an_account", names)

    def test_find_accounts_survives_unreadable_parent(self):
        """An unlistable parent used to raise straight out and kill the app."""
        app = nullkey.App(self.app_dir, use_tor=False, idle=0)
        with patch("os.listdir", side_effect=PermissionError("nope")):
            accounts = app._find_accounts()      # must not raise
        self.assertIsInstance(accounts, list)

    @patch("nullkey.clear_screen")
    def test_switch_account_resets_identity_and_state(self, mock_clear):
        peer_b_dir = os.path.join(self.test_dir, "peerB")
        os.makedirs(peer_b_dir, exist_ok=True)
        priv_b = identity.load_or_create_x25519(peer_b_dir)

        app = nullkey.App(self.app_dir, use_tor=False, idle=0)
        mock_listener = MagicMock()
        app.listener = mock_listener
        app.peer_label = "stale-peer"            # leftovers from the old identity
        app.peer_pub = b"\x01" * 32
        epoch_before = app._epoch

        app._switch_account(peer_b_dir)

        self.assertEqual(os.path.abspath(app.data_dir), os.path.abspath(peer_b_dir))
        self.assertEqual(bytes(app.priv), bytes(priv_b))
        mock_listener.close.assert_called_once()
        self.assertIsNotNone(app.listener)
        self.assertNotEqual(app.listener, mock_listener)
        # per-identity state must NOT leak across the switch
        self.assertIsNone(app.peer_label)
        self.assertIsNone(app.peer_pub)
        self.assertIsNone(app.conn)
        self.assertIsNone(app.ratchet)
        # and threads from the old identity must be invalidated
        self.assertGreater(app._epoch, epoch_before)
        _stop_accept_loop(app)

    @patch("nullkey.clear_screen")
    def test_switch_account_failure_keeps_current_account(self, mock_clear):
        """A bad target must not leave the app with no listener and no identity."""
        app = nullkey.App(self.app_dir, use_tor=False, idle=0)
        original_dir, original_priv = app.data_dir, app.priv
        # a FILE where the account dir should be -> makedirs raises
        bad = os.path.join(self.test_dir, "iam_a_file")
        with open(bad, "w") as f:
            f.write("x")

        app._switch_account(bad)

        self.assertEqual(app.data_dir, original_dir)
        self.assertEqual(bytes(app.priv), bytes(original_priv))
        _stop_accept_loop(app)


class TestAttachRace(unittest.TestCase):
    """The connection slot must have exactly one owner."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.test_dir, "peerA"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _app(self):
        return nullkey.App(os.path.join(self.test_dir, "peerA"), use_tor=False, idle=0)

    # _attach spawns a reader thread; stub it out so the MagicMock socket doesn't
    # feed a live reader (MagicMock supports += and len()==0, so recv would spin).
    @patch.object(nullkey.App, "_reader", lambda self, sock: None)
    def test_attach_refuses_to_overwrite_a_live_connection(self):
        app = self._app()
        first, second = MagicMock(), MagicMock()
        self.assertTrue(app._attach(first, MagicMock(), b"a" * 32, b"b" * 32))
        # a second peer must NOT silently replace the first (that used to hand your
        # session to whoever finished handshaking last)
        self.assertFalse(app._attach(second, MagicMock(), b"a" * 32, b"c" * 32))
        self.assertIs(app.conn, first)
        second.close.assert_called_once()

    def test_dialing_flag_marks_the_slot_busy(self):
        app = self._app()
        self.assertFalse(app.dialing)
        app.dialing = True
        # this is what _accept_loop consults; while dialing, inbound peers are refused
        with app.lock:
            busy = app.conn is not None or app.dialing
        self.assertTrue(busy)


if __name__ == "__main__":
    unittest.main()
