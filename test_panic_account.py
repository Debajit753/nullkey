"""
Tests for /panic and /account commands.
"""
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import nullkey
import identity


class TestPanicAccount(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.app_dir = os.path.join(self.test_dir, "peerA")
        os.makedirs(self.app_dir, exist_ok=True)
        # Create identity to make it a valid account
        self.priv = identity.load_or_create_x25519(self.app_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("sys.exit")
    @patch("nullkey.clear_screen")
    def test_panic_deletes_files(self, mock_clear, mock_exit):
        app = nullkey.App(self.app_dir, use_tor=False, idle=0)
        app.listener = MagicMock()
        app.conn = MagicMock()

        # Call panic
        app._command_panic()

        # Verify files are deleted
        self.assertFalse(os.path.exists(os.path.join(self.app_dir, "crypto_identity.key")))
        # Verify connection and listener are closed
        app.listener.close.assert_called_once()
        app.conn.close.assert_called_once()
        # Verify exit and clear screen were called
        mock_clear.assert_called_once()
        mock_exit.assert_called_once_with(0)

    def test_find_accounts_finds_them(self):
        # Create another account sibling
        peer_b_dir = os.path.join(self.test_dir, "peerB")
        os.makedirs(peer_b_dir, exist_ok=True)
        identity.load_or_create_x25519(peer_b_dir)

        # Create a non-account directory (no key)
        non_acc_dir = os.path.join(self.test_dir, "not_an_account")
        os.makedirs(non_acc_dir, exist_ok=True)

        app = nullkey.App(self.app_dir, use_tor=False, idle=0)
        accounts = app._find_accounts()

        # Should find peerA and peerB, but not not_an_account
        account_names = [name for name, path in accounts]
        self.assertIn("peerA", account_names)
        self.assertIn("peerB", account_names)
        self.assertNotIn("not_an_account", account_names)

    @patch("nullkey.clear_screen")
    def test_switch_account(self, mock_clear):
        peer_b_dir = os.path.join(self.test_dir, "peerB")
        os.makedirs(peer_b_dir, exist_ok=True)
        priv_b = identity.load_or_create_x25519(peer_b_dir)

        app = nullkey.App(self.app_dir, use_tor=False, idle=0)
        mock_listener = MagicMock()
        app.listener = mock_listener
        
        # Switch to peerB
        app._switch_account(peer_b_dir)

        # Verify data_dir is updated
        self.assertEqual(os.path.abspath(app.data_dir), os.path.abspath(peer_b_dir))
        # Verify new keys are loaded
        self.assertEqual(bytes(app.priv), bytes(priv_b))
        # Verify old listener was closed
        mock_listener.close.assert_called_once()
        # Verify new listener is set up
        self.assertIsNotNone(app.listener)
        self.assertNotEqual(app.listener, mock_listener)


if __name__ == "__main__":
    unittest.main()
