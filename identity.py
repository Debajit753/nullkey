"""
identity.py — your two persistent identities.

1. The ONION identity (Tor v3 service key). Saving it keeps your `.onion`
   address the SAME every run, so a contact can save it once and reach you.
2. The CRYPTO identity (a long-term X25519 key). Saving it makes your
   safety number STABLE, so "verified" means something across sessions.

Both files are created with 0600 permissions (owner read/write only) and written
ATOMICALLY. Guard them like passwords — they ARE your identity.
"""
import os
import tempfile
from nacl.public import PrivateKey

X25519_KEY_LEN = 32


def write_secret(path, data):
    """
    Write secret bytes to `path` atomically, never world-readable.

    Two things matter here and both are security-relevant:
      * The file is created 0600 FROM THE START. Writing first and chmod'ing
        after leaves a window where another local user can read your key.
      * The write goes to a temp file, is fsync'd, then renamed into place. A
        crash mid-write can then never leave a truncated key that bricks the
        account — you either get the old file or the new one, never a hybrid.
    `data` may be bytes or str.
    """
    if isinstance(data, str):
        data = data.encode()
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".part")
    try:
        try:
            os.fchmod(fd, 0o600)          # no-op/unsupported on Windows
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)             # atomic on POSIX and Windows
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _quarantine(path, why):
    """Move a damaged secret aside instead of deleting it, and explain."""
    backup = path + ".corrupt"
    try:
        os.replace(path, backup)
    except OSError:
        backup = path
    raise SystemExit(
        "\n  %s:\n    %s\n"
        "  It has been moved to:\n    %s\n"
        "  Nullkey will NOT silently generate a new identity — that would change your\n"
        "  safety number and quietly break every contact who verified you.\n"
        "  If you have a backup, restore it. Otherwise delete the .corrupt file and\n"
        "  restart to begin as a NEW identity (your contacts must re-verify you).\n"
        % (why, path, backup)
    )


def load_or_create_x25519(data_dir) -> PrivateKey:
    """Long-term X25519 key used for the message handshake + safety number."""
    path = os.path.join(data_dir, "crypto_identity.key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) == X25519_KEY_LEN:
            return PrivateKey(raw)
        if len(raw) == 0:
            # Zero bytes means a create was interrupted before any key material
            # was written — nothing was ever there to lose, so regenerating is safe.
            os.unlink(path)
        else:
            _quarantine(path, "Your identity key is corrupt (wrong size — %d bytes, expected %d)"
                              % (len(raw), X25519_KEY_LEN))
    key = PrivateKey.generate()
    write_secret(path, bytes(key))
    return key


def create_persistent_service(controller, data_dir, vport, local_port) -> str:
    """
    Create (or re-create) our onion service with a STABLE address.
    First run: Tor generates a key, we save it. Later runs: we hand the saved
    key back so the same .onion address comes up again.
    """
    key_path = os.path.join(data_dir, "onion_identity.key")
    if os.path.exists(key_path):
        with open(key_path) as f:
            blob = f.read().strip()
        if ":" not in blob:
            if not blob:
                os.unlink(key_path)       # interrupted create — safe to redo
            else:
                _quarantine(key_path, "Your onion identity key is corrupt (expected 'TYPE:KEY')")
        else:
            key_type, key_content = blob.split(":", 1)
            resp = controller.create_ephemeral_hidden_service(
                {vport: local_port},
                key_type=key_type,
                key_content=key_content,
                await_publication=True,
            )
            return resp.service_id + ".onion"

    resp = controller.create_ephemeral_hidden_service(
        {vport: local_port},
        key_type="NEW",
        key_content="ED25519-V3",
        await_publication=True,
    )
    write_secret(key_path, "%s:%s" % (resp.private_key_type, resp.private_key))
    return resp.service_id + ".onion"
