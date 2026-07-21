"""
identity.py — your two persistent identities.

1. The ONION identity (Tor v3 service key). Saving it keeps your `.onion`
   address the SAME every run, so a contact can save it once and reach you.
2. The CRYPTO identity (a long-term X25519 key). Saving it makes your
   safety number STABLE, so "verified" means something across sessions.

Both files are written with 0600 permissions (owner read/write only).
Guard them like passwords — they ARE your identity.
"""
import os
from nacl.public import PrivateKey


def load_or_create_x25519(data_dir) -> PrivateKey:
    """Long-term X25519 key used for the message handshake + safety number."""
    path = os.path.join(data_dir, "crypto_identity.key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return PrivateKey(f.read())
    key = PrivateKey.generate()
    with open(path, "wb") as f:
        f.write(bytes(key))
    os.chmod(path, 0o600)
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
            key_type, key_content = f.read().strip().split(":", 1)
        resp = controller.create_ephemeral_hidden_service(
            {vport: local_port},
            key_type=key_type,
            key_content=key_content,
            await_publication=True,
        )
    else:
        resp = controller.create_ephemeral_hidden_service(
            {vport: local_port},
            key_type="NEW",
            key_content="ED25519-V3",
            await_publication=True,
        )
        with open(key_path, "w") as f:
            f.write("%s:%s" % (resp.private_key_type, resp.private_key))
        os.chmod(key_path, 0o600)
    return resp.service_id + ".onion"
