"""
contacts.py — a tiny JSON contact book.

Shape:  { "<name>": {"address": "<onion or host:port>",
                      "verified": false,
                      "pubkey": "<hex X25519 key, once verified>"} }

- `address`  is how you reach them (their onion, or host:port in local mode).
- `verified` becomes true once you've compared safety numbers out of band.
- `pubkey`   is remembered on verify so you recognize them next time (TOFU).
"""
import os
import json
import tempfile


class Contacts:
    def __init__(self, path):
        self.path = path
        self.data = {}
        self.load()

    def load(self):
        """Read the book. A damaged file is moved aside, never silently ignored."""
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (ValueError, OSError) as e:
            backup = self.path + ".corrupt"
            try:
                os.replace(self.path, backup)
            except OSError:
                backup = "(could not move it aside)"
            print("  ! contacts file was unreadable (%s)\n"
                  "    moved to: %s\n"
                  "    starting with an empty contact book." % (e, backup))
            self.data = {}
            return
        self.data = data if isinstance(data, dict) else {}

    def save(self):
        """
        Write the book ATOMICALLY, 0600, via temp-file + rename.

        A plain open(path,"w") truncates immediately, so a crash or a full disk
        mid-write used to leave an empty/half file — destroying every verified
        contact. With rename you always keep either the old book or the new one.
        """
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-contacts-")
        try:
            try:
                os.fchmod(fd, 0o600)        # no-op/unsupported on Windows
            except (AttributeError, OSError):
                pass
            with os.fdopen(fd, "w") as f:
                json.dump(self.data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def add(self, name, address):
        entry = self.data.get(name, {})
        entry["address"] = address
        entry.setdefault("verified", False)
        entry.setdefault("pubkey", None)
        self.data[name] = entry
        self.save()

    def get(self, name):
        return self.data.get(name)

    def all(self):
        return self.data

    def resolve(self, name_or_addr):
        """Accept a contact name OR a raw address. Returns (name_or_None, address)."""
        if name_or_addr in self.data:
            return name_or_addr, self.data[name_or_addr]["address"]
        for name, c in self.data.items():
            if c.get("address") == name_or_addr:
                return name, c["address"]
        return None, name_or_addr  # unknown name → treat the input as a raw address

    def set_verified(self, name, value=True):
        if name in self.data:
            self.data[name]["verified"] = value
            self.save()

    def set_pubkey(self, name, pubkey_hex):
        if name in self.data:
            self.data[name]["pubkey"] = pubkey_hex
            self.save()

    def find_by_pubkey(self, pubkey_hex):
        for name, c in self.data.items():
            if c.get("pubkey") == pubkey_hex:
                return name
        return None

    def delete(self, name):
        if name in self.data:
            del self.data[name]
            self.save()
            return True
        return False

    def clear_all(self):
        self.data = {}
        self.save()
