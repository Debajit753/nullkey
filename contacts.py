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


class Contacts:
    def __init__(self, path):
        self.path = path
        self.data = {}
        self.load()

    def load(self):
        if os.path.exists(self.path):
            with open(self.path) as f:
                self.data = json.load(f)

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)
        os.chmod(self.path, 0o600)

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
