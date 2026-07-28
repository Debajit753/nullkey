# Hardening pass — bugs found and fixed

> ⚠️ Still an educational, unaudited project. This pass fixed real defects, but a
> clean bug list is not an audit. See [SECURITY.md](SECURITY.md).

A multi-lens adversarial review of Nullkey (panic/account code, the ratchet + DoS
hardening, threading/sockets, storage, and the test suite) turned up 8 confirmed
defects. Every one is fixed below, and every fix is pinned by a test that **fails
if the fix is reverted** — verified by mutation testing, not assumed.

**Result:** 39 tests → **60 tests**, all passing on both the C++ and pure-Python
crypto backends.

---

## 1. `/panic` left the whole conversation in the terminal scrollback

**Severity: high.** `prompt_toolkit`'s `clear()` emits only `ESC[2J`, which clears
the *visible screen*. The scrollback buffer is `ESC[3J`. So after a panic wipe the
keys were gone but **Shift+PageUp recovered the entire plaintext conversation**,
your `.onion` address, the contact list, and the safety numbers.

**Fix** — `nullkey.py:_hard_clear()`:
- emit `ESC[3J` + `ESC[2J` + `ESC[H` (scrollback *and* screen),
- write straight to **fd 1** rather than through `print()`/`sys.stdout`, because
  `patch_stdout()` queues output on a background flush thread that could repaint
  text *after* the clear,
- exit via `os._exit(0)` so no `atexit` hook or daemon thread can run afterwards.

> **Still true, and documented:** clearing scrollback is terminal-dependent, and it
> cannot reach a terminal's *session logging* if you have that switched on.

## 2. `/panic` could silently do nothing and still report success

**Severity: medium** (needs an unusual filesystem state) **but fails open**, which
is the worst direction for a duress feature. Every delete was wrapped in
`except Exception: pass` plus `rmtree(ignore_errors=True)`, with no verification.
Reproduced: on a non-writable data dir, a **total no-op and a complete wipe produced
identical output** — screen clears, exit code 0 — while `crypto_identity.key` and
`contacts.json` remained byte-identical.

**Fix** — `_wipe_data_dir()` now **re-checks the filesystem afterwards** and returns
the list of survivors. If anything survived, `/panic`:
- does **not** clear the screen,
- prints the exact paths still on disk,
- exits with status **1**.

## 3. `/panic` only destroyed the active account · new `/panic-all`

Since `/account` made multiple identities normal, wiping only `self.data_dir` left
your other identities and their contacts intact.

**Fix** — scope is now explicit and predictable:

| Command | Destroys |
|---|---|
| `/panic` | **this** account only (siblings untouched) |
| `/panic-all` | **every** account in the folder |

`/panic-all` reuses `_find_accounts()`, so it only touches directories that
actually contain a `crypto_identity.key` — unrelated folders are left alone
(verified by test).

## 4. Secrets were unlinked, not overwritten

`os.remove` only drops the directory entry. **Fix:** `_shred_file()` overwrites the
bytes with random data and `fsync`s before unlinking.

> **Honest caveat, stated in the code and the docs:** on SSDs, journaling and
> copy-on-write filesystems the original blocks may still be recoverable — wear
> levelling means the drive decides where bytes physically land. This raises the
> bar against casual recovery; it is **not** a guarantee. Full-disk encryption is
> the real answer.

## 5. `/verify` silently rebound a contact's identity key

**This one quietly broke the core security promise.** If the key presented under a
saved name changed, `/verify` overwrote it with no warning — turning the safety
number into theatre, since a man-in-the-middle looks exactly like a reinstall.

**Fix** — a changed key is now **refused and loudly flagged**:

```
!!! IDENTITY KEY CHANGED for 'alice'
  The key saved under this name is NOT the key this peer is using.
  Expected only if they reinstalled or changed device.
  Otherwise it can mean a man-in-the-middle — check the safety number
  with them out of band (call them) BEFORE you accept it.
  To accept the new key anyway:  /verify alice force
```

Accepting requires the explicit `/verify <name> force`.

## 6. Race: an inbound peer could hijack the connection slot mid-dial

`_connect` released the lock before dialing, so for the *entire* dial (routinely
20–60 s over Tor, up to ~7 min with retries) `self.conn` was still `None` and the
slot looked free. An inbound peer could attach, and then `_attach` would silently
overwrite it when our dial landed — you'd see "connected to bob", start typing,
**and actually be talking to carol**, with bob's socket leaked.

**Fix:**
- a `self.dialing` flag, set under the lock for the whole dial, which the accept
  loop treats as busy;
- `_attach()` is now defensive — it refuses to overwrite a live connection, closes
  the losing socket, and returns `False` instead of orphaning it.

## 7. One silent connection could block *all* inbound connections

`settimeout(30)` is a **per-`recv()`** timeout, and `_recv_exact` loops on `recv`.
A peer dribbling one byte every 29 s reset the clock forever. Worse, the handshake
ran **inline on the accept thread**, so that single stalled connection parked the
whole accept loop — **for up to 48 minutes, at zero cost to the attacker** — and
every real contact saw you as offline.

**Fix:**
- `crypto._recv_exact(sock, n, deadline=...)` takes a **wall-clock deadline** the
  peer cannot refresh, threaded through `recv_frame` and `ratchet_handshake`;
- handshakes run on **short-lived worker threads**, so `accept()` returns
  immediately, capped by a `Semaphore(MAX_INFLIGHT_HANDSHAKES)` so the workers
  can't be exhausted either.

## 8. `/account` switch could attach a session built from the *old* identity key

A handshake already in flight during a switch completed with the **previous**
`self.priv` and attached — so the app showed the new account's banner and address
over a session authenticated as the old identity.

**Fix** — an epoch counter (`self._epoch`), bumped on every switch. Accept loops
and in-flight handshakes carry the epoch they started under and bail out if it
changed. `_switch_account` also now:
- **loads the new identity before tearing anything down**, so a failure leaves the
  current session working instead of a half-dead app with no listener;
- clears `peer_label` / `peer_pub` / `conn` / `ratchet`, so nothing leaks across
  identities.

---

## Also fixed

| Issue | Fix |
|---|---|
| Keys/contacts written world-readable, then `chmod`'d — a readable window | Created **0600 from the start** via `mkstemp` + `fchmod`, never `chmod`-after |
| A crash mid-save destroyed **every verified contact** (`open(...,"w")` truncates immediately) | **Atomic** temp-file + `fsync` + `os.replace` — you always keep the old book or the new one |
| A truncated key file **bricked the account** with a crash at startup | Zero-byte key (interrupted create) regenerates; a *damaged* key is **quarantined to `.corrupt`**, never silently rotated — silent rotation would change your safety number and quietly break everyone who verified you |
| Corrupt `contacts.json` crashed startup | Moved aside to `.corrupt`, start with an empty book, tell the user |
| `sendall` from 3 threads could splice frames together | A send lock (`App._send`) serializes writes |
| `_find_accounts()` crashed the app on an unreadable parent dir | Guarded `os.listdir` |

## Reviewed and found **correct** (no change needed)

Recorded so nobody re-checks them:

- **The ratchet is properly locked.** Every `encrypt`/`decrypt` — reader, `_say`,
  cover traffic, and the priming decoy — is inside `self.rlock`. No unlocked path exists.
- **The transport MAC is sound.** Initiator and responder derive byte-identical
  `mac_key`s, from an HKDF range independent of `SK`.
- **Both launchers work**, including from Finder and with a space in the project path.
- **Two review findings were refuted** by adversarial verification: the claimed
  `/account` "path traversal" (no trust boundary — only the person at the keyboard
  can type it, and `--data-dir` already does the same by design), and a claimed
  "276× CPU amplification" in the rate limiter (measured **1.18×** — the attacker
  pays essentially the same cost as the victim).

---

## Testing

```bash
make test          # 60 tests
```

The suite is **mutation-tested**: each fix was individually reverted and the suite
re-run to confirm a test actually fails. All 13 reverts were caught. Two checks
worth calling out, because a naive test passes either way:

- **the transient permission window** — write-then-`chmod` still *ends* at 0600, so
  checking the finished file proves nothing. The test records the mode **at the
  moment `chmod` is called**, under a cleared `umask`.
- **panic reporting** — the test asserts a **non-zero exit and no screen clear**
  when files survive, which is precisely what distinguishes a real wipe from a
  fake one.
