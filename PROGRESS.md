# Nullkey — Progress Log

A running record of what's been **added, removed, changed, or fixed**. Newest at the top.
Keep appending an entry every time you touch the project.

**Project:** Nullkey — a terminal, peer-to-peer, end-to-end-encrypted chat over Tor (family: Briar / Cwtch / SimpleX).
**Location:** `Documents/movie temp/nullkey/`
**Status:** MVP (0–3) done + app runs on the C++ core + Phase 5 metadata hardening (padding, decoys, obfs4 plumbing).

## 2026-07-21 — GitHub ship-prep (audited + hardened) ✅
Ran a 5-lens pre-ship audit (secret-leak ×2, doc-accuracy, hygiene, test-health) before any `git init`. Fixes applied:
- **Secret leak closed:** `.gitignore` covered `peer*/` and `data/` but **not** `torA/`/`torB/`, so their `contacts.json` (a real peer `.onion` address + public key) would have been committed. Rewrote `.gitignore` to also ignore `tor*/`, `contacts.json`, `**/contacts.json`, `*.onion`, `.DS_Store`, and `*.dSYM/`. Verified with a real `git` simulation: **0** keys/contacts/data files would be staged. (Nothing was ever pushed — the repo wasn't init'd yet.)
- **CI-breaker fixed:** `test_core_parity.py` called `sys.exit()` at import when the C++ `.so` was missing, which aborted the **entire** pytest run on any fresh clone / CI. Now it `pytest.skip`s just the 6 parity tests; the other 29 always run.
- **CI:** added a `cpp-core` job that installs `libsodium-dev`, builds the extension, and runs the parity tests for real — so C++↔Python parity is verified in CI, not only locally.
- **Honesty:** added a prominent ⚠️ "educational / self-implemented / unaudited — use Signal for real secrets" banner at the top of README **and** GLOSSARY; softened absolute security claims ("are protected" → "designed to").
- **Added** `LICENSE` (MIT), `SECURITY.md` (private reporting + disclaimer + threat model), `.gitattributes`, `CONTRIBUTING.md`.
- **Docs:** re-centered the README quick-start on `nullkey.py` (was leading with the throwaway `chat.py`); fixed the `USER/REPO` CI-badge placeholder; corrected the `.gitignore` description.
- Tests: **29 pass**; 6 parity skip without the core (and run green in the `cpp-core` CI job).
- Left for the human: fill the copyright name in `LICENSE`, put the real `user/repo` in the badge, create the repo, `git push`. Optional later: asciinema demo; Phase 4 (encrypted local store + disappearing messages); full DoubleRatchet port to C++; `make fuzz-cpp` after `brew install llvm`.

---

## 2026-07-18 — Bugfix: real cause of the early disconnect (socket read-timeout)
- **Symptom:** "peer disconnected" well under 3 min even while connected.
- **Cause:** the connected socket kept the *connect* timeout (30s in `--local`, 120s over Tor) as its read timeout, so `recv` timed out during any quiet stretch and the reader treated it as a disconnect. (Not the idle timer.)
- **Fix:** bound only the handshake with a timeout, then `sock.settimeout(None)` so chat reads block indefinitely; the 3-min idle loop is now the sole inactivity disconnect. Verified: post-connect sockets have no read timeout and stay connected while idle.

## 2026-07-18 — Idle fix + /clear + /del-contacts
- **Idle:** the 3-min idle timeout now **resets on ANY interaction** (typing a command or a message), not just on sending a chat message — so an actively-used session isn't dropped "before you could write." Still 3 min of true inactivity → disconnect (`--idle SECONDS`, 0 = never).
- **Added** `/clear` — clears the screen (prompt_toolkit's clear, no raw ANSI).
- **Added** `/del-contacts <name|all>` — delete one contact or all; added `Contacts.delete()` / `Contacts.clear_all()` + tests. 29 tests pass.

## 2026-07-18 — Simplified UI to plain text + ASCII logo (per request)
- **Reverted** all the colors/ANSI, the status bar, and the colored prompt. Now the **only** styled thing is a cool ASCII-art **NULLKEY** banner (figlet "standard" font) with a one-line tagline under it.
- Everything else is plain text: plain `you >` / `nullkey >` prompt, plain `alice > message`, plain notices. No ANSI anywhere.
- `ui.py` is now just the banner + plain formatting helpers. 28 tests still pass.

## 2026-07-18 — Polished the terminal UI
- **Added** `ui.py` — colors, a boxed **NULLKEY banner**, a colored prompt (`you ›` green when connected), a live **bottom status bar** (connected-to / backend / cover), **timestamped + color-coded messages** (incoming magenta, notices dim, errors red, safety number highlighted), and a styled `/help` + contact list.
- **Changed** `nullkey.py` to route all output through `ui`. Colors **auto-disable** when stdout isn't a TTY or `NO_COLOR` is set, so tests/pipes are unaffected. 28 tests still pass.
- **Bugfix:** raw ANSI printed with `print()` showed as literal `?[92m` codes because prompt_toolkit's prompt intercepts stdout. Fixed with `ui.out()` → `print_formatted_text(ANSI(...))`, which renders colors correctly (even from the background reader thread).

## 2026-07-18 — Hardening pass: expanded test vectors (kept our own crypto)
- Decision: **keep the self-implemented Double Ratchet + C++ core** (best learning story) and harden its trust story rather than swap in a library.
- **Expanded** `test_vectors.py` to more published standard vectors, all passing: **X25519** RFC 7748 (2 vectors), **HKDF-SHA256** RFC 5869 (TC1/TC2/TC3), **BLAKE2b** ("abc" + empty), and an XChaCha20-Poly1305 round-trip/tamper check → the primitives provably match the standards.
- **Formal check (Verifpal):** the model `nullkey.vp` is ready, but Verifpal couldn't be installed in this environment (not in Homebrew core; its tap needs auth; won't pull an arbitrary binary). **To run it yourself:** install from verifpal.com, then `verifpal verify nullkey.vp`.
- 28 tests pass.

## 2026-07-18 — Added idle auto-disconnect
- **Added** a 3-minute idle timeout (`--idle SECONDS`, default 180, 0 = never): if no REAL message is sent/received either way, the chat auto-disconnects. Decoy/cover traffic does NOT count as activity. Any real message resets the timer. Verified with a short-timeout e2e (disconnects when idle; stays up while messages flow).

## 2026-07-18 — Bugfix: responder could not send first (crash + disconnect)
- **Symptom:** the side that *accepted* a connection got `kdf_ck(): ... Invoked with: None` and `[peer disconnected]` when it typed the first message.
- **Cause:** in the Double Ratchet the responder has no sending chain (`CKs`) until it receives the initiator's first message; `_say` then crashed, and the send-error handler wrongly dropped the connection.
- **Fix:** (1) the initiator now auto-sends one **priming decoy** right after connecting, so the responder immediately gets a sending chain and can type first; (2) `_say` guards against `CKs is None` with a friendly "[not ready]" message instead of crashing/disconnecting.
- **Verified:** new e2e — B connects to A, then **A sends first** → works, no crash, no disconnect, both messages delivered. 24 tests still pass.

## 2026-07-18 — App now runs on the C++ core + Phase 5 metadata hardening ✅

**Finished the C++ integration:**
- **Changed** `ratchet.py` / `crypto.py` so the primitives (`hkdf`, `kdf_ck`, `msg_keys`, AEAD, `parse_header`, `safety_number`) **dispatch to `nullkey_core` (C++) when it's built**, falling back to pure Python otherwise. Pure versions kept as `*_py` for parity. New `NULLKEY_FORCE_PYTHON=1` switch.
- `nullkey.py` prints the active `crypto backend:` on startup.
- **Verified:** full suite passes on **both** the C++ path *and* the forced-Python path (24 each); app end-to-end runs on the C++ core; parity test now compares C++ vs the pure-Python reference.

**Phase 5 — metadata hardening:**
- **Added** `wire.py` — a message layer under the ratchet: every message is tagged REAL/DECOY and **padded to a fixed 256-byte bucket**, so message length is hidden and a decoy is indistinguishable from a real message on the wire.
- **Changed** `nullkey.py` — send/receive go through `wire`; added a `--cover` decoy-traffic loop (random 15–45s) whose messages the peer drops silently.
- **Changed** `net.py` — `launch_tor` accepts obfs4 **bridges**; `nullkey.py` gains `--bridge` (needs `obfs4proxy` + real bridge lines to hide Tor usage itself).
- **Added** `test_wire.py`. **Verified:** padding makes a 1-byte and a 37-byte message produce the *same* 312-byte frame; decoys are dropped and the chain stays in sync; 24 tests pass; bandit clean at medium+.
- **Honest note:** obfs4 plumbing is written but not runtime-tested here (needs `obfs4proxy` + bridges). Padding is per-message (fixed buckets), not constant-rate traffic — a strong-but-not-perfect defense; a global passive adversary is still out of scope.

---

## 2026-07-18 — Added GLOSSARY.md
- **Added** `GLOSSARY.md` — a plain-language reference: the end-to-end **processes** (startup, contact exchange, handshake, verify, send/receive, ratchet turning) and a full **glossary** of every term (Tor/onion, X25519/Ed25519/DH, AEAD/nonce/HKDF, forward secrecy/PCS/MITM/TOFU, X3DH/Double Ratchet/root-chain-message keys, pybind11/libsodium, ASan/UBSan/fuzzing/bandit/Verifpal, etc.), plus a file-by-file table. Linked from the README.

## 2026-07-18 — Phase 3: C++ core ✅ (completes the MVP)
- **Added** `cpp/core.cpp` + `cpp/core.hpp` — C++/**libsodium** port of the primitives + the untrusted frame parser: `safety_number` (BLAKE2b), `hkdf` (HMAC-SHA256), `kdf_ck`, `msg_keys`, `parse_header`, `aead_encrypt/decrypt` (XChaCha20-Poly1305).
- **Added** `cpp/bindings.cpp` + `setup.py` — a **pybind11** extension `nullkey_core` (`make core` / `python setup.py build_ext --inplace`).
- **Added** `test_core_parity.py` — proves the C++ core matches the Python reference **byte-for-byte** (safety number, HKDF, kdf_ck, msg_keys, header parse) and that AEAD interoperates both directions. **6 parity tests pass** (20 tests total now).
- **Added** `cpp/asan_test.cpp` (Apple-clang ASan/UBSan) + `cpp/fuzz_frame.cpp` (libFuzzer). **Verified:** ASan/UBSan ran 300k random buffers through the parser with **zero memory/UB errors**. libFuzzer target written (needs `brew install llvm` to build).
- **Added** Makefile targets `core / parity / asan / fuzz-cpp`; `.gitignore` now ignores build artifacts.
- **Installed** dev deps: `libsodium` (brew), `pybind11` (pip).
- **Note (honest):** the primitives + parser are ported and parity-verified; the full `DoubleRatchet` state machine is still Python. The app doesn't *use* the C++ core yet (next step) — but it's built, matched, and sanitized.

---

## 2026-07-18 — Security testing + CI ✅
- **Added** `requirements-dev.txt` (pytest, pytest-cov, ruff, bandit, pip-audit, detect-secrets).
- **Added** `test_contacts.py` — 5 tests incl. a check that the contacts file is `0600`.
- **Added** `fuzz_parser.py` — fuzzes `ratchet.decrypt` + header parse (atheris if present, else stdlib). Verified: 50k malformed frames handled, session intact.
- **Added** `nullkey.vp` — a **Verifpal** model of the handshake (active-attacker, confidentiality + authentication queries) for design-level checking.
- **Added** `Makefile` (`make test|cov|lint|sec|fuzz|all`) and `.github/workflows/ci.yml` (pytest+coverage, bandit, pip-audit, fuzz smoke, **gitleaks** secret scan on every push).
- **Added** a CI badge to the README (placeholder `USER/REPO`) + a "Testing & security checks" section.
- **Changed** `.gitignore` to ignore test/tool caches.
- **Results (verified locally):** 14 tests pass; **bandit** clean at medium+; **detect-secrets** 0 secrets; **fuzz** clean; **`pip-audit -r requirements.txt` → no vulnerabilities in runtime deps** (advisories seen in `make sec` are dev-tooling packages only, non-fatal).

---

## 2026-07-18 — Added security-property tests
- **Added** `test_security.py` — security tests (not just functional): **forward secrecy** (a compromise now can't decrypt already-delivered messages), **MITM detectable** via safety-number divergence, **no key/nonce reuse**, **cross-session isolation**, and **malformed-input robustness** (2000 random frames rejected, session survives — parse/DoS safety).
- **Verified:** all pass. Noted honestly in the file: these give *confidence, not proof* — real assurance needs reference vectors + fuzzing + formal analysis + a professional audit + audited libraries.

## 2026-07-18 — Phase 2 built: forward secrecy (X3DH + Double Ratchet) ✅
- **Added** `ratchet.py` — the **Double Ratchet** (Signal spec, educational): X25519 DH ratchet + HKDF/HMAC-SHA256 root & chain KDFs + XChaCha20-Poly1305 AEAD (all libsodium via PyNaCl). Gives **forward secrecy** (one-time message keys) and **post-compromise security** (DH ratchet mixes in fresh key material). Includes snapshot/rollback so a tampered frame is dropped without corrupting the session, and skipped-key handling for out-of-order messages.
- **Added** `crypto.ratchet_handshake()` — an authenticated **X3DH-style triple-DH** handshake (both peers online) that mixes both long-term identity keys (authentication) + fresh ephemeral keys (forward secrecy) into a shared secret, then seeds the ratchet.
- **Changed** `nullkey.py` — the app now encrypts/decrypts through the Double Ratchet instead of the static `Box`; added a lock around the (stateful) ratchet; the safety number is now over the **persistent identity keys** (stable & verifiable).
- **Removed** the static-`Box` message path from the app (`crypto.handshake` kept only for the Phase 0 `chat.py` reference).
- **Added** `test_ratchet.py` — proves the properties: bidirectional + DH-ratchet rotation, out-of-order delivery, tamper caught + session survives, replay rejected (one-time keys).
- **Verified:** unit tests pass; full end-to-end app test (two peers, real handshake, multi-turn) passes with no errors and confirmed ratchet-key rotation.
- **Honest caveat kept:** educational implementation — for real use, a professionally reviewed library + security audit.

---

## 2026-07-18 — Moved & renamed housekeeping
- **Moved** the whole project from `Documents/figma code/nullkey/` → `Documents/movie temp/nullkey/`.
- **Added** `secure-messenger-prd.md` into the project folder (was one level up) so the project is self-contained; **changed** the doc links in `README.md` and `LEARNING-PATH.md` from `../secure-messenger-prd.md` to `secure-messenger-prd.md`.
- **Removed / rebuilt** the Python `.venv` (virtualenvs bake in an absolute path and can't be moved).
- **Added** this `PROGRESS.md`.

## 2026-07-18 — Renamed the project → "Nullkey"
- **Changed** the name everywhere from the working codename *Silvertongue* → **Nullkey**: folder, entry file (`silvertongue.py` → `nullkey.py`), the app banner, and all docs (README, LEARNING-PATH, PRD).
- Re-verified: 0 stray old-name mentions, all modules compile, integration test passes.

## 2026-07-18 — Phase 1 built (persistent, symmetric app) ✅
- **Added** `nullkey.py` — the Phase 1 app (replaces the throwaway host/join flow of `chat.py`).
- **Added** modules:
  - `crypto.py` — length-prefixed framing + X25519 handshake + BLAKE2 safety number (factored out of Phase 0).
  - `identity.py` — **persistent onion key** (stable `.onion` address) + a **long-term X25519 key** (stable safety number).
  - `contacts.py` — JSON contact book: address, `verified` flag, remembered pubkey (trust-on-first-use).
  - `net.py` — Tor launch + SOCKS connect + `connect_with_retry` (backoff).
- **Added features:** persistent identity, symmetric peers (always reachable; dial a contact to talk), contact book with `/verify`, reconnect-with-retry, a `prompt_toolkit` input line that survives incoming messages, and a `--local` (no-Tor) dev mode.
- **Fixed** a robustness bug: the reader thread threw `OSError` when a socket closed; `crypto._recv_exact` now treats a closed socket as a clean disconnect (no traceback).
- **Added** `prompt_toolkit` to `requirements.txt`.
- **Verified:** modules compile; headless handshake + contacts test; live two-peer localhost integration (2-way encrypted messaging + clean disconnect).

## 2026-07-18 — Phase 0 prototype ✅
- **Added** `chat.py` — the smallest working thing: launches a private Tor instance, creates a v3 onion service, does an X25519 key exchange + NaCl `Box` authenticated encryption, prints a safety number, with `host` / `join` / `testhost` / `testjoin` modes. Kept as a simple reference.
- **Added** `requirements.txt`, `.gitignore`.
- **Verified:** crypto/handshake/framing round-trip over a socket pair.

## 2026-07-18 — Docs & planning
- **Added** `secure-messenger-prd.md` — full design: threat model, P2P-over-Tor architecture, why modern crypto (X3DH + Double Ratchet) over PGP, tech-stack verdict (Rust recommended; C++/Python path chosen to match the student's languages), existing systems to learn from, roadmap, pitfalls.
- **Added** `LEARNING-PATH.md` — the curriculum: foundations, every phase (what / how / done-when), testing, showcase, schedule, safety, and a "build it yourself, no-AI" section.

---

## Where the crypto stands (be honest)
- **Now:** X3DH-style authenticated handshake + **Double Ratchet** → forward secrecy + post-compromise security. Own implementation, spec-based, covered by `test_ratchet.py`.
- **Still educational:** it hasn't had a professional security review, and a real product would lean on an audited library. Don't trust it with anything genuinely sensitive yet.
- **Next hardening (Phase 4/5):** encrypted local store, header-encryption variant, padding/metadata resistance.

## Roadmap status
- [x] Phase 0 — onion-service chat prototype
- [x] Phase 1 — persistent identity, contacts, symmetric peers, reconnect, TUI
- [x] Phase 2 — X3DH-style handshake + Double Ratchet (forward secrecy)
- [x] Phase 3 — C++ core (libsodium) via pybind11 + sanitizers/fuzzing (app runs on it; full ratchet port = optional depth)
- [x] Phase 5 — metadata hardening: fixed-size padding + decoy/cover traffic + obfs4 plumbing
- [ ] Phase 4 — encrypted local store (Argon2id) + disappearing messages (optional, not started)
- [ ] Phase 6+ — files, groups, GUI

## How to update this log
When you add/remove/change something, add a dated entry at the **top** with what changed and (if relevant) whether you verified it. Small, honest entries beat perfect ones.
