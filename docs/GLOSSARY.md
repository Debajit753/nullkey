# Nullkey — Concepts, Processes & Glossary

A plain-language reference for **everything in this project**: how the moving parts work (processes), and what every term means (glossary). Read the "Big picture" and "Processes" first; use the "Glossary" as a lookup.

> ⚠️ **Educational, unaudited project** — self-implemented crypto, no security review. Don't use Nullkey to protect real secrets; use [Signal](https://signal.org). See [SECURITY.md](SECURITY.md).

---

## Big picture (in one breath)

Nullkey is a **terminal** chat app where two people talk **directly to each other over the Tor network** — no server, no account. Your address *is* your public key. Messages are encrypted end-to-end with a **Double Ratchet** (designed so a stolen key can't read old messages — though this is a from-scratch, unaudited implementation). It's built in Python, with the crypto primitives + the risky parser also written in C++ (libsodium) for speed and memory safety.

---

## Processes (how things actually happen)

### 1. Starting up — your identity
When you run the app it loads (or, first time, creates and saves) **two keys** in your data folder:
- an **onion service key** → your `.onion` address (your network identity), and
- a **long-term X25519 key** → your crypto identity (drives the safety number).
Both files are saved `0600` (only you can read them). It then starts a Tor onion service so you're reachable, and listens for connections.

### 2. Adding a contact (the "share your key" problem)
You give someone your `.onion` address **out of band** (in person, a QR code, a short string) and they run `/add <name> <address>`. Because the address *is* a key, there's no PGP block to leak — it just looks like a random string. Out-of-band sharing is also what stops a man-in-the-middle.

### 3. The handshake (X3DH-style, when you connect)
When A dials B, they run an **authenticated key agreement** before any message:
1. Each side sends its **identity public key**, a fresh **ephemeral public key**, and a fresh **ratchet public key**.
2. Both compute the same shared secret by mixing **three Diffie–Hellman results** — two that involve the long-term identity keys (that's the *authentication*) and one from the ephemerals (that's the *forward secrecy*).
3. That shared secret **seeds the Double Ratchet**.
(Code: `crypto.ratchet_handshake` → `ratchet.DoubleRatchet.init_*`.)

### 4. Verifying a contact (defeating MITM)
Both sides print a **safety number** (a hash of the two identity keys). You read it to each other on a *different* channel. Match = nobody's in the middle → `/verify <name>`. Different = stop. (Code: `crypto.safety_number`.)

### 5. Sending a message (encrypt path)
`your text` → the ratchet advances its **sending chain** by one step, producing a fresh **message key** → the text is encrypted with that key (AEAD) → wrapped in a **length-prefixed frame** with a small **header** → sent over the Tor socket. The message key is then thrown away. (Code: `ratchet.encrypt` + `crypto.send_frame`.)

### 6. Receiving a message (decrypt path)
Read one frame → split into header + ciphertext → if the header shows a **new ratchet key**, take a **DH ratchet step** (mix in fresh randomness) → advance the **receiving chain** to the right message number (storing keys for any **skipped/out-of-order** messages) → derive the one message key → decrypt (AEAD verifies it wasn't tampered with). If anything is wrong, the whole attempt is rolled back so a bad frame can't corrupt the session. (Code: `ratchet.decrypt` + `crypto.recv_frame`.)

### 7. The ratchet "turning" (why it's called a ratchet)
Every time the conversation changes direction (you reply), a brand-new key pair is generated and mixed in. Keys only ever move **forward** and old ones are deleted — you can't run it backwards. That's what gives **forward secrecy** and **post-compromise security**.

---

## Glossary

### Anonymity & network
- **Tor** — a network that routes your traffic through several relays so no single point sees both who you are and what you're doing.
- **Onion service (v3)** — a server reachable *inside* Tor at a `…​.onion` address, with no public IP and no exit node. Here, each user runs one; the address is derived from a key, so **the address is a public key**.
- **SOCKS proxy** — the local port Tor gives you to send connections *through* Tor. The app dials a contact's `.onion` through it (via `PySocks`).
- **Control port / `stem`** — Tor's admin channel; the `stem` Python library uses it to create your onion service.
- **Pluggable transport (obfs4 / Snowflake)** — disguises Tor traffic so a network watcher can't even tell you're using Tor (`--bridge`; needs `obfs4proxy`).
- **Padding** — making every message the same size (a fixed "bucket") so its length doesn't reveal how much you wrote. (`wire.py`, Phase 5.)
- **Cover / decoy traffic** — sending fake messages at random times so an observer can't tell *when* you're really typing; the receiver drops them (`--cover`).
- **Guard node** — the first Tor relay you connect to; it sees your IP but not your destination.
- **Metadata** — the "who talked to whom, when, how much" around a message. Encryption hides *content*; Tor + onion services hide most *metadata*.

### Cryptography — the building blocks
- **Symmetric vs asymmetric** — symmetric = one shared secret key encrypts & decrypts; asymmetric = a **public** key (shareable) + a **private** key (secret) that are mathematically linked.
- **Public / private key** — you share the public one; you guard the private one. Anyone can lock a box with your public key that only your private key opens.
- **X25519** — the specific elliptic-curve system used for **key agreement** (Diffie–Hellman). Fast, modern, safe defaults.
- **Ed25519** — the sibling used for **signatures** (proving "I wrote this"). Tor v3 onion addresses are Ed25519 keys.
- **Diffie–Hellman (DH / ECDH)** — a trick where two people who each have a key pair can compute the *same* shared secret without ever sending it. The heart of the handshake and the ratchet.
- **Ephemeral vs long-term key** — long-term = your identity, reused (authentication). Ephemeral = fresh per session/message, then deleted (forward secrecy).
- **AEAD (XChaCha20-Poly1305)** — "Authenticated Encryption with Associated Data": encrypts a message **and** produces a tag that detects any tampering. XChaCha20-Poly1305 is the specific fast, misuse-resistant AEAD used here.
- **Nonce** — a "number used once" fed to the cipher; reusing one with the same key is catastrophic, so each message gets a fresh key+nonce.
- **Tag / MAC** — the little authentication checksum AEAD adds; if the message is altered, the tag won't verify and decryption fails.
- **Hash (BLAKE2b, SHA-256)** — a one-way fingerprint of data. Same input → same fingerprint; you can't reverse it. Used for the safety number and inside KDFs.
- **KDF (Key Derivation Function)** — turns one secret into one or more keys in a one-way way. **HKDF** (built on **HMAC**) is the standard one; the ratchet's "root" and "chain" steps are KDFs.
- **Argon2id** — a deliberately-slow **password** hash (Phase 4) for turning a passphrase into a key to encrypt your local files, resistant to brute-force.

### Cryptography — the properties (what we're buying)
- **Forward secrecy** — if your keys are stolen *today*, messages from *yesterday* stay unreadable, because their one-time keys were already deleted.
- **Post-compromise security ("self-healing")** — after a temporary compromise, the conversation *recovers* its secrecy as fresh key material gets mixed in.
- **Authentication** — you're sure you're really talking to the intended person (not an impostor). Comes from the identity keys + the safety number.
- **Man-in-the-middle (MITM)** — an attacker who secretly sits between you and relays/alters messages. Defeated by comparing safety numbers out of band.
- **Trust-on-first-use (TOFU)** — you accept a contact's key the first time and remember it; you're warned if it ever changes.
- **Safety number / fingerprint** — a short, human-comparable hash of both identity keys. Same on both ends = no MITM.
- **Replay** — re-sending a captured message to fool the receiver. Rejected here because each message key is one-time.

### The protocol (Signal-style)
- **X3DH ("Extended Triple Diffie–Hellman")** — the handshake that agrees on the first shared secret using several DHs, mixing long-term (auth) + ephemeral (forward secrecy) keys.
- **Double Ratchet** — the algorithm that gives every message a fresh key: a **DH ratchet** (new key pair each turn) combined with **symmetric-key ratchets** (chains).
- **Root key** — the long-lived secret the DH ratchet keeps updating; it seeds each new chain.
- **Chain key** — advances once per message (one-way) to spit out message keys; there's a *sending* chain and a *receiving* chain.
- **Message key** — the actual one-time key that encrypts a single message, then is deleted.
- **DH ratchet step** — happens when you receive a message with a new ratchet public key: mix a fresh DH into the root key.
- **Skipped message keys** — if messages arrive out of order, the keys for the "gaps" are saved so those messages still decrypt when they show up.
- **Header** — the small unencrypted-but-authenticated part of each message: the sender's current ratchet public key + message counters.
- **Framing (length-prefix)** — putting a 4-byte length in front of each message so the receiver knows where it ends (TCP is a stream, not neat packets).

### Engineering, build & libraries
- **libsodium** — the audited C crypto library everything is built on. "Don't roll your own crypto" = use this.
- **PyNaCl** — the Python bindings to libsodium (what `ratchet.py`/`crypto.py` call).
- **`stem` / `PySocks` / `prompt_toolkit`** — Tor control / SOCKS dialing / the terminal input line.
- **pybind11** — the glue that lets C++ code be `import`ed from Python. The C++ core becomes the `nullkey_core` module.
- **`setup.py` (build_ext)** — compiles the C++ into that importable module.
- **CMake** — an alternative C++ build system (not used here; we build via `setup.py`). Mentioned because most C++ projects use it.

### Testing & security tooling
- **pytest** — the test runner; finds and runs every `test_*.py`.
- **Coverage** — how much of the code the tests actually execute (`pytest --cov`).
- **Parity test** — proves the C++ core produces the *exact same bytes* as the Python reference (`test_core_parity.py`). The real test of a port.
- **Property test** — checks a security *property* holds (e.g. "a stolen key can't read old messages"), not just that a function returns the right value (`test_security.py`).
- **Fuzzing** — throwing huge amounts of random/garbage input at a parser to find crashes. **atheris** (Python) / **libFuzzer** (C++) do it cleverly; `fuzz_parser.py` / `cpp/fuzz_frame.cpp` are the targets.
- **AddressSanitizer (ASan)** — a compiler tool that catches memory bugs (buffer overflows, use-after-free) at runtime. Critical for C++.
- **UBSan (UndefinedBehaviorSanitizer)** — catches undefined behavior (bad shifts, overflows) at runtime.
- **bandit** — scans Python code for insecure patterns (SAST = static analysis).
- **pip-audit** — checks your dependencies against known-vulnerability (CVE) databases.
- **detect-secrets / gitleaks** — scan for secrets (keys, tokens) accidentally committed to the repo.
- **Verifpal** — a tool to model the *protocol design* and check, against an active attacker, that it keeps secrets and authenticates. Tests the design, not the code (`nullkey.vp`).
- **CI (GitHub Actions)** — runs all the tests + scanners automatically on every push, so regressions are caught immediately (`.github/workflows/ci.yml`).
- **Threat model** — the written list of *which attackers* you defend against and which you don't. Every security choice should trace back to it (see the PRD).

---

## File-by-file

| File | What it does |
|---|---|
| `nullkey.py` | The Phase 1+ app: identity, contacts, connect, the terminal UI. |
| `chat.py` | The Phase 0 prototype (kept as a simple reference). |
| `crypto.py` | Framing, the safety number, and the `ratchet_handshake` (X3DH-style). |
| `ratchet.py` | The **Double Ratchet** (forward secrecy). |
| `identity.py` | Persistent onion key + long-term X25519 key. |
| `contacts.py` | The JSON contact book (address, verified, pubkey). |
| `net.py` | Tor launch (+ obfs4 bridges), SOCKS connect, retry logic. |
| `wire.py` | Phase 5 metadata layer: message **padding** (hide length) + REAL/DECOY types (`--cover`). |
| `cpp/core.cpp`,`core.hpp` | The C++/libsodium port of the primitives + parser. |
| `cpp/bindings.cpp`,`setup.py` | pybind11 → the `nullkey_core` Python module. |
| `cpp/asan_test.cpp`,`fuzz_frame.cpp` | Sanitizer + libFuzzer harnesses for the parser. |
| `test_*.py` | Functional, security, contacts, and C++ parity tests. |
| `fuzz_parser.py` | Python-side fuzzer for the parser. |
| `nullkey.vp` | Verifpal model of the handshake. |
| `Makefile` | One-word checks (`make test / sec / fuzz / core / parity / asan`). |
| `.github/workflows/ci.yml` | Runs everything on every push. |
| `secure-messenger-prd.md` | The full design doc (threat model, architecture, decisions). |
| `LEARNING-PATH.md` | The phase-by-phase curriculum. |
| `PROGRESS.md` | The running changelog. |
| `README.md` | Quick start. |

---

*This is a learning project. Passing every test here means "no obvious mistakes," not "provably secure." Real assurance needs a professional audit and, ideally, audited crypto libraries — see the PRD.*
