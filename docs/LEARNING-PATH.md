# Nullkey — Learning Path

*A build-and-learn roadmap for a terminal, peer-to-peer, end-to-end-encrypted chat over Tor.*
Save this file as `LEARNING-PATH.md` next to your code (`chat.py`) and the design doc (`secure-messenger-prd.md`).

---

You already did the hard part: **Phase 0 works.** `chat.py` launches its own Tor instance, stands up a v3 onion service, does an X25519 key exchange with authenticated encryption (PyNaCl's `Box`), prints a safety number, and lets two people talk — over Tor or in a fast local test mode. That means you are not starting from a blank page. You are starting from *running code that already does the scary parts*, and everything below is about growing it into something you'd be proud to put your name on.

This path takes you from that prototype to a genuinely impressive, finishable project: a private messenger in the same family as **Briar, Cwtch, Ricochet-Refresh, and SimpleX** — real privacy software, built the way the real ones are built (don't invent crypto, don't invent Tor, do earn your forward secrecy).

**How to use this document — two rules that will save you months:**

1. **Learn foundations *just in time*, not all up front.** You do not need to "finish learning cryptography" before you build. Each phase names the two or three concepts it actually requires; learn *those*, ship the phase, move on. The Foundations track (§2) is a lookup table, not a prerequisite course.
2. **Build in vertical slices.** Never spend three weeks on a "crypto module" with nothing to run. Every phase ends in something you can *demonstrate* — two terminals talking, a test that goes green, a fuzzer that finds nothing. Keep `python3 chat.py testhost` / `testjoin` working at all times as your five-second smoke test. If a change breaks it, you know immediately.

Be honest with yourself as you go (§7): **no forward secrecy = not done**, use **libsodium** instead of hand-rolled crypto, get a **security review** before trusting it with anything real, and remember the **endpoint is the weakest link** — perfect crypto can't save a compromised laptop.

> **Want to build it entirely by hand — no AI writing your code?** That's the best way to actually learn. See **§8 — Build it yourself**: a repeatable coding method, a per-phase list of exactly what to write yourself, how to get unstuck without AI, and the reference shelf.

---

> ## ⚠️ Terminal, not Tor Browser — read this first
>
> **Nullkey runs in your terminal.** It is a standalone program that *uses the Tor network* (specifically, v3 onion services) as its transport. **You do not open it in Tor Browser.** Tor Browser is a web browser for visiting *websites*; Nullkey is not a website and there is no page to load.
>
> **The one-line analogy:** *The Tor network is a road. Tor Browser is one kind of car that drives on it (for browsing websites). Nullkey is a different vehicle — a terminal chat app — driving on the very same road.* Same network, completely different program.
>
> **The alternative we deliberately avoid — the "onion website":** You *could* build this as a normal web server sitting behind an onion address, where both people load a page in Tor Browser. Don't. That design puts a **central server in the middle** that sees every user and every message — a single trusted party and a metadata honeypot. Nullkey is **peer-to-peer**: each person *is* their own onion service, and messages are end-to-end encrypted so nothing in between can read them. (A desktop **GUI** is a fine *later* option — Phase 6+, built with Qt/PySide, still a native app, still not a browser.)

---

## 1. The map — phase overview

Rough time assumes a motivated student at roughly **8–10 hours/week**. Adjust to your life.

| Phase | Goal | Language | Rough time | Cut-line |
|---|---|---|---|---|
| **0 ✅ done** | Onion-service 1:1 chat, X25519 + authenticated encryption, safety number | Python | *(built)* | **MVP** |
| **1** | Robustness: both peers as onion services (symmetric), reconnect, a real terminal UI, config file | Python | 2–3 weeks | **MVP** |
| **2 ✅ done** | Real crypto: X3DH-style handshake + **Double Ratchet** (forward secrecy + post-compromise security) | Python | *(built — `ratchet.py`)* | **MVP** |
| **3 ✅ core done** | **The C++ core**: crypto primitives + frame parser in C++/libsodium, exposed via `pybind11`, byte-matching Python; ASan/UBSan + libFuzzer | **C/C++** | *(core built — `cpp/`)* | **MVP** — your headline |
| **4** | Local security: encrypt the message store with an **Argon2id** passphrase; disappearing messages | Python/C++ | 1–2 weeks | Stretch |
| **5 ✅ core** | Metadata hardening: fixed-size **padding** + **decoy traffic** (`--cover`) + **obfs4** bridge support (`--bridge`) | Python | *(built — `wire.py`)* | Stretch |
| **6+** | File transfer → group chat → desktop GUI (Qt/PySide) → mobile (separate project) | — | open-ended | Stretch |

**Phases 0–3 are the complete MVP** — a finishable, genuinely impressive class-project / portfolio scope. Phase 3 is the sentence that makes a résumé reviewer stop scrolling: *"I built the crypto core in C++."* Everything from Phase 4 on is real, valuable polish you add once the MVP stands on its own.

---

## 2. Foundations track — learn these *alongside* the build

Don't binge these up front. When a phase calls for a concept, spend a focused hour or two on it, then get back to building. Full links are in the [Resources appendix](#appendix-resources); this table tells you *what* to learn and *when*.

| Concept | Why you need it | First needed | The 1-hour version |
|---|---|---|---|
| **TCP sockets & length-prefixed framing** | Messages are just bytes on a socket; you already send a 4-byte length + payload (`send_frame`). Understand why. | You have it (Phase 0); deepen for Phase 1 | Beej's Guide — the "framing" idea |
| **Tor onion services (v3)** | Your address *is* a public key; there's no server. This is the whole trick behind "share a key without PGP." | Phase 0/1 | Tor Project "onion services" overview |
| **Concurrency: threads vs `asyncio`** | Chat must send and receive at once. Phase 0 uses threads; Phase 1's TUI wants `asyncio`. | Phase 1 | Python `asyncio` "coroutines & tasks" |
| **Symmetric vs asymmetric, AEAD, nonces** | Know *what* `Box` does: a DH key agreement feeding authenticated encryption, and why a nonce must never repeat. | Phase 0 → 2 | Crypto 101 (free book) |
| **Key exchange (Diffie-Hellman) & MAC vs signature** | X3DH is *four* DH operations; the ratchet is DH + KDF. You can't wield them blind. | Phase 2 | Signal X3DH spec, intro |
| **Forward secrecy (FS) vs post-compromise security (PCS)** | FS protects *yesterday's* messages after a key leak; PCS heals *tomorrow's*. PGP gives neither; the Double Ratchet gives both. This is *why* Phase 2 exists. | Phase 2 | Signal Double Ratchet spec, intro |
| **"Don't roll your own crypto"** | The #1 project-killer. You compose audited primitives (libsodium) and port audited protocols; you don't invent. | Always | libsodium intro |
| **C++ memory safety, sanitizers, fuzzing, constant-time** | In C++, safety is opt-in and permanent. ASan/UBSan + a fuzzer on the parser are non-negotiable. | Phase 3 | LLVM libFuzzer + ASan docs |
| **Foreign function interface (`pybind11`)** | How your C++ core becomes a Python module so the app keeps working while the internals get fast and hard. | Phase 3 | pybind11 "first steps" |
| **Threat modeling** | "Secure against *whom*?" Write down your adversary so you can tell done from not-done. | Phase 2/5 | PRD §4 (you already have one) |
| **Git, GitHub, CI** | Your proof-of-work and your safety net (tests + sanitizers on every push). | Phase 1 onward | GitHub Actions quickstart |

---

## 3. The phases

Every phase below uses the same shape: **Goal · What you'll learn · What to do · How to do it · Common pitfalls · Done when · Est. time · Resources.** The "Done when" line is a *demonstrable* checkpoint — if you can't show it, the phase isn't finished.

---

### Phase 0 — Onion-service 1:1 chat *(✅ already built)*

**Goal.** The smallest thing that actually works, so every later phase has running code to grow from. *This is done — this section is here so the path is complete and you know exactly what you're standing on.*

**What it already does.** `chat.py` (a) launches a private Tor instance via **stem**, (b) creates a **v3 ephemeral onion service**, (c) performs an **X25519 key exchange + authenticated encryption** with **PyNaCl** (`Box`, i.e. libsodium's `crypto_box`), (d) prints a **safety number** — a BLAKE2 hash of both public keys — to compare out of band, and (e) ships `host` / `join` real modes plus `testhost` / `testjoin` local modes.

**What you already learned.** Onion services, applied key exchange + AEAD, and *why the safety number exists*: encryption alone only guarantees "encrypted to somebody"; comparing the safety number on a **different channel** (a call, in person) is what upgrades that to "encrypted to the **right** somebody" and defeats a man-in-the-middle.

**Done when** *(already true).* Two terminals — `testhost` + `testjoin` locally, or `host` + `join` over Tor — establish an encrypted channel, print **matching** safety numbers, and exchange messages.

**Its honest limits (the to-do list for the rest of this path).** Static X25519 with **no forward secrecy**, **trust-on-first-use**, only the *joiner* dials the *host* (asymmetric), a bare readline UI, no persistence. Every one of those is a phase below.

**Resources:** *stem docs*, *PyNaCl docs*, *Tor onion services overview*.

---

### Phase 1 — Robustness: symmetric peers, reconnect, a real TUI, config

**Goal.** Turn the prototype into something that survives real use: either side can start the conversation, dropped connections recover, the screen doesn't get mangled when a message arrives while you're typing, and settings live in a file instead of command-line args.

**What you'll learn.** Persisting an onion identity (so your address is *stable*, not ephemeral), `asyncio` for reading and writing at the same time cleanly, terminal UI programming, and basic config/state management.

**What to do.**
- [ ] **Make identity persistent.** Save the onion private key so your `.onion` address stays the same across restarts (right now it's ephemeral and changes every run).
- [ ] **Make peers symmetric.** Each side runs its *own* onion service and can dial the other's — no fixed host/joiner roles.
- [ ] **Add reconnect.** When Tor or the socket drops, back off and retry instead of dying.
- [ ] **Build a TUI.** A scrolling message history above a fixed input line; incoming messages never clobber your half-typed text.
- [ ] **Add a config file + contacts file.** Your identity, your listen port, and a small list of saved contacts (nickname → onion address + their pinned public key).

**How to do it.**
- **Persistent onion key:** with **stem**, create the onion service with `await`/`create_ephemeral_hidden_service(..., key_type='NEW', key_content='ED25519-V3')`, then **save the returned `service_id` and private key** to disk (0600 perms). On next launch, pass the saved key back in as `key_content` so you get the same address. Keep it in your app data dir, not the repo.
- **Concurrency:** migrate the blocking `recv`/`send` threads to **`asyncio`** with `asyncio.open_connection` / `start_server`. To dial *out* through Tor, connect through Tor's **SOCKS5** proxy (that's what **PySocks** is for) to the peer's `<addr>.onion:5000`.
- **TUI:** use **`prompt_toolkit`** (great for a split "history + input line" chat and integrates with `asyncio`) or **`Textual`**/`Rich` if you want something more app-like. Keep your framing (`send_frame`/`recv_frame`) exactly as-is — the UI sits *on top* of the existing byte protocol.
- **Config:** a **TOML** file parsed with the stdlib **`tomllib`** (Python 3.11+) or a small JSON file. Store contacts as a separate file so you can pin each contact's public key on first verification (this is where trust-on-first-use becomes trust-*then*-remembered).
- **Reconnect:** wrap the connect loop with exponential backoff (`1s, 2s, 4s… cap at ~30s`) and surface "reconnecting…" in the TUI.

**Common pitfalls.**
- **Deadlocks in the handshake.** Two symmetric peers both trying to "read first" will hang. Keep a deterministic order (e.g. the dialer sends first), as `chat.py` already does for host vs joiner.
- **Leaking the onion key into git.** Add the key file and any `.tor-*` runtime dirs to `.gitignore` (you already ignore the runtime dirs).
- **Mixing threads and `asyncio`.** Pick one model for the network path; don't half-migrate.
- **UI redraw races.** Let the TUI library own the screen; never `print()` straight to stdout once you have a TUI.

**Done when.** Two people on two different machines each run the app with **no arguments**, it comes up on the **same address each time**, you add each other as saved contacts, either side starts the chat, you pull the Ethernet / toggle Wi-Fi and it **reconnects on its own**, and typing while a message arrives never corrupts your input line.

**Est. time.** 2–3 weeks.

**Resources:** *stem docs*, *Python `asyncio` docs*, *prompt_toolkit docs*, *Textual/Rich docs*, *PySocks*.

---

### Phase 2 — Real crypto: X3DH + the Double Ratchet

**Goal.** Replace the single static X25519 exchange with the modern messaging stack, so a stolen key **can't** decrypt past messages (forward secrecy) and the conversation **heals** after a compromise (post-compromise security). This is the phase that makes "secure" an honest word.

**What you'll learn.** The Signal messaging stack conceptually and in code: **X3DH** for the initial key agreement and the **Double Ratchet** for per-message key rotation — a DH ratchet (a fresh X25519 keypair as the conversation ping-pongs) plus symmetric send/receive KDF chains. You'll also learn *why* this beats PGP for chat: **PGP gives neither FS nor PCS; the ratchet gives both.**

**What to do.**
- [ ] **Understand the two layers** before writing anything: X3DH does the *first* agreement (four DH operations: identity, signed prekey, one-time prekey, ephemeral) and can message a peer who's momentarily offline; the Double Ratchet takes over for every message after.
- [ ] **Carry the prekey bundle in the contact-exchange blob.** You have no key server (that's the point), so the prekeys travel *inside* the invite/QR payload you already exchange out of band.
- [ ] **Implement the Double Ratchet** (or port an audited one) and run it *per message*.
- [ ] **Validate against test vectors** — known-answer tests, not "it looked encrypted."
- [ ] **Re-anchor the safety number** on the long-term identity keys (so verifying once still means something after keys rotate).

**How to do it.**
- **Don't build the ratchet from the paper.** Two honest Python paths: **(a)** use the maintained **`DoubleRatchet`** and **`X3DH`** PyPI packages (the `python-doubleratchet` / `python-x3dh` projects, the same ones behind Python OMEMO) as your implementation or a port target; or **(b)** implement straight from the **Signal X3DH and Double Ratchet specs** using primitives you already trust — **PyNaCl** for X25519, and **HKDF/HMAC** from **`cryptography`** (pyca) — and check every step against published vectors. Either way: **compose primitives, don't invent them.**
- **Simplest-correct alternative for the transport channel:** if you want the *channel* rock-solid first and the ratchet second, wrap the socket in a **Noise** handshake (the **`noiseprotocol` / dissononce** Python libraries) for a clean, audited-pattern secure channel, then run the Double Ratchet *inside* it. This mirrors what the PRD recommends and lets you ship a correct v1 channel before the full ratchet lands.
- **Nonce discipline:** whatever AEAD you use, a nonce must never repeat under a key. libsodium/PyNaCl's XChaCha20-Poly1305 has a 192-bit nonce specifically so **random nonces are safe** — prefer it and stop worrying about counters.
- **Keep the old code runnable.** Put the new stack behind the same interface the app already calls, so `testhost`/`testjoin` keep working while you swap the engine.

**Common pitfalls.**
- **Rolling your own ratchet from the whitepaper.** The single biggest way this class of project dies. Port or use an audited implementation; treat the spec as documentation, not a coding assignment.
- **Skipping test vectors.** "It encrypts and decrypts round-trip" proves almost nothing. Match published known-answer vectors for X25519, the AEAD, and the ratchet.
- **Losing skipped messages.** Out-of-order delivery is normal; handle the skipped-message-key cache the spec describes, and cap it so a peer can't exhaust your memory.
- **Calling it done without PCS.** Forward secrecy *and* post-compromise security — if a leaked key still decrypts future messages, the DH ratchet isn't actually turning.

**Done when.** You can demonstrate **forward secrecy**: capture some ciphertext, then reveal a peer's *current* key material, and show that the *earlier* messages **still can't be decrypted** — plus your test suite passes known-answer vectors for the primitives and the ratchet.

**Est. time.** 4–6 weeks. This is the conceptually hardest phase; budget for it and don't rush it.

**Resources:** *Signal X3DH spec*, *Signal Double Ratchet spec*, *`DoubleRatchet` + `X3DH` PyPI packages*, *Noise Protocol Framework*, *`cryptography` (pyca)*, *libsodium docs*, *Crypto 101*.

---

### Phase 3 — The C++ core *(the headline systems milestone)*

**Goal.** Reimplement the security-critical core — the crypto operations and the message framing/parsing — in **C++ with libsodium**, and expose it to your Python app through **`pybind11`** (or ship a standalone C++ client). This is where your systems skills show: constant-time discipline, memory hygiene, and a fuzzed parser. It's the milestone that turns a good student project into an interview magnet.

**What you'll learn.** Real-world C++ for security code: libsodium's API (X25519, Ed25519, XChaCha20-Poly1305, BLAKE2b/HKDF), the **mandatory safety harness** (AddressSanitizer + UndefinedBehaviorSanitizer, and **fuzzing** the byte parser), constant-time comparisons, explicit key zeroization, a CMake build, and binding native code to Python.

**What to do.**
- [ ] **Port the framing + crypto**, not the whole app. Keep the Tor/UI/config in Python; move only the security-critical bytes into C++.
- [ ] **Wrap it with `pybind11`** so `chat.py` imports it like any Python module — the app keeps working the whole time.
- [ ] **Stand up the safety harness in CI**: ASan + UBSan on every test build, a **libFuzzer** target on the message parser, plus a static analyzer.
- [ ] **Prove interop.** C++ encrypts a message, Python (Phase 2 code) decrypts it, and vice versa — bit-for-bit compatible.

**How to do it.**
- **Crypto:** use **libsodium** directly — `crypto_kx` / `crypto_scalarmult` for X25519, `crypto_sign` for Ed25519, `crypto_aead_xchacha20poly1305_ietf_*` (or `crypto_secretstream`) for AEAD, `crypto_generichash` for BLAKE2b, `crypto_pwhash` for Argon2 (Phase 4). Never OpenSSL low-level, never hand-rolled.
- **Memory & timing hygiene:** allocate secrets with `sodium_malloc`, wipe them with `sodium_memzero` the instant you're done, and compare secrets with `sodium_memcmp` / `crypto_verify_*` — **never `memcmp` on a secret** (it's a timing side channel).
- **Bindings:** **`pybind11`** (header-only, plays well with CMake). Expose a tiny, boring surface — `encrypt(state, plaintext) -> bytes`, `decrypt(state, ciphertext) -> bytes`, `parse_frame(bytes)` — and keep the ugly pointer work behind it.
- **Build:** **CMake** with two configs — a normal Release build and a **sanitized** build (`-fsanitize=address,undefined -fno-omit-frame-pointer`) that all tests run under.
- **Fuzzing:** write a **libFuzzer** harness (`LLVMFuzzerTestOneInput`) that feeds arbitrary bytes into your **frame parser / deserializer** — the exact code an attacker controls. Compile with `-fsanitize=fuzzer,address,undefined`, save a corpus, and run it in CI. Treat **any** sanitizer or fuzzer finding as **release-blocking**.
- **CI:** GitHub Actions job that builds the sanitized target, runs the unit + known-answer tests, and runs the fuzzer for a fixed number of seconds against the saved corpus.

**Common pitfalls.**
- **Skipping the sanitizers "for now."** In C++ safety is opt-in and permanent; a use-after-free in crypto code is a catastrophic bug you'll never spot by eye. ASan/UBSan from commit one.
- **Not fuzzing the parser.** The deserializer is your attack surface. An unfuzzed parser is an unproven parser.
- **`memcmp` on secrets / forgetting to zeroize.** Both are classic footguns libsodium exists to prevent — use its helpers.
- **Rewriting everything.** Port only the security-critical core; leave Tor, UI, and config in Python. Small surface, big payoff.
- **Byte-format drift.** If the C++ wire format doesn't exactly match the Python one, interop silently breaks — pin it with cross-language round-trip tests.

**Done when.** `chat.py` runs unmodified in behavior but its crypto/framing now come from your **C++ module**; the CI badge is green with **ASan + UBSan + fuzzer** all passing; and a C++-encrypted message decrypts correctly in Python and vice versa.

**Est. time.** 4–6 weeks.

**Resources:** *libsodium docs*, *pybind11 docs*, *LLVM libFuzzer guide*, *AddressSanitizer/UBSan docs*, *CMake docs*, *GitHub Actions docs*.

---

### Phase 4 — Local security: encrypted store + disappearing messages

**Goal.** Protect data *at rest*. Right now a lost or seized laptop hands over everything; after this phase, message history is encrypted under a passphrase, and messages can be set to auto-delete.

**What you'll learn.** Password-based key derivation with **Argon2id** (memory-hard, tuned so brute force is expensive), the "random data key wrapped by a passphrase-derived key" pattern (so changing your passphrase doesn't re-encrypt everything), auto-lock, and secure deletion semantics.

**What to do.**
- [ ] **Encrypt the whole local store.** Either an encrypted SQLite DB (**SQLCipher** via `pysqlcipher3`) or a single XChaCha20-Poly1305 file using libsodium's `crypto_secretstream`.
- [ ] **Derive the key with Argon2id** from the user's passphrase, and **wrap a random DB key** with it.
- [ ] **Auto-lock + zeroize.** Lock after inactivity or on exit; wipe the derived key and any plaintext from memory.
- [ ] **Disappearing messages.** A per-conversation TTL that deletes messages (both sides) after a timer.

**How to do it.**
- **Argon2id:** libsodium `crypto_pwhash` (or PyNaCl's `nacl.pwhash.argon2id`). This is a *passphrase unlock*, not a fast server login — turn the cost **up**: target roughly **256–512 MiB memory, t=3–4 iterations, p=1**, tuned to about **0.5–1 s** on your target hardware.
- **Key wrapping:** generate a **random** database key with the OS CSPRNG (`randombytes`), then encrypt it under the Argon2id-derived key. Changing the passphrase re-wraps that one small key instead of re-encrypting the whole database.
- **In-memory hygiene:** keep the derived key and plaintext only in locked memory; `sodium_memzero` on lock/exit (your Phase 3 C++ core makes this natural).
- **Disappearing messages:** store an `expires_at` per message; a background task deletes expired rows and tells the peer to do the same. Remember this is *cooperative* — it isn't DRM (see pitfalls).

**Common pitfalls.**
- **Weak KDF parameters.** OWASP's *login* floor is far too low for a device passphrase; go well above it (the numbers above).
- **Deriving the DB key directly from the passphrase.** Then the user can never change the passphrase without re-encrypting everything. Wrap a random key instead.
- **Thinking disappearing messages are guaranteed.** A determined peer can screenshot or log. It reduces incidental exposure; it does not defeat a hostile endpoint.
- **Leaving plaintext in swap or logs.** Never log plaintext; lock memory where you can.

**Done when.** A cold-started app requires the passphrase, opens history only when it's correct, **re-locks** after inactivity, and a message with a 60-second timer is gone from **both** ends after the timer — verified by inspecting the on-disk store and seeing only ciphertext.

**Est. time.** 1–2 weeks.

**Resources:** *libsodium docs (pwhash/secretstream)*, *SQLCipher docs*, *OWASP Password Storage Cheat Sheet*.

---

### Phase 5 — Metadata hardening: padding, cover traffic, pluggable transports

**Goal.** Resist *traffic analysis*. Content is already encrypted; now hide the **shape and existence** of your traffic — message sizes, timing, and even the fact that you're using Tor at all.

**What you'll learn.** Why metadata leaks (an observer counting bytes and timing packets learns a lot even without plaintext), fixed-size padding, cover/dummy traffic, and **pluggable transports** that disguise Tor itself.

**What to do.**
- [ ] **Pad messages to fixed size buckets** so length stops being a fingerprint.
- [ ] **Add cover traffic** — dummy messages on a schedule so "silence vs typing" isn't observable.
- [ ] **Enable a pluggable transport** (**obfs4**, **Snowflake**, or **WebTunnel**) so an ISP can't easily tell you're on Tor.
- [ ] *(Advanced)* **Elligator2-encode handshake ephemerals** so even your public keys look like random bytes on the wire.

**How to do it.**
- **Padding:** round every ciphertext up to the next bucket (e.g. 256 / 1024 / 4096 bytes) and strip the pad after decryption. Your Phase 3 framing is the natural place for this.
- **Cover traffic:** send indistinguishable dummy frames at randomized intervals; the receiver silently drops them. Understand the cost — it trades bandwidth/battery for unlinkability — and make it configurable.
- **Pluggable transports via stem/Tor:** configure your launched Tor with `ClientTransportPlugin` pointing at the transport binary (**`lyrebird`**/`obfs4proxy` for obfs4, `snowflake-client` for Snowflake) plus `Bridge` lines. obfs4 makes the stream look like random bytes; Snowflake looks like WebRTC; WebTunnel looks like HTTPS. Consider the **Vanguards** add-on to blunt guard-discovery attacks on your onion service.
- **Elligator2:** map raw X25519 ephemerals to indistinguishable-from-random strings (the same technique obfs4/lyrebird uses) so a handshake doesn't stick out. This is genuinely advanced — treat it as a stretch within a stretch.

**Common pitfalls.**
- **Padding that still leaks.** If your buckets are too fine-grained or you forget to pad control messages too, sizes still fingerprint you.
- **Cover traffic with a detectable rhythm.** Fixed intervals are their own signal; randomize.
- **Assuming a transport hides *everything*.** It hides *that Tor is in use* from a casual ISP; a well-resourced censor can still attempt statistical detection, and bridge availability varies.
- **Over-building.** This phase has diminishing returns for a learning project — do padding + one transport well before chasing Elligator2.

**Done when.** All messages leave the wire at a **fixed size**, a passive local observer can't distinguish "typing" from "idle," and your Tor connection runs through **obfs4 or Snowflake** such that a casual network observer can't trivially tell you're using Tor.

**Est. time.** 2–4 weeks.

**Resources:** *Tor pluggable transports docs*, *Snowflake docs*, *lyrebird/obfs4 repo*, *Vanguards*, *PRD §9 (metadata resistance)*.

---

### Phase 6+ — File transfer, group chat, GUI, mobile *(optional stretch)*

**Goal.** Grow features *after* the secure core is solid. Order them easiest-first so each is a satisfying, shippable win.

**What you'll learn.** Chunked binary transfer over the same encrypted channel; the genuinely hard jump from 1:1 to group cryptography; native GUI development; and cross-platform packaging.

**What to do / how.**
- **File transfer (easiest):** chunk the file, send chunks as framed messages through the *existing* ratchet, reassemble and verify a hash on the other end. Reuse everything; add a progress indicator in the TUI.
- **Group chat (hardest — respect it):** 1:1 crypto does **not** trivially extend to groups. Either fan out client-side (encrypt separately to each member — simple, doesn't scale) or adopt a real group protocol (**Sender Keys**, or **MLS** for large groups). Scope this deliberately; it's a project in itself.
- **Desktop GUI:** a native app with **Qt / PySide6** (or a C++ Qt front end onto your Phase 3 core). **Not** a web browser, **not** an onion website — same reasoning as the callout at the top: no central server, no page to load.
- **Mobile:** treat as a **separate project**. The crypto core (Phase 3 C++) can be reused, but the platform, packaging, and background-networking story are big enough to stand alone.

**Common pitfalls.** Trying group chat before the 1:1 core is audited; letting a GUI rewrite the security core (it should *call* the Phase 3 module, not reimplement it); scope-creeping mobile into the middle of the MVP.

**Done when.** Whichever you pick: a file arrives intact with a matching hash / three people hold a working encrypted group / a GUI drives the same secure core the terminal app uses — each demonstrable on its own.

**Est. time.** Open-ended — pick one, ship it, then decide on the next.

**Resources:** *MLS overview (RFC 9420)*, *Signal Sender Keys write-up*, *Qt for Python (PySide6) docs*.

---

## 4. Testing per phase

Testing isn't a phase you do at the end; it's the "Done when" of every phase made repeatable. Keep the fast local loop (`testhost`/`testjoin`) working *always* — it's your canary. Here's the specific test each phase should *add* to your suite; the crypto ones use **known-answer vectors**, not vibes.

| Phase | The test you add | What it proves |
|---|---|---|
| **0** | Round-trip: local encrypt→send→decrypt; both sides print the **same** safety number | The channel and MITM check work |
| **1** | Reconnect test (kill the socket mid-chat) and identity-stability test (same `.onion` after restart) | Robustness is real, not luck |
| **2** | **Known-answer vectors** for X25519 / AEAD / the ratchet, **plus a forward-secrecy test**: revealing a current key must **not** decrypt earlier captured ciphertext | The crypto is correct *and* forward-secret |
| **3** | Unit + KAT tests under **ASan/UBSan**; a **libFuzzer** target on the parser with a saved corpus; a **cross-language interop** test (C++ ⇄ Python) | The native core is memory-safe and byte-compatible |
| **4** | Inspect the on-disk store and assert it's **only ciphertext**; wrong passphrase is rejected; expired message is gone from both ends | Data at rest is actually protected |
| **5** | Assert all frames are a **fixed size**; a timing/size trace can't distinguish idle from active | Metadata is actually hidden |
| **6+** | File-hash-matches-after-transfer; group-member-can/can't-read as designed | The feature is correct, not just present |

**Wire all of this into CI (GitHub Actions).** Every push builds, runs the tests (Phase 3 onward: under sanitizers, plus a timed fuzz run), and updates the badge in your README. A red badge is a to-do; a green one is your proof-of-work.

---

## 5. Run, test & show it — the portfolio plan *(free, no hosting)*

The whole point of "build in vertical slices with a demonstrable checkpoint" is that at every stage you have *something to show*. None of this needs a server or a dollar:

- **GitHub repo, clean.** Push `nullkey/` with a tight README (yours is already good), this `LEARNING-PATH.md`, the PRD, tests, and CI config. Keep secrets out — the onion key file and `.tor-*` dirs stay `.gitignore`d. Tag releases per phase (`v0.1-phase1`, `v0.2-phase2`, …) so the history *is* the story.
- **A CI badge.** Add the GitHub Actions status badge to the top of the README. For Phase 3+, seeing "build passing" next to "ASan + UBSan + fuzz" tells a reviewer you build like a professional. Free.
- **An asciinema recording.** Record a real session with **asciinema** (`asciinema rec`) — two panes: verify the safety number, chat over Tor, reconnect, then show the on-disk store is ciphertext. Upload free to asciinema.org or convert to a GIF (`agg`) and embed it in the README. This is the single highest-leverage thing you can do; a 60-second cast is worth a thousand words of README.
- **A short write-up.** One page (a GitHub Pages / Markdown post — free): *the problem* ("share a key without it looking like PGP, without revealing you use such a system"), *the design* (you are your own onion service; out-of-band verification; the ratchet for FS/PCS), *the hard part* (the C++ core + fuzzing), and *the honest limits* (endpoint is the weak link; not audited). Honesty reads as competence.
- **Résumé framing.** One bullet, loaded with real substance:
  > *Built **Nullkey**, a peer-to-peer, end-to-end-encrypted terminal messenger over Tor v3 onion services (Python + C++). Implemented **X3DH + Double Ratchet** for forward secrecy and post-compromise security atop **libsodium**; wrote the crypto/framing **core in C++**, **fuzzed** it under ASan/UBSan in CI, and exposed it to Python via **pybind11**.*

  Every phrase in that sentence is something you actually did and can defend in an interview — which is exactly why this scope is worth finishing.

---

## 6. Study schedule & sequencing

A realistic ~one-semester plan at **8–10 hrs/week**. Weeks are a guide, not a whip.

| Weeks | Focus | Ship by end of block |
|---|---|---|
| **1** | Quick-start (§8): reread your own `chat.py`, get Tor working end-to-end, set up git + a trivial CI | Repo is public, CI is green on a hello-world test |
| **2–4** | **Phase 1** — persistent identity, symmetric peers, TUI, config, reconnect | Two machines auto-connect with stable addresses |
| **5–10** | **Phase 2** — X3DH + Double Ratchet, test vectors *(the long one — don't rush)* | Forward-secrecy test passes |
| **11–16** | **Phase 3** — C++ core, pybind11, sanitizers + fuzzer in CI | Green CI with ASan/UBSan/fuzz; C++⇄Python interop |
| **— MVP cut-line —** | **Stop here for a complete, impressive project.** Record the demo, write the post, ship. | A finished portfolio piece |
| **17–18** | **Phase 4** — encrypted store + disappearing messages *(stretch)* | On-disk store is ciphertext behind Argon2id |
| **19–22** | **Phase 5** — padding, cover traffic, one pluggable transport *(stretch)* | Fixed-size frames; Tor use disguised |
| **23+** | **Phase 6+** — pick one: file transfer → group → GUI *(stretch)* | One shipped feature |

**Momentum advice — the stuff that actually determines whether this gets finished:**
- **End every session with running code.** Never stop mid-refactor with a broken `testhost`. Commit while it's green.
- **One vertical slice at a time.** Resist "I'll build the whole crypto layer then wire it up." Small, working, committed — repeat.
- **The `testhost`/`testjoin` loop is sacred.** It's your five-second proof that nothing's on fire. Break it and you're flying blind.
- **The MVP cut-line is a real finish line, not a failure.** Phases 0–3 finished and demoed beats Phases 0–6 half-done, every time. Ship the MVP, *then* decide if you want the stretch phases.
- **When Phase 2 feels impossible,** remember: you're *porting audited work and checking it against vectors*, not inventing cryptography. That's a reading-and-wiring task, not a genius task.

---

## 7. Safety, ethics & don't-fool-yourself

This is legitimate, legal privacy software — the same family as Briar, Cwtch, Ricochet-Refresh, and SimpleX. Build it to learn and to protect privacy, not to harm or target anyone. And keep yourself honest about what it does and doesn't do:

- **Don't invent crypto (or Tor).** Compose **libsodium** primitives and **port audited protocols**. Rolling your own is the #1 way projects like this die quietly and insecurely.
- **No forward secrecy = not done.** Phase 0's static key is a *learning* prototype. Until the Double Ratchet (Phase 2) is in and its FS test passes, "secure" is not an honest word for it. Don't skip Phase 2 and call the rest secure.
- **In C++, safety is opt-in and permanent.** ASan + UBSan on every build and a **fuzzer** on the parser aren't optional extras — they're the price of admission. Any finding is release-blocking.
- **Never log plaintext.** Not to files, not to a console you forget to clean up, not to swap. Zeroize secrets.
- **The endpoint is the weakest link.** Perfect crypto over perfect Tor cannot save a keylogged or seized-while-unlocked laptop. Say so plainly in your write-up; overclaiming is the opposite of security-mindedness.
- **Trust-on-first-use needs the human step.** The safety number only protects you if someone actually reads it out on a different channel. Design the UI to make that the obvious thing to do, not an afterthought.
- **Get a security review before anyone trusts it for real.** You will have built something genuinely good — and it still shouldn't guard anything sensitive until someone qualified has looked. That caveat is a mark of maturity, not weakness.

---

## 8. Build it yourself — the no-AI method (how to code, what to code, references)

The fastest way to *have* this program is to let something write it for you. The fastest way to *become the person who can build it* is to write every line yourself. For a student, the skill is the whole point — so do it this way: **use docs, specs, and real open-source code as references, but never commit a line you can't explain.**

### What "without AI" should really mean

A purity contest helps no one. Professional engineers read documentation, read protocol specs, and read other people's source all day — that's not cheating, it's the job. The line that matters is *understanding*:

- **Green light:** official docs, the protocol specs, textbooks, and reading existing projects' source to see *how* they solved something.
- **Red light:** pasting any block — from AI, Stack Overflow, or a blog — that you couldn't rewrite from scratch and defend.
- **The one rule:** *never commit a line you can't explain to another person.* If you can explain it, you learned it.

(Middle path, if you want one: use an AI as a **tutor**, not an **author** — ask it to explain a concept, review code *you* wrote, or help read an error — but type every line of the program yourself. Your call; the rest of this section assumes you're doing the typing.)

### The loop — how to code any feature yourself

Repeat this for every feature, in every phase. It *is* the method:

1. **State the goal + a "done when," in one sentence.** E.g. *"Save my onion key to a file so my address survives a restart — done when I restart and print the same `.onion`."*
2. **Find the primitive in the docs.** One focused search in the *official* reference ("stem persistent onion service", "libsodium xchacha20poly1305", "pybind11 class"). Read the real API page, not a blog.
3. **Spike it in isolation.** Write a ~10-line throwaway script that does *only* that one thing. Get it working alone, where there's nothing else to blame.
4. **Prove it with a tiny test.** A `print`, an `assert`, or a unit test. See it pass.
5. **Wire it into `chat.py`,** then immediately run `testhost`/`testjoin` — your five-second smoke test.
6. **Commit.** Small commit, honest message. Next feature.

Spikes are the secret. Most "I'm stuck" is really "I'm debugging five things at once." A 10-line spike has exactly one.

### What to code yourself — the per-phase shopping list

This tells you *what* to build and *where the answer lives* — deliberately **not** the code. Writing it is the exercise.

**Phase 1 — robustness**
- `identity.py` → `load_or_create_identity()`: first run, create a v3 onion service and **save its private key** to a file (permissions `600`); later runs, load it so your `.onion` stays the same. *Look at:* stem's `create_ephemeral_hidden_service` (`key_type` / `key_content` params + the returned key), Tor `control-spec` `ADD_ONION`.
- `contacts.py` → a tiny JSON store: `add_contact(name, onion)`, `mark_verified(name)`, `load()/save()`. Per contact: name, onion, `verified: bool`.
- `net.py` → `connect_with_retry(onion, attempts, backoff)`: dial through Tor's SOCKS with retries + growing delays.
- A **TUI input line** so incoming messages don't scramble your typing. *Look at:* `prompt_toolkit` → `PromptSession` + `patch_stdout()`. (Skip full-screen `Textual` for now — that's gold-plating.)
- *Done when:* you restart and your address is unchanged, a saved contact can reach you, and typing stays clean while messages arrive.

**Phase 2 — real crypto (X3DH + Double Ratchet)**
- **Read the two specs first** (short and readable): Signal **X3DH** and **Double Ratchet**. Note the state each side keeps.
- `x3dh.py` → the initial agreement: identity key, signed prekey, one-time prekeys, the 3–4 DH combine. *Primitives:* libsodium `crypto_scalarmult` (X25519), `crypto_sign` (Ed25519), an HKDF.
- `ratchet.py` → a `Ratchet` class: `encrypt(plaintext) -> wire`, `decrypt(wire) -> plaintext`, managing the root key, sending/receiving chain keys, the DH-ratchet step, per-message keys, and a store for **skipped** keys (out-of-order messages).
- **The one place not to freestyle:** implement against **published test vectors** and check every step, or study a maintained library (search `python-doubleratchet`) and re-implement *with understanding*. A ratchet that "seems to work" but is subtly wrong gives you **zero** of the security you think it does.
- *Done when:* two sessions exchange messages, and after you *simulate a key leak* you can show older messages stay unreadable (forward secrecy — the whole point of this phase).

**Phase 3 — the C++ core**
- `crypto_core.cpp/.hpp` → a class mirroring the Python crypto: keypair gen, shared-key agreement, AEAD encrypt/decrypt, the BLAKE2b safety number, and the length-prefixed **frame parser**. *Primitives (libsodium):* `crypto_kx_keypair`, `crypto_kx_client/server_session_keys`, `crypto_aead_xchacha20poly1305_ietf_encrypt/decrypt`, `crypto_generichash` (BLAKE2b), `sodium_memzero`.
- `CMakeLists.txt` → build and link libsodium.
- `bindings.cpp` → expose the class to Python with **pybind11**, so `chat.py` imports your C++ module and *nothing else changes*. (Great test: swap the module in, run `testhost`/`testjoin`, everything still works.)
- **Non-negotiable harness:** build with `-fsanitize=address,undefined`, and write a **libFuzzer** target (`LLVMFuzzerTestOneInput`) that throws random bytes at your frame parser. In C++ one memory bug in that parser hands an attacker your keys — the fuzzer is how you sleep at night.
- *Done when:* the app runs on your C++ core, ASan/UBSan are clean, and the fuzzer runs an hour finding nothing.

### Getting unstuck without AI

When you hit a wall (you will — that's the learning), in order:

1. **Read the whole error,** then the docs for the *exact* function it names.
2. **Shrink to a minimal repro** — cut everything unrelated until ~10 lines still show the bug.
3. **Print the facts** — lengths, byte values, types. Most bugs are "the bytes weren't what I assumed."
4. **Read the source** — of the library, or a real project (Cwtch, ricochet-refresh, OnionShare). Reading working code is a superpower.
5. **Rubber-duck it** — explain the problem out loud, in full. You'll often solve it mid-sentence.
6. **Ask humans** with your minimal repro: Tor Stack Exchange, `r/crypto` / `r/cryptography` (for design questions), a project's chat/mailing list.

### Reference shelf (canonical, mostly free)

Lean on primary sources — they're more correct than blogs. (More in the [Resources appendix](#appendix-resources).)

- **Python:** docs.python.org — `socket`, `asyncio`, `struct`, `json`, `secrets`.
- **Networking:** *Beej's Guide to Network Programming* (free) — sockets & framing.
- **Tor / stem:** stem.torproject.org (tutorials + API); Tor "onion services" overview; the Tor `control-spec`.
- **Crypto (do):** libsodium docs (doc.libsodium.org) — your bible for Phase 3; the Signal **X3DH** and **Double Ratchet** specs for Phase 2.
- **Crypto (theory):** *Crypto 101* (free book); Dan Boneh's *Cryptography I* (Coursera, free to audit).
- **C++:** cppreference.com; *A Tour of C++* (Stroustrup); the CMake tutorial; **pybind11** docs; LLVM **libFuzzer** + sanitizers docs.
- **Read real code (don't copy):** Cwtch, ricochet-refresh, Briar, OnionShare, SimpleX — especially how each does **contact exchange**.

**The mindset:** you're not memorizing answers, you're learning to *find and understand* them. That loop — read the spec, spike it, test it, wire it in — is the real thing this project teaches, and it's worth far more than the chat app itself.

---

## 9. Your first week — start today

Small, concrete, do-it-now. The goal this week is **momentum**, not perfection.

- [ ] **Day 1 — Reread your own code.** Open `chat.py` and read it top to bottom. You wrote a length-prefixed framing protocol (`send_frame`/`recv_frame`), an X25519 handshake, and a BLAKE2 safety number. Understanding *your own* Phase 0 is the best crypto lesson available to you right now.
- [ ] **Day 1 — Run the fast loop.** In two terminals: `python3 chat.py testhost` and `python3 chat.py testjoin`. Watch the safety numbers match and send a message. This is the canary you'll protect for the rest of the project.
- [ ] **Day 2 — Go over Tor for real.** Install the Tor binary (`brew install tor` / `sudo apt install tor`), then `python3 chat.py host` on one machine and `python3 chat.py join <addr>.onion` on another (or a VM). It takes 10–60s the first time — that pause *is* Tor building a circuit. Read the safety number aloud to yourself and feel why the out-of-band step matters.
- [ ] **Day 3 — Version control + a heartbeat CI.** Push `nullkey/` to GitHub (secrets `.gitignore`d). Add a GitHub Actions workflow that just installs deps and runs one trivial test. Get the badge green. Now every future push is measured.
- [ ] **Day 4 — Write one real test.** A single automated test that runs the local handshake and asserts both sides produce the **same** safety number and a round-tripped message decrypts. Wire it into CI.
- [ ] **Day 5 — One hour of foundations, aimed at Phase 1.** Skim the `asyncio` "coroutines and tasks" page and the `prompt_toolkit` intro. Sketch (on paper) how a "scrolling history + fixed input line" TUI sits on top of your existing framing.
- [ ] **Day 6–7 — First Phase 1 slice.** Make the onion identity **persistent**: save the onion private key to disk and reload it so your `.onion` address survives a restart. That one change — a stable address you can hand out — is your first taste of turning a prototype into a tool. Commit it. You're building.

You have running code, a clear map, and a finish line that's genuinely worth reaching. Learn each concept the moment you need it, keep every change small enough to run, and let the green CI badge and the growing asciinema demo tell your story. Go build Nullkey.

---

## Appendix: Resources

All free unless noted. Grouped by area; deduped so each lives in exactly one place.

**Tor & onion services**
- **Tor Project — onion services overview** — how v3 onion services work; your address *is* a key — https://community.torproject.org/onion-services/
- **Tor pluggable transports** — obfs4 / Snowflake / WebTunnel, and how to configure them — https://tb-manual.torproject.org/circumvention/
- **Snowflake** — the WebRTC-looking transport — https://snowflake.torproject.org/
- **lyrebird / obfs4** — the obfs4 transport implementation — https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird
- **Vanguards add-on** — hardening onion services against guard-discovery — https://github.com/mikeperry-tor/vanguards

**Python libraries you'll use**
- **stem** — controls Tor, creates the onion service (already in your stack) — https://stem.torproject.org/
- **PySocks** — connect out through Tor's SOCKS proxy — https://github.com/Anorov/PySocks
- **PyNaCl** — libsodium bindings: X25519, AEAD, Argon2 (already in your stack) — https://pynacl.readthedocs.io/
- **cryptography (pyca)** — HKDF/HMAC and more, for the ratchet — https://cryptography.io/
- **DoubleRatchet (`python-doubleratchet`)** — maintained Double Ratchet implementation / port target — https://github.com/Syndace/python-doubleratchet
- **X3DH (`python-x3dh`)** — maintained X3DH implementation / port target — https://github.com/Syndace/python-x3dh
- **noiseprotocol / dissononce** — Noise handshakes in Python (simplest-correct channel) — https://pypi.org/project/noiseprotocol/
- **prompt_toolkit** — build the TUI (history + input line, asyncio-friendly) — https://python-prompt-toolkit.readthedocs.io/
- **Textual / Rich** — richer terminal UI, if you want an app-like feel — https://textual.textualize.io/
- **Python `asyncio` docs** — coroutines, tasks, streams — https://docs.python.org/3/library/asyncio.html

**Cryptography — learn the concepts**
- **Crypto 101** — free, beginner-friendly applied-crypto book — https://www.crypto101.io/
- **Signal — X3DH specification** — the initial key agreement — https://signal.org/docs/specifications/x3dh/
- **Signal — Double Ratchet specification** — per-message key rotation, FS + PCS — https://signal.org/docs/specifications/doubleratchet/
- **The Noise Protocol Framework** — clean, audited handshake patterns — https://noiseprotocol.org/
- **libsodium documentation** — the primitives, and the "don't roll your own" API — https://doc.libsodium.org/
- **A Graduate Course in Applied Cryptography (Boneh & Shoup)** — free PDF, deeper theory when you want it — https://toc.cryptobook.us/
- **OWASP Password Storage Cheat Sheet** — Argon2id parameter guidance (go above the login floor) — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

**C++ core, sanitizers & fuzzing (Phase 3)**
- **pybind11** — bind C++ to Python; header-only — https://pybind11.readthedocs.io/
- **LLVM libFuzzer** — coverage-guided fuzzing for your parser — https://llvm.org/docs/LibFuzzer.html
- **AddressSanitizer** — catch memory bugs at runtime — https://clang.llvm.org/docs/AddressSanitizer.html
- **UndefinedBehaviorSanitizer** — catch UB at runtime — https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
- **CMake documentation** — build the native core + sanitized configs — https://cmake.org/cmake/help/latest/

**Storage & local security (Phase 4)**
- **SQLCipher** — encrypted SQLite — https://www.zetetic.net/sqlcipher/
- **libsodium `crypto_secretstream` / `crypto_pwhash`** — file encryption + Argon2id (see libsodium docs above)

**Groups & GUI (Phase 6+)**
- **MLS — RFC 9420** — the modern group-messaging protocol — https://datatracker.ietf.org/doc/rfc9420/
- **Qt for Python (PySide6)** — native desktop GUI (not a browser) — https://doc.qt.io/qtforpython/

**Networking, tooling & showcase**
- **Beej's Guide to Network Programming** — sockets and framing, the classic free intro — https://beej.us/guide/bgnet/
- **GitHub Actions quickstart** — CI, tests, and your status badge — https://docs.github.com/actions/quickstart
- **asciinema** — record and share terminal sessions for your demo — https://asciinema.org/
- **agg (asciinema gif generator)** — turn a cast into an embeddable GIF — https://github.com/asciinema/agg

**Learn from the real ones (same family as Nullkey)**
- **Briar** — P2P encrypted messaging over Tor — https://briarproject.org/
- **Cwtch** — metadata-resistant P2P messaging — https://cwtch.im/
- **Ricochet-Refresh** — onion-service instant messaging — https://www.ricochetrefresh.net/
- **SimpleX Chat** — no-identifier private messaging — https://simplex.chat/

**Your own docs**
- **`secure-messenger-prd.md`** — the full design, threat model (§4), crypto design (§8), and metadata resistance (§9). This learning path is the *how-to-build*; the PRD is the *why*.
- **`nullkey/README.md`** — the student-scoped build plan and roadmap table this path expands on.
