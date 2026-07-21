# Product Requirements Document: **Nullkey** — Private Peer-to-Peer Chat over Tor

*Version 1.0 (final) · 2026-07-14 · Author: (PM) · Builder: Debajit*

---

## 1. Vision

**Nullkey is a serverless, end-to-end-encrypted chat app where two people talk directly to each other over the Tor network — with no accounts, no phone numbers, no central server, and nothing that visibly announces "this is encryption software."** Each person's identity is just a Tor onion address, which doubles as their cryptographic key. To an outsider watching the network, there is no server to seize, no contact list to subpoena, and (with the right settings) not even a clear signal that Tor is being used at all.

It belongs to the same family as **Briar, Cwtch, Ricochet-Refresh, and SimpleX** — legitimate privacy tools built for journalists, activists, researchers, and ordinary privacy-conscious people. The feeling we want: *opening it should feel like slipping two notes under a door that only you and one other person share — quiet, direct, and forgettable.* This document is the buildable spec: architecture, crypto, stack, roadmap, and honest limits.

---

## 2. Answering your three questions first

Read this section, then the rest fills in the "how." These are the questions you actually asked.

### (a) "How do I give someone my public key without it looking like PGP — or revealing that I use this kind of system at all?"

**You don't hand over a PGP key. You hand over a Tor onion address, and that address *is* your public key.**

In this design your identity is a **Tor v3 onion service** — a 56-character string ending in `.onion` that is mathematically derived from an Ed25519 public key you control. Sharing your "public key" means sharing that address. There is no `-----BEGIN PGP PUBLIC KEY-----` banner, no armored blob, no key-server — just a random-looking string that reads like an obscure web address. Three layers make it deniable:

1. **The blob itself carries no crypto markers.** It's a bare onion address (or a QR code / short numeric string). Never wrap it in PGP armor, a custom `nullkey://` URI, or anything that self-labels as "secure messenger." If it needs to survive being pasted into an ordinary chat, it can be tucked inside a mundane-looking link or sentence (steganography — raises the cost for a *casual* observer, not a determined one).
2. **The exchange is out-of-band.** Show a QR code screen-to-screen, tap phones over NFC, or read a short string aloud on a call. This is both how you avoid a searchable "directory of crypto users" and how you defeat the one attack the network can't stop (someone swapping in a fake address — see §7).
3. **The wire looks like nothing.** All traffic is inside Tor and looks like generic encrypted bytes; the app's own records are indistinguishable from random. And if merely *using Tor* is itself incriminating in your context, you route Tor through a **pluggable transport** (obfs4 / Snowflake / WebTunnel) so even your ISP can't easily tell you're on Tor. That is the honest, complete answer to "will they know this person uses a crypto system?" — at the byte level, no; at the "is this person on Tor at all" level, only if you skip the pluggable-transport step.

**One caveat to internalize:** the network hides *content and metadata*, but you can still blow your own cover at the human layer — reusing a known handle, linking the address to your real name, EXIF in a photo. Crypto protects bytes, not operational discipline.

### (b) "I was thinking C++ — is that right, or something else?"

**Honest verdict: Rust is the better choice, and it's not close for this specific problem. C++ is viable but strictly more dangerous and more work to reach the same safety.**

Here's the reasoning, because it's a real security argument, not taste: in this app you spend all day parsing bytes an attacker sent you over the network. In C/C++ a *single* memory bug in that parser (a buffer overflow, a use-after-free) lets the attacker read your keys straight out of memory — silently defeating every cipher you carefully implemented. Historically, ~65–70% of critical security vulnerabilities in C/C++ software come from exactly this bug class. **Rust eliminates that entire class at compile time.** On top of that, Rust is where the whole ecosystem you need already lives: **Arti** (the Tor Project's own Rust implementation of Tor) lets you run your onion service *inside your app* with no separate process, plus audited crypto crates and mature async networking.

If you want to build in C++ because that's what you're learning, §10 gives you a real, complete C++ path — but with a **non-negotiable safety harness** (sanitizers + fuzzing + static analysis in CI) that you must run forever, because in C++ safety is opt-in and perpetual. **My recommendation: build the security core in Rust; treat this as the project where you *also* level up C++, not where you bet the security on it.**

### (c) The one-line "what to actually build"

> **A 1:1 text chat where each user is their own Tor v3 onion service; contacts are added by exchanging onion addresses out-of-band; messages are protected by a modern forward-secret ratchet (Noise + Double Ratchet, built on libsodium) — never PGP; written in Rust with Arti. Ship that, audited, before anything else.**

---

## 3. Goals & Non-Goals

### Goals
- **G1.** Two people exchange text messages with strong end-to-end encryption, forward secrecy, and post-compromise security.
- **G2.** No central server, no account, no phone/email. Identity = a self-generated onion address.
- **G3.** Hide *who talks to whom* from ISPs, network observers, and (because there is none) any seizable server.
- **G4.** Make the fact that crypto is in use non-obvious on the wire and at rest; optionally hide Tor use itself.
- **G5.** Encrypt everything at rest; make the app's presence and its contacts plausibly deniable within the limits crypto allows.
- **G6.** Be small, auditable, and buildable by one motivated developer, phase by phase.

### Non-Goals (for v1 — some are later phases, some are permanent)
- **N1.** Not a mass-market product; no growth features, telemetry, or ads. Ever.
- **N2.** No groups, files, voice/video, or mobile in v1 (groups and files are later phases; mobile is a separate project).
- **N3.** No reliable offline/asynchronous delivery in the pure-P2P MVP — both peers must be online at once (see §6, §17 for the async decision).
- **N4.** Not a defense against a **global passive adversary** who watches both endpoints, nor against a **compromised endpoint** (malware / seized unlocked device). These are permanent limits, stated honestly throughout.
- **N5.** No custom cryptography. We *use* vetted primitives and port from vetted implementations; we do not invent.

---

## 4. Threat Model & Adversaries

Write this table into the repo README. It decides every downstream choice. "Protect" = the design defends against it; "Can't" = out of scope or a fundamental limit.

| Adversary | What we protect against them | What we honestly can't |
|---|---|---|
| **Local network observer / ISP** | Can't see who you talk to or message content — only encrypted Tor traffic to a guard relay. With a pluggable transport, can't even tell it's Tor. | Without a pluggable transport, they can tell you're *using Tor* (not to whom). |
| **Central-server operator / subpoena / seizure** | Nothing to get — **there is no server**, no account, no stored contact graph or logs. | If you later add a store-and-forward mailbox for offline delivery, you reintroduce a server-shaped target (§6, §17). |
| **Single malicious Tor relay** | v3 descriptors are encrypted and addresses unguessable, so one hostile relay (HSDir / intro / rendezvous) learns very little. | A relay you happen to use as your **guard** sees your real IP (mitigated by Vanguards, §6). |
| **Active network MITM** | Onion address = the peer's public key, so an attacker can't impersonate an address without its private key. | Nothing — if they instead trick you into using the *wrong* address at contact-exchange time (§7). |
| **Global passive adversary (watches both ends)** | — | Can correlate timing/volume to link the two of you *without breaking encryption*. Fundamental limit of low-latency onion routing. Padding/cover traffic only raise the cost. |
| **Compromised endpoint (malware, keylogger, unlocked seized device)** | — | Reads plaintext as you do. No crypto helps. This is the real ceiling. |
| **Coercion / "rubber-hose" (compelled to unlock)** | Forward secrecy means past messages already deleted stay unreadable; panic-wipe / decoy profiles buy some plausibility. | Can't stop someone who compels the passphrase, especially under key-disclosure laws. |
| **Guard-discovery attacker (patient, runs relays)** | Full Vanguards make it hard to walk circuits toward your entry guard. | Given enough time + resources, still a structural risk for an always-on service (§6). |

**The one-sentence summary for users:** *Nullkey protects you against ISPs, seized servers, and local observers — not against a global surveillance apparatus watching both ends, and not against malware on your own device.*

---

## 5. Security & Design Goals

Concrete definitions so we can test against them.

| Property | What it means here | How we get it |
|---|---|---|
| **Confidentiality** | Only the two endpoints read messages. | AEAD (XChaCha20-Poly1305) under a ratcheted per-message key. |
| **Integrity / authenticity** | Messages can't be forged or tampered undetected. | AEAD tags + MAC-based (not signature-based) message auth. |
| **Authentication** | You're really talking to the holder of that onion key. | Onion address = Ed25519 identity; Noise handshake proves key control. |
| **Forward secrecy (FS)** | Compromising today's keys does **not** expose *yesterday's* messages. | Double Ratchet deletes each message key after use. |
| **Post-compromise security (PCS / "self-healing")** | After a key theft, the conversation *recovers* once both sides ratchet again. | Double Ratchet's DH ratchet injects fresh entropy each round-trip. |
| **Deniability** | A leaked transcript can't cryptographically *prove* who authored it. | MAC auth with shared/derived keys — never per-message signatures. |
| **Metadata resistance** | Hide who-talks-to-whom and when. | Tor onion services; no server; padding; optional cover traffic. |
| **Anonymity** | Hide network identity/IP; optionally hide Tor use. | Tor v3 onion services + Vanguards + optional pluggable transports. |
| **Indistinguishability** | Bytes on the wire / at rest look random. | No magic bytes/version fields; Elligator2-encoded handshake keys; fixed-size padded records. |

**FS vs PCS — they're different, keep them straight:** FS is about the *past* (old messages stay safe after a leak because their keys are gone). PCS is about the *future* (after a leak, the next DH exchange heals the channel so future messages are safe again). **PGP gives neither.** The Double Ratchet gives both. This single fact is why we don't use PGP for messages.

---

## 6. Architecture — Pure P2P over Tor v3 Onion Services

**Every user runs their own Tor v3 onion service inside the app.** A contact is nothing more than a 56-char `.onion` address + its identity key. To talk, A opens a Tor circuit to B's onion service and B does the same back. **No exit node is ever used** (onion-to-onion traffic never leaves Tor), and **there is no server, relay, or account in the middle.** This is the proven Ricochet-Refresh / Cwtch model.

```
        ┌─────────────────────┐                              ┌─────────────────────┐
        │  Alice's device     │                              │   Bob's device      │
        │                     │                              │                     │
        │  App (Rust)         │                              │  App (Rust)         │
        │  ├─ Chat UI         │                              │  ├─ Chat UI         │
        │  ├─ Double Ratchet  │   end-to-end encrypted        │  ├─ Double Ratchet  │
        │  ├─ Noise channel  ●┼───── message layer ─────────●┼─ Noise channel      │
        │  ├─ Encrypted store │   (indistinguishable bytes)   │  ├─ Encrypted store │
        │  └─ Arti (Tor)      │                              │  └─ Arti (Tor)      │
        │     ▼ onion svc     │                              │     ▼ onion svc     │
        └─────┼───────────────┘                              └───────────────┼─────┘
              │                                                              │
              │  ~3 hops                                            ~3 hops  │
              ▼                                                              ▼
        [Guard]→[Middle/Vanguard]→[Rendezvous Point]←[Middle/Vanguard]←[Guard]
                             ▲  the two circuits meet here  ▲
              Neither end learns the other's IP or guard. No plaintext anywhere on the path.
```

**How the connection actually forms (so you can implement/debug it):** B's onion service picks a few **Introduction Points** and publishes a *signed, encrypted* descriptor to the distributed HSDir ring. A fetches that descriptor (A must already know B's unguessable address), picks a **Rendezvous Point**, and asks B — via an intro point — to meet there. Both build ~3-hop circuits to the rendezvous, so the full path is ~6 hops. Neither side learns the other's IP or entry guard. Because v3 descriptors are encrypted and addresses are unguessable, hidden services **cannot be enumerated** — a real improvement over the dead/removed v2.

**Guard nodes & the top structural risk (guard discovery).** Your **entry guard** is the one relay that sees your real IP, so Tor keeps a small, stable guard set for months. Against a long-lived onion service, an adversary can repeatedly force circuit builds until one of *their* middle relays is chosen, narrowing toward your guard; compromise/coerce it and you're deanonymized. **Defense = Vanguards:** extra pinned layers of middle relays (Layer2 lifetime ~days, Layer3 ~hours) so the path can't be "walked" to your guard. **Enable Full Vanguards** — because each user runs an always-on service, Vanguards-Lite (Arti's default) isn't enough. Also consider running the service only while the user is online, to shrink the attack window.

### Tor integration: **Arti (Rust)** — recommended — vs C `tor` + control port

| | **Arti (`arti-client` crate)** ✅ recommended | C `tor` daemon + control port (fallback) |
|---|---|---|
| Language / safety | Memory-safe Rust, embeddable as a library, in-process | Large memory-unsafe C process you supervise |
| Onion services | Production-ready since **Arti 2.0 (LTS, early 2026)** | Mature, feature-complete (Briar/OnionShare use it) |
| Vanguards | Built in (Lite on by default; enable Full) | Available via the `vanguards` tooling |
| Operational cost | One crate, one process | Bundle + configure + supervise + update a daemon |
| When to use | Default for a new (Rust) build | Only if you hit a real Arti feature gap |

**Decision: embed Arti.** It removes an entire memory-unsafe process from your trusted computing base and ships modern guard protection. Keep C-tor in mind only as a documented fallback.

---

## 7. Identity, Contact Exchange & Key Management — *the core section (answers Q1 fully)*

This is the heart of your first question. Read it slowly.

### 7.1 Identity = the onion key

Each **profile** generates a Tor v3 onion service; its **Ed25519 key pair is the user's long-term identity.** The public **contact ID is literally the onion address** (56-char base32 + `.onion`, derived from that Ed25519 public key). **There is no separate PGP key to paste** — the address and the key are one object. Publishing the service and holding its private key already *proves* identity: reachability + authentication + key exchange collapse into a single step.

You can reuse this key for message crypto too: libsodium converts Ed25519 ↔ X25519 (`crypto_sign_ed25519_pk_to_curve25519`), so the same onion identity key can seed the Diffie-Hellman handshake. (For hygiene we still keep long-term identity keys separate from per-session message keys — see §8.)

### 7.2 Contact-exchange flow

1. **B shares B's contact ID out-of-band** (QR screen-to-screen = gold standard; NFC; a short read-aloud string; a stego link if remote).
2. **A opens A's Tor client, connects to B's onion service**, opens an auth channel, **proves control of A's own onion key** (signs the request), and sends: A's contact ID + optional nickname/intro line + signature.
3. **B sees an incoming request**, sees who it claims to be, and taps **Accept / Reject**. Reject can blacklist that key. Rate-limit + require-signature to blunt spam.
4. **On accept**, both store each other; future sessions auto-authenticate from the known keys (optionally a pre-shared random secret), and the messaging layer (§8) takes over.

Because B recomputes A's contact ID from the presented public key and verifies the signature, **B knows the request genuinely came from whoever controls that onion address.** A network MITM can't fake this — they'd need the private key.

### 7.3 The one attack the network *can't* stop: the ID-swap (human-layer MITM)

The onion tunnel stops network MITM. It does **not** stop someone who controls the channel you used to *share the address* from giving you *their* address instead of your friend's. If a hostile intermediary slips a fake ID into an email, you'll happily, securely authenticate — to the attacker.

**Defenses, in order of strength:**
- **Out-of-band exchange** (in person / QR / NFC / voice) — the attacker isn't sitting in that channel, so they can't substitute.
- **Safety-number / SAS verification** — derive a short, human-comparable fingerprint from *both* parties' identity keys and compare it out-of-band (read digits aloud, scan a QR). Matching numbers prove no swap occurred; a mismatch is a loud red flag. Copy **Signal's safety-number** model; do not invent your own comparison scheme.
- **TOFU by default** — trust the ID you were handed and pin it (like SSH host keys); **warn loudly if a known contact's fingerprint ever changes** (possible MITM or reinstall).

> **This is the single most important thing to hammer in the UI:** the math can't tell your real friend from an impostor who handed you a substituted key. Verification is the one manual step you cannot automate away.

### 7.4 Deniability & indistinguishability — three layers

1. **The exchanged blob** has *zero* crypto markers — a bare onion address that looks like a random web address. Never add PGP armor, headers, or a branded URI. Optional steganography (hide the ID in an innocuous sentence/image/link) defeats a *casual* observer only.
2. **The local database** is encrypted with a passphrase-derived key, and supports a **passwordless / plausibly-deniable profile mode** (as Cwtch does) plus optional **decoy profiles**, so possessing the app doesn't prove you have secret contacts, and a coerced user can reveal something innocuous.
3. **The wire** looks like generic random/TLS-ish bytes (Tor already does this); to hide *that Tor itself is in use*, route through **obfs4 / WebTunnel / Snowflake**.

### 7.5 Honest limits of deniability
- Can't hide Tor use from a network observer **unless** you add pluggable transports.
- Can't defeat an attacker who controls the out-of-band channel — only verification does.
- Can't survive endpoint compromise or forensic imaging of an unlocked device.
- **Can't beat legal compulsion / key-disclosure laws.** Decoy profiles raise cost; they are not a guarantee. Say this plainly to users.
- Steganography defeats casual observation, not a determined analyst.
- **Long-term onion-key compromise = permanent impersonation** until you rotate the key and re-verify with every contact. Support key rotation + re-verification, and keep long-term keys separate from message keys.

---

## 8. Cryptographic Design

### 8.1 Why NOT plain PGP/GPG for chat (put this in the PRD verbatim)

| PGP problem | Consequence | What we use instead |
|---|---|---|
| **No forward secrecy** | One long-term key leak decrypts *all* past intercepted messages. | Double Ratchet — per-message keys, deleted after use. |
| **No post-compromise security** | After a leak, no automatic recovery until you manually reissue keys. | DH ratchet self-heals each round-trip. |
| **Non-repudiable signatures** | Cryptographically *proves* you authored a message — dangerous for at-risk users. | MAC-based message auth = deniable. |
| **Key-management burden** | Fingerprints, keyservers, expiry, revocation — users get it wrong. | Onion address *is* the key; TOFU + safety numbers. |
| **Identifiable ciphertext** | `-----BEGIN PGP MESSAGE-----` armor + packet framing is trivially fingerprintable. | Indistinguishable-from-random wire format (§8.4). |

### 8.2 Recommended scheme — two layers

**Layer 1 — live transport channel: Noise Protocol Framework.** Because this is synchronous onion-to-onion P2P, run a **Noise handshake (pattern `XK` or `IK` over X25519)** to mutually authenticate the two onions and set up an encrypted channel. `XK` (initiator knows responder's static key ahead of time, e.g. from the onion identity; responder learns initiator's during the handshake) gives the initiator identity-hiding; `IK` is a clean 1-RTT option when both addresses are known. The peer's static key = the Ed25519 key embedded in the v3 onion address, converted to X25519. **For a first build, `snow` (the Noise crate) is the lowest-complexity correct path.**

**Layer 2 — message layer: X3DH + Double Ratchet (Signal stack).** Run the Double Ratchet *inside* the Noise channel so you also get long-term forward-secret **stored history** and a clean path to async delivery later.
- **X3DH (Extended Triple Diffie-Hellman)** does the *initial* key agreement — four X25519 DHs (identity, signed prekey, one-time prekey, ephemeral) — and lets you message a contact who is momentarily offline. In our serverless design the "prekey bundle" travels **inside the contact-exchange payload** (QR / invite blob), not a Signal-style key server.
- **Double Ratchet** rotates keys per message: a DH ratchet (new X25519 keypair as the conversation ping-pongs) + two symmetric KDF ratchets (send/receive chains). Fresh key per message; automatic rekey every round-trip; no manual key management ever.

> **Don't build the ratchet from the paper.** Port from / use an audited implementation: **`vodozemac`** (Matrix's audited pure-Rust Double Ratchet) if you want a Signal-style ratchet, or start with **`snow`** (Noise only) for the simplest correct v1 and add the ratchet next. In C++, port from **libsignal** rather than hand-writing.

### 8.3 Concrete primitive set (all in **libsodium** — the "don't roll your own crypto" decision)

| Purpose | Primitive | libsodium API |
|---|---|---|
| ECDH key agreement | **X25519** | `crypto_kx` / `crypto_scalarmult` |
| Signatures (identity/prekey binding **only**) | **Ed25519** | `crypto_sign` (+ `..._pk_to_curve25519` to reuse onion key) |
| AEAD (messages, framing) | **XChaCha20-Poly1305** | `crypto_aead_xchacha20poly1305` / `crypto_secretstream` |
| KDF / hashing (ratchet) | **BLAKE2b + HKDF** | `crypto_generichash` |
| Password → store key | **Argon2id** | `crypto_pwhash` |
| RNG | **OS CSPRNG** | libsodium `randombytes` (never a hand-rolled/seeded PRNG) |

**Why XChaCha20-Poly1305:** its 192-bit nonce makes **random nonces safe with no counter coordination** — libsodium explicitly recommends it when you don't need interop. `crypto_secretstream` manages nonces and adds tamper detection for you; prefer it for streams. Nonce reuse catastrophically breaks AEAD, so this choice removes a whole footgun.

### 8.4 Wire format: indistinguishable from random (the byte-level half of Q1)

1. **No plaintext markers** — zero magic bytes, version fields, or ASCII. A captured packet must look like uniform random bytes. AEAD ciphertext + random nonce already passes this.
2. **Elligator2-encode ephemeral public keys.** Raw X25519 public keys are curve points and *are* distinguishable from random — a fingerprint. **Elligator2** maps them to indistinguishable-from-random strings (the exact technique Tor's obfs4/lyrebird uses). Do this for every handshake ephemeral.
3. **Pad to fixed-size records** (e.g. bucket to 1 KB / 4 KB, echoing Tor's fixed 512-byte cells) so length leaks nothing.
4. **Optional cover/constant-rate sending** if the threat model includes timing analysis (§9).

### 8.5 Message/session flow to implement

1. **Bootstrap:** exchange identity pubkey + signed prekey + one-time prekeys (the prekey bundle) out-of-band via QR/invite (§7).
2. **First message:** sender runs X3DH → root key → sends header (Elligator-encoded ephemeral pubkey) + AEAD ciphertext.
3. **Ongoing:** each side runs the Double Ratchet — symmetric ratchet per message; DH ratchet whenever a new ephemeral pubkey arrives in a header.
4. **Rekeying:** automatic every round-trip. No manual rotation, ever.
5. **Out-of-order / dropped (Tor reorders!):** cache **bounded** skipped message keys (e.g. max 1000) so late/reordered packets still decrypt; include a per-message counter in the AEAD associated data and **reject already-seen counters** (replay defense). Keep the skipped-key cache small/short-lived to limit FS exposure.
6. **Key store:** persist identity + ratchet state encrypted with an Argon2id-derived key; `sodium_memzero` secrets after use.

### 8.6 Deniability as a *designed* feature
Authenticate messages with **derived-key MACs**, so either party *could* have forged a transcript (the OTR/Signal repudiability property). **Only** sign the long-term identity binding and prekeys with Ed25519. **Never sign individual chat messages** — that's the PGP instinct that destroys deniability and can endanger users.

### 8.7 Post-quantum (optional, forward-looking)
X25519/Ed25519 aren't quantum-safe; a "harvest now, decrypt later" adversary could store traffic today. If PQ is in scope, adopt a **hybrid X25519 + ML-KEM (Kyber)** agreement as SimpleX and Signal (PQXDH) already have. libsodium lacks ML-KEM, so add **liboqs** for the KEM half only. Defer unless the threat model demands it.

### 8.8 "If you insist on PGP" — a short honest note
If you truly must interoperate with PGP for *some* out-of-band artifact (e.g. signing a release, §15), fine — that's a static-signature use case. **But not for chat messages.** For chat, PGP gives no FS, no PCS, non-repudiation, and a fingerprintable wire format — every one of which is a direct hit against this project's core goals. There is no configuration of PGP that fixes these; the modern ratchet designs exist *because* PGP can't.

---

## 9. Metadata & Traffic-Analysis Resistance

Encryption hides *content*. Metadata — *who, when, how much* — is often the sensitive part. Layer defenses, and be honest about cost.

| Technique | What it buys | Cost / limit |
|---|---|---|
| **Tor v3 onion services** | Hides who-talks-to-whom from ISPs; no server graph to seize. | Latency; both peers online for pure P2P. |
| **No central server** | No push/directory service to reintroduce a central observer. | You lose easy offline delivery (§17 decision). |
| **Fixed-size padding** (do always) | Message length leaks nothing. | Tiny bandwidth overhead. Cheap — always on. |
| **Cover / decoy traffic** (opt-in "high-security" mode) | The *only* thing that meaningfully blunts timing correlation. | Constant bandwidth + battery drain; users disable it → make it opt-in, not default. Still not a full defense. |
| **Randomized send delays / jittered presence** | Reduces linkability from timing. | Trades latency for unlinkability. |
| **Vanguards (Full)** | Defends the guard against discovery. | Slightly less path diversity. |
| **Pluggable transports (obfs4 / Snowflake / WebTunnel)** | Hides *that Tor is in use* from a censoring ISP. obfs4 = random bytes; Snowflake = looks like WebRTC; WebTunnel = looks like HTTPS. | Extra setup; bridge availability; a resourced censor can still attempt statistical detection. |

**State plainly in the product:** none of these defeat a true **global passive adversary** who watches both endpoints. Metadata resistance is a **spectrum, not a binary**. And do the same discipline locally — don't write a plaintext "last contacted" index, and be conservative with timing-revealing features like read receipts and typing indicators.

---

## 10. Tech Stack & Language

**Core principle: memory safety is a crypto requirement, not a style preference.** An attacker feeds you untrusted bytes all day; one overflow/UAF leaks keys and silently defeats everything.

### 10.1 Verdict

| Language | Verdict | Why |
|---|---|---|
| **Rust** ✅ **primary** | **Recommended.** | Compile-time memory safety kills the buffer-overflow/UAF class for free; **Arti** gives in-process Tor + onion service; audited crypto crates; `tokio` async. Best ecosystem fit, full stop. |
| **C++** ⚠️ viable | Only with a mandatory, perpetual safety harness. | No Arti equivalent (drive C-tor over the control port); safety is opt-in and never-ending; strictly more work to reach the same floor Rust gives by default. Good if the goal is *also* to learn C++. |
| **Go** — third | Memory-safe, great networking (Cwtch is Go+Tor), but weaker fit. | GC makes it hard to guarantee secrets are zeroed / not copied; worse constant-time control; still shells out to C-tor. Prefer only if the team already lives in Go. |

### 10.2 Recommended PRIMARY stack (Rust)

| Concern | Choice |
|---|---|
| Language | Rust (2021/2024 edition) |
| Tor | **Arti** (`arti-client`) — embed Tor + host onion service in-process; pin the version and isolate it behind one thin module (API still stabilizing) |
| Async | **tokio** |
| Crypto primitives | RustCrypto (`x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`, `argon2`) or `ring` |
| Secure channel | **`snow`** (Noise) for the simplest correct v1; **`vodozemac`** (audited Double Ratchet) when you add long-term ratcheting |
| Storage | **SQLite via `rusqlite` + SQLCipher** (encrypted DB); key from Argon2id passphrase |
| Serialization | **`serde`** + compact `postcard`/CBOR (avoid ad-hoc byte parsing — a top CVE source) |
| Secret hygiene | **`zeroize`** for key buffers; disable core dumps; never log secrets |
| UI | **`ratatui`** (TUI first) → **`egui`** (simple pure-Rust GUI) or Tauri; **`uniffi`** later to share the core with Android/iOS |
| Supply chain | **`cargo audit` / `cargo deny`** in CI; commit `Cargo.lock`; minimize deps; warnings-as-errors |

### 10.3 Viable C++ stack (only if you go this route)

| Concern | Choice |
|---|---|
| Language | Modern **C++20/23** — mandatory RAII, smart pointers, `std::span`/`std::array`, bounds-checked access; **no raw `new`/`malloc` buffers, no C strings** |
| Crypto | **libsodium** (never OpenSSL low-level, never hand-rolled) — X25519, Ed25519, XChaCha20-Poly1305, Argon2, `sodium_malloc`/`sodium_memzero`/constant-time compare |
| Tor | **C `tor` daemon as subprocess**, driven over the **control port** to create the onion service + open SOCKS streams |
| Async net | **Boost.Asio** (or standalone Asio) |
| Storage | **SQLCipher** |
| Serialization | **Protocol Buffers / FlatBuffers** — a memory-safe parser, never ad-hoc byte parsing |
| Ratchet | Port from **libsignal**; do not hand-write from the spec |
| **Mandatory safety harness (the price of C++)** | **AddressSanitizer + UBSan** on all builds/tests; **libFuzzer (+ASan) continuous fuzzing of every parser/deserializer** with saved corpora; **clang-tidy / clang analyzer / cppcheck** in CI; constant-time discipline via libsodium helpers (never `memcmp` on secrets); explicit key zeroization. Treat any sanitizer/fuzzer finding as **release-blocking.** |

### 10.4 Both stacks — build/release integrity
Pin + audit deps every CI run; minimize the dependency tree (each dep is attack surface). **Sign all release artifacts** (minisign/signify or Sigstore) and verify in-app. **Publish source, aim for reproducible builds** so users/auditors can confirm the binary matches source. **Avoid auto-updaters that can be coerced into pushing a targeted malicious build** — a classic attack on secure messengers.

---

## 11. Learn From / Build On Existing Systems

Six mature projects have solved most of your hard problems under real threat models. Study them; reuse their patterns; don't reinvent crypto.

| System | Status (2025–26) | Contact / key exchange | Metadata handling | Transport |
|---|---|---|---|---|
| **Ricochet (original)** | **Abandoned ~2016** — don't fork | Onion address = your public key, shared out-of-band | No servers, no metadata store; strictly synchronous | Tor v3 onion, pure P2P |
| **Ricochet-Refresh** | **Active** (Blueprint; 3.1-alpha Nov 2025 is a **Rust rewrite**) | Same: identity = onion address handed to a contact | Strong — no central server; contact requests ride the onion | Tor v3 onion, P2P |
| **Cwtch** | **Active** (Open Privacy, Go) | Cwtch address (onion) out-of-band; groups via a shared **untrusted** relay | Best-in-class async: untrusted servers **blindly broadcast ciphertext** — learn neither membership, size, nor content | Tor v3 onion + optional discardable relays |
| **Briar** | **Active** (activists/journalists) | **BQP** (QR, in person) + **BRP** (remote rendezvous) | Delay-tolerant; works offline/mesh so there may be *no internet metadata at all* | Bramble over Tor **or** Bluetooth/Wi-Fi/USB |
| **OnionShare (chat)** | **Active** | No accounts — host shares an ephemeral `.onion` + private key | Ephemeral by design: messages in RAM only, zero logs | Your computer *is* the server; Tor v3 onion |
| **Session** | **Active** (⚠️ cautionary) | Session ID = an X25519 public key | Onion-routed over **Oxen** (not Tor); stake-gated | **Dropped FS in 2021**, re-adding in Protocol V2 (2026-27) |
| **SimpleX** | **Active** | **No persistent identifiers** — one-time invite link/QR | Strongest ID-hiding: pairwise per-queue IDs; conversations share no metadata | SMP relays (self-hostable); Tor optional, not native |

**Key takeaways to copy:**
1. **Contact bootstrapping is always out-of-band** — nobody uses a searchable directory. Make the ID blob compact and look like a generic random string (like a Session ID / SimpleX link), never PGP armor.
2. **The onion address doubles as the public key/identity** (Ricochet/Cwtch/Briar) — reuse this, don't invent key exchange.
3. **Solve async the Cwtch way** *if* you need it — untrusted, discardable relays that only see broadcast ciphertext give offline delivery without a server holding your social graph.
4. **Metadata minimization is a spectrum** — OnionShare (nothing persisted) and SimpleX (no identifiers) are the extremes; pick your point early.
5. **Session is the anti-pattern** — it dropped forward secrecy and spent years re-adding it. Concrete proof to keep FS/Double-Ratchet from day one.

**Recommendation:** Build **on Tor v3 onion services + a vetted ratchet.** The closest reference to copy is **Cwtch** (and **Ricochet-Refresh's** Rust rewrite for a modern memory-safe implementation of the same 1:1 model). If you want to *ship* rather than *research*, seriously consider studying/forking Ricochet-Refresh's approach; if you want maximum ID-hiding, imitate SimpleX's pairwise-queue *idea*. **Whatever you do — reuse their protocol designs and the Tor layer via libraries; never reimplement their crypto by hand.**

---

## 12. Local Device Security & UX

**The honest ceiling:** endpoint compromise — not the crypto — is what actually breaks these apps. Put the real work here.

- **Encrypted store.** Encrypt the whole local DB (SQLCipher, or an XChaCha20-Poly1305 file). The DB key is **random**; wrap it with an **Argon2id**-derived key so the user can change passphrase without re-encrypting everything. For a passphrase unlock (not a fast server login), use **strong** Argon2id — well above OWASP's login floor: target **~256–512 MiB memory, t=3–4, p=1**, tuned to ~0.5–1 s on target hardware. Keep the derived key + plaintext in locked memory only; **zeroize on lock/exit.**
- **Auto-lock.** Lock after inactivity and on minimize; require passphrase (or an OS-keystore-backed biometric that unlocks the wrapping key) to resume. **Never persist the passphrase or plaintext DB key to disk.**
- **Disappearing messages.** Real per-conversation timers, deleted on both ends after read/expiry — but tell users plainly it only clears *this app's own store*; it can't delete screenshots, backups, or a copy a compromised peer kept.
- **Secure deletion reality — get this right.** On modern SSD/flash, wear-leveling and garbage collection mean overwriting a file does **not** reliably destroy the old bytes. **The only dependable erase is crypto-erasure: keep everything encrypted and destroy the key.** Design the store so one wipe of the key vault renders all history unreadable instantly.
- **Verification UX.** Give each contact a short human-comparable safety number; make **unverified visibly different from verified**; **warn loudly if a known contact's fingerprint changes.** Copy Signal; don't invent a comparison scheme.
- **Indistinguishability at rest.** Never write recognizable ciphertext markers or PGP armor to disk. All at-rest bytes = indistinguishable AEAD ciphertext.
- **Panic / duress / decoy (implement, frame honestly).** A **panic wipe** (destroy the key vault → crypto-erase everything, via a quick keystroke/gesture) and optionally a **duress passphrase** that opens a decoy profile. These help against a "hand over your phone" moment but are **weak against a prepared forensic adversary** who images the device first or coerces the real passphrase. **Never oversell them in the UI.**
- **OpSec guidance to ship to users (plain-language help page):** exchange addresses/fingerprints over a channel the adversary doesn't control and verify in person/by voice; keep OS + app updated; use full-disk encryption + a strong device lock (the crypto is moot if an unlocked phone is seized); assume screenshots and the other person's device are outside your control; **Tor hides who you talk to, not what a compromised endpoint sees**; disable cloud backups that would copy plaintext; use a strong unique passphrase; know that running an anonymity tool can itself draw attention in some places.

---

## 13. Build Roadmap

Ship a CLI/TUI first to get the protocol right before any GUI. **Each phase ships only after the previous is audited.**

- **Phase 0 — Spike (prove the transport).**
  - [ ] Two Arti onion services on one machine exchange raw bytes end-to-end over Tor.
  - [ ] Confirm no exit node is used; log the ~6-hop rendezvous path.
  - [ ] Enable Full Vanguards; verify guard pinning.
- **Phase 1 — Secure channel.**
  - [ ] Noise (`snow`) handshake (`XK`/`IK`) over the onion link; mutual auth from onion identity keys.
  - [ ] Elligator2-encode handshake ephemerals; verify wire bytes look random.
  - [ ] Fixed-size record padding.
- **Phase 2 — Message crypto.**
  - [ ] Double Ratchet inside the Noise channel (port `vodozemac`/libsignal — don't hand-write).
  - [ ] Skipped-key cache (bounded), per-message counter in AEAD AD, replay rejection.
  - [ ] Prove FS + PCS with a test that leaks a key and shows past-safe / future-heals.
- **Phase 3 — Contact exchange.**
  - [ ] Onion-address-as-identity; signed contact request; Accept/Reject/blacklist.
  - [ ] Out-of-band QR + short-string exchange; prekey bundle in the invite blob.
  - [ ] Rate-limit incoming requests.
- **Phase 4 — Messaging MVP (1:1 text).**
  - [ ] Send/receive text reliably while both online; reconnect handling.
  - [ ] CLI/TUI (`ratatui`).
- **Phase 5 — Verification.**
  - [ ] Safety-number derivation + compare UX; verified/unverified states; fingerprint-change warning.
- **Phase 6 — Local encryption & disappearing.**
  - [ ] SQLCipher store; Argon2id passphrase unwrap; auto-lock; zeroize.
  - [ ] Disappearing timers; crypto-erasure wipe; optional panic/decoy.
- **Phase 7 — Files.** (Big new metadata + malware surface — study OnionShare first.)
- **Phase 8 — Groups.** (Hardest — metadata, membership, ordering, FS all worsen — study MLS / Cwtch's untrusted-relay model before attempting.)
- **Phase 9 — Mobile.** (Background delivery over Tor + OS keystore = a project in itself; reuse the Rust core via `uniffi`.)
- **Async delivery (cross-cutting, decide early — §17):** if needed, add Cwtch-style **untrusted** relays that only see broadcast ciphertext; **threat-model the relay separately** as a server-shaped adversary.

---

## 14. Problems & Mitigations (consolidated)

| Risk / attack | Mitigation | Residual limit |
|---|---|---|
| **Rolling your own crypto/ratchet** (#1 killer) | libsodium primitives; port ratchet from `vodozemac`/libsignal; get a security review | Logic bugs still possible → audit |
| **Nonce reuse** | XChaCha20-Poly1305 random nonces or `crypto_secretstream`; OS CSPRNG only | — |
| **Public-key fingerprinting on the wire** | Elligator2-encode ephemerals | — |
| **Replay / reordering over Tor** | Bounded skipped-key cache; per-message counter in AEAD AD; reject seen counters | — |
| **ID-swap MITM at contact exchange** | Out-of-band exchange + safety-number verification | Can't help if the OOB channel is attacker-controlled *and* verification skipped |
| **Guard discovery → guard compromise** | Full Vanguards; keep Arti updated; run service only while online | Structural risk for always-on services |
| **Global passive adversary** | Padding + optional cover traffic + jitter | Fundamental — not defeatable at low latency |
| **Endpoint compromise** | Memory-safe language; minimal attack surface; auto-lock; minimal on-disk plaintext; Tails/Whonix guidance for high-risk users | Owns the endpoint = reads plaintext. Hard ceiling. |
| **Key-store theft (seized device)** | Argon2id-encrypted store; `sodium_memzero`; small short-lived skipped-key cache | Fails if device seized *unlocked* |
| **Secrets lingering in memory** | `zeroize`/`sodium_malloc`; disable core dumps; no logging secrets; no swap for sensitive mem | Best-effort |
| **Supply-chain / malicious dep** | Minimize deps; `cargo audit`/`cargo deny` / OSV-Scanner in CI; pin; prefer audited libs | Compromised signing key/build machine still fatal |
| **Insecure updates** | Signed releases; reproducible builds; no coercible auto-updater | Signing-key compromise |
| **Coercion / key-disclosure** | FS (past-safe); panic-wipe; decoy profiles | Legal compulsion can still win |
| **Recognizable crypto (PGP armor / magic bytes)** | Indistinguishable AEAD everywhere; pluggable transports to hide Tor | Statistical traffic analysis; app's mere presence is evidence |
| **Async temptation → accidental central server** | If you must, use untrusted broadcast relays; threat-model separately | Reintroduces a server-shaped adversary |
| **Scope creep (groups/files/mobile too early)** | Hold the phased roadmap; audit each phase | — |

---

## 15. Testing & Security Validation

- **Unit tests** for every crypto step: known-answer vectors for X25519/Ed25519/XChaCha20-Poly1305/Argon2id; ratchet test vectors (compare against libsignal/vodozemac); Elligator2 round-trip; padding.
- **Integration tests:** two onion services handshake, exchange, reconnect; out-of-order and dropped-message delivery; replay rejection; FS test (leak a key → past messages unreadable); PCS test (leak → after one round-trip, channel heals).
- **Fuzzing:** coverage-guided fuzzing of **every parser/deserializer** (handshake, message framing, contact-request, DB records) with saved corpora. In C++, libFuzzer + ASan; in Rust, `cargo fuzz`. Treat any finding as release-blocking.
- **Sanitizers (C++ path):** ASan + UBSan on all CI builds. (Rust gets most of this floor for free.)
- **Constant-time checks:** all secret-dependent comparisons via libsodium helpers (`sodium_memcmp`), never `memcmp`; audit for secret-dependent branches/indexing.
- **Dependency auditing:** `cargo audit`/`cargo deny` (or OSV-Scanner) every CI run; commit lockfiles; minimize + review new deps.
- **Reproducible-build check** in CI so the published binary provably matches source.
- **The non-negotiable gate:** **get a real, external security review before anyone trusts this with anything sensitive.** None of the reference projects became trustworthy without outside audit; neither will this. Publish source and invite review early.

---

## 16. Legal, Ethical & Responsible Use

Encryption and anonymity are **legitimate and widely used** — by journalists protecting sources, activists under surveillance, domestic-abuse survivors, lawyers, doctors, and ordinary people who value privacy. This project is squarely in the family of Briar, Cwtch, and SimpleX. Keep the framing honest and brief:
- **This tool is for private communication, not for facilitating crime.** Ship a short responsible-use note; don't market or design around illicit use.
- **Jurisdiction & export awareness:** cryptography and anonymity tools face varying legal treatment across countries (including key-disclosure laws and, in some places, restrictions on Tor itself). Users should understand their local context; you should be aware of export considerations before distributing.
- **The endpoint-security caveat is also an ethical one:** be clear with users about what the tool *can't* protect (compromised device, coercion, global adversary) so no one relies on it beyond its real guarantees. Overselling safety to at-risk users is the harm to avoid.

---

## 17. Open Questions & Decisions for Debajit

Lock these before Phase 1; each shapes the rest.

| # | Decision | Recommendation | Notes |
|---|---|---|---|
| 1 | **Language** | **Rust** | C++ path exists (§10.3) if learning C++ is a co-goal, but accept the perpetual safety-harness cost. |
| 2 | **Fork vs fresh** | **Fresh in Rust, but steal designs** from Ricochet-Refresh (Rust rewrite) + Cwtch | Reuse Tor via Arti; never reimplement crypto by hand. |
| 3 | **Sync-only vs async delivery** | **Sync-only for MVP** | Async needs untrusted relays (Cwtch model) → threat-model the relay separately. Biggest architectural fork. |
| 4 | **Secure-channel design** | **Noise (`snow`) first, add Double Ratchet (`vodozemac`) next** | Simplest correct path to FS; ratchet adds stored-history FS + async path. |
| 5 | **UI target** | **TUI (`ratatui`) → `egui` desktop** | GUI/mobile after the core is stable and audited. |
| 6 | **Groups in v1?** | **No** | Metadata/membership/FS all worsen; study MLS/Cwtch first (Phase 8). |
| 7 | **Pluggable transports in v1?** | **Optional toggle, design the seam early** | Required if hiding Tor use is in the user's threat model. |
| 8 | **Post-quantum?** | **Defer (design the seam)** | Add hybrid X25519+ML-KEM via liboqs later if "harvest now, decrypt later" matters. |
| 9 | **Panic/decoy profiles in v1?** | **Panic-wipe yes; decoy optional** | Frame honestly; not proof against forensic imaging. |
| 10 | **Multi-device?** | **No for v1** | Multi-device + serverless is genuinely hard; revisit post-MVP. |

---

*End of PRD. The short version, one more time: onion-address-as-identity (no PGP block to hide) + out-of-band exchange + safety-number verification; Noise + Double Ratchet on libsodium, never PGP; indistinguishable wire format; Rust + Arti; ship a tiny audited 1:1 MVP first. Build the boring, small, correct thing — then get it reviewed before anyone's safety depends on it.*
