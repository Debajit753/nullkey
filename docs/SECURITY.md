# Security Policy


Its cryptography (an X3DH-style handshake and a
Double Ratchet) is **implemented from scratch** and has had **no professional
security review or audit**. It may contain serious flaws.

**Do not use Nullkey to protect anything sensitive, or to keep anyone safe.**
If you need real private, anonymous messaging, use a reviewed tool such as
[Signal](https://signal.org), [Briar](https://briarproject.org), or
[Cwtch](https://cwtch.im).

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security bugs.

- contact the repo owner via their GitHub profile.


## Threat model (what it is *designed* to do — remember: unverified)

**Aims to protect:**
- **Message confidentiality & integrity** end-to-end (XChaCha20-Poly1305), with
  **forward secrecy** and **post-compromise security** from the Double Ratchet — so
  a key stolen today shouldn't decrypt yesterday's or tomorrow's messages.
- **Who-talks-to-whom**, by running every connection through **Tor v3 onion
  services** — there's no central server that sees the metadata.
- **Impersonation / man-in-the-middle**, *only if* both people compare the
  **safety number** out of band. This check is mandatory: skipping it removes the
  authentication guarantee entirely (it becomes trust-on-first-use).
- **Message size** and **when you talk**, partially: fixed-size padding hides
  length, and `--cover` adds decoy traffic.

**Does NOT protect against:**
- A **compromised device** (malware, keylogger, someone at your unlocked computer).
  Crypto can't save a broken endpoint — and your `data/` dir *is* your account.
- A **global passive adversary** who can watch the whole Tor network's timing and
  volume. Padding + cover traffic raise the bar; they don't defeat this.
- **You leaking your own identity** out of band, or **skipping the safety-number
  check** (then MITM is possible).
- Bugs in this from-scratch, unaudited code. See the top of this file.

## Scope

This policy covers the code in this repository. It does not cover Tor itself,
libsodium, or your operating system — keep those updated.
