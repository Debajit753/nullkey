# Getting started with Nullkey

> ⚠️ Educational, unaudited project — don't use it to protect real secrets. See [SECURITY.md](SECURITY.md).
> New here? The **[README](../README.md)** explains what Nullkey is and how it works, and the **[GLOSSARY](GLOSSARY.md)** defines every term in plain language.

---

## 1. Prerequisites

- **Python 3.9+** — required.
- **The Tor binary** — only needed for the *real* over-Tor mode (the local test doesn't use it):
  - macOS: `brew install tor`
  - Linux: `sudo apt install tor`
- **libsodium** *(optional)* — only if you want to build the C++ core. The app runs fine in **pure Python** without it.
  - macOS: `brew install libsodium` · Linux: `sudo apt install libsodium-dev`

## 2. Install

```bash
git clone https://github.com/Debajit753/nullkey.git      # or unzip the release
cd nullkey
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

That's all — `nullkey.py` is now runnable in pure Python.

## 3. Run it

### A) Local test (no Tor) — the fastest way to see it work

Two terminals:

```bash
python3 nullkey.py --local --data-dir ./peerA    # terminal 1 — waits for a connection
python3 nullkey.py --local --data-dir ./peerB    # terminal 2
```

In **terminal 2**:
1. `/me` — note terminal 1's `127.0.0.1:PORT` (shown in terminal 1's `/me` too).
2. `/add alice 127.0.0.1:<peerA-port>`
3. `/connect alice`
4. Type to chat. Compare the **safety numbers** in both windows, then `/verify alice`.

Instant — this proves the crypto + Double Ratchet without waiting on Tor.

### B) The real thing (over Tor)

Needs the Tor binary (step 1). On **each** machine:

```bash
python3 nullkey.py            # bootstraps Tor, then prints your <56 chars>.onion (it's persistent)
```

- Share your `.onion` address **out of band** — in person, a call, or a QR code. (Sharing it out of band is also what stops a man-in-the-middle.)
- Your contact runs `/add <name> <your-onion>` then `/connect <name>`. Only one side connects; the other waits.
- The **first** Tor connection takes ~30 s–2 min (directory lookup + building a rendezvous circuit). Leave the session open — reconnecting pays that cost again. Use `--idle 0` so it never auto-disconnects.

### Always: verify the safety number

Both sides print a `SAFETY NUMBER`. Read it to each other on a **different channel** (a call, in person):
- **Match** → no one is in the middle. `/verify <name>` to remember it.
- **Different** → **stop.** Someone may be intercepting.

This is the step that turns "encrypted to somebody" into "encrypted to the *right* person" — skipping it is the one thing that breaks the whole security model.

## 4. Commands

| Command | What it does |
|---|---|
| `/me` | show your own address (onion, or `127.0.0.1:PORT` in `--local`) |
| `/add <name> <address>` | save a contact |
| `/contacts` | list saved contacts (`*` = verified) |
| `/del-contacts <name\|all>` | delete one contact, or all of them |
| `/connect <name\|address>` | dial a contact (retries automatically) |
| `/verify <name>` | mark a contact verified after you've compared safety numbers |
| `/clear` | clear the screen |
| `/bye` | disconnect the current chat (stay running) |
| `/quit` | exit the app |
| `/help` | list commands |

## 5. Command-line flags

| Flag | Default | What it does |
|---|---|---|
| `--local` | off | skip Tor; connect over `127.0.0.1` (for testing) |
| `--data-dir <dir>` | `./data` | where your identity keys + contacts live (**this folder is your account**) |
| `--idle <seconds>` | `180` | auto-disconnect after this much inactivity; `0` = never |
| `--cover` | off | send decoy traffic so real messages are hidden among fakes |
| `--bridge "<obfs4 line>"` | off | route Tor through an obfs4 bridge to hide that you're using Tor (needs `obfs4proxy` + real bridge lines from <https://bridges.torproject.org>) |

## 6. Your data dir *is* your account

Everything that makes you *you* lives in the `--data-dir` (default `./data`):
- `onion_identity.key` — your persistent `.onion` address
- `crypto_identity.key` — your long-term key (drives your safety number)
- `contacts.json` — who you've saved

Guard that folder. Back it up if you want to keep your address; delete it and you become a brand-new identity next run. It's `.gitignore`d, so it never gets committed.

---

## FAQ

**Why is it so slow over Tor?**
Your message can't go straight to your contact — that would reveal both IP addresses. Instead Tor routes it through ~6 relays worldwide. The first connection (directory lookup + building the rendezvous circuit) is the slow part (30 s–2 min); after that each message still hops those relays, so it's laggier than a normal chat. That latency *is* the anonymity — it's not a bug. For quick testing, use `--local`.

**How do I give someone my key without it looking like PGP?**
You don't share a `-----BEGIN PGP-----` blob. Your **onion address *is* your public key** — just a random-looking string. Share it out of band (in person / a call / a QR). Nothing about it screams "encrypted messaging."

**Is this safe to use for real / sensitive conversations?**
**No.** The crypto is implemented from scratch for learning and has **not** been audited. Use it to learn, not to protect anything real. For that, use [Signal](https://signal.org), [Briar](https://briarproject.org), or [Cwtch](https://cwtch.im). See [SECURITY.md](SECURITY.md) for the full threat model.

**How do I host it / stay reachable for free?**
You don't need a server or a host. Each person *is* their own Tor onion service — as long as `nullkey.py` is running on your machine, your `.onion` address is reachable. No paid hosting, no port forwarding, no static IP.

**My contact can't connect / it keeps retrying.**
Make sure the waiting side is fully booted (Tor bootstrapped to 100% and it printed its `.onion`) **before** the other side runs `/connect`. Double-check the onion address is exact. The first attempt often times out and a retry succeeds once Tor caches the descriptor — let the retries run.

**Do I need the C++ core?**
No. It's an optional speed/memory-safety layer. The app automatically falls back to pure Python. To build it: `make core` (needs libsodium). To prove it matches Python: `make parity`.

**How do I run the tests?**
`pip install -r requirements-dev.txt` then `make test` (or `make all`). Details + charts: [TESTING.md](TESTING.md).

**Can I use it on my phone?**
No — it's a terminal app for a computer. Mobile would be a separate project.

**Is using Tor legal?**
In most places, yes — Tor and encryption are legal, everyday privacy tools (this is the same family as Briar and Cwtch). Check your local laws, and use it to protect privacy, not to harm anyone.
