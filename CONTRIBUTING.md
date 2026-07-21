# Contributing to Nullkey

Thanks for looking! Nullkey is a **learning project** (see the README banner and
[SECURITY.md](SECURITY.md)). Contributions that make it a better *teaching* tool —
clearer code, better tests, better docs — are very welcome. It is **not** trying to
become production-grade secure messaging; for that, use Signal.

## Dev setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt      # pytest, bandit, ruff, pip-audit, ...
make all                                 # tests + security lint + fuzz
```

The C++ core is optional (the app falls back to pure Python). To build + parity-test it:

```bash
brew install libsodium        # or: sudo apt install libsodium-dev
make core && make parity
```

## Ground rules

- **Never log plaintext or key material.**
- Changes to the crypto, the wire format, or the frame **parser** must keep
  `make test`, `make parity`, and `make fuzz` green.
- Don't invent crypto or roll your own Tor layer — use libsodium + onion services.
- Security bugs: **don't** open a public issue — see [SECURITY.md](SECURITY.md).

## Style

`make lint` (ruff). Keep it plain and readable — this code is meant to be *read*.
