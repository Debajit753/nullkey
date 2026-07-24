#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Nullkey launcher — macOS / Linux
#  macOS: double-click this file (Terminal opens automatically).
#  Linux: run  ./start/start.command   (or right-click → Run in Terminal).
#
#  It cd's to the project, creates the virtualenv + installs dependencies on the
#  first run, activates it, and starts Nullkey. No manual cd / activate needed.
# ─────────────────────────────────────────────────────────────────────────────

# Go to the project root (this script lives in ./start/).
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1

# Find Python 3.
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "Python 3.9+ was not found."
  echo "Install it (macOS: brew install python | Linux: sudo apt install python3 python3-venv), then run again."
  read -r -p "Press Enter to close..." _
  exit 1
fi

# First run: create the venv and install dependencies.
if [ ! -f ".venv/bin/activate" ]; then
  echo "First run — setting up the virtual environment (one time, ~1 min)..."
  "$PY" -m venv .venv || { echo "Could not create the virtualenv."; read -r -p "Press Enter to close..." _; exit 1; }
  # shellcheck source=/dev/null
  . .venv/bin/activate
  python -m pip install --upgrade pip
  pip install -r requirements.txt || { echo "Dependency install failed."; read -r -p "Press Enter to close..." _; exit 1; }
else
  # shellcheck source=/dev/null
  . .venv/bin/activate
fi

echo
echo "Starting Nullkey...  (press Ctrl+C to quit)"
echo "Tip: for a local no-Tor test, pass args, e.g.:  ./start/start.command --local --data-dir ./peerA"
echo
python nullkey.py "$@"

echo
echo "Nullkey has exited."
read -r -p "Press Enter to close this window..." _
