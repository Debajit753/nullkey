"""
net.py — Tor plumbing + connection helpers (sockets, SOCKS, retries).
"""
import os
import sys
import socket
import time


# ----------------------- per-peer rate limiting --------------------------- #
class DecryptionRateLimiter:
    """
    Token-bucket rate limiter that throttles bad frames on a per-connection
    basis.  Each bad (failed-MAC / failed-decrypt) frame consumes one token.
    Once the bucket is empty the caller should drop the connection.

    Tokens refill at a steady rate so legitimate hiccups don't cause bans.
    """
    def __init__(self, capacity: int = 30, refill_per_sec: float = 2.0):
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self.tokens = float(capacity)
        self._last_refill = time.monotonic()

    def allow(self) -> bool:
        """Return True if another bad frame should be tolerated; False ⇒ drop connection."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._last_refill = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def listen_socket(port):
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(5)
    return ls


def launch_tor(socks_port, control_port, data_dir, bridges=None):
    from stem import process as stem_process

    def on_line(line):
        if "Bootstrapped" in line:
            print("[tor] " + line.strip())

    os.makedirs(data_dir, exist_ok=True)
    config = {
        "SocksPort": str(socks_port),
        "ControlPort": str(control_port),
        "DataDirectory": data_dir,
    }
    # Phase 5: route Tor through an obfs4 pluggable transport so a network observer
    # can't even tell you're using Tor. Needs the obfs4proxy binary + real bridge
    # lines (get them from https://bridges.torproject.org).
    if bridges:
        import shutil
        obfs4 = shutil.which("obfs4proxy")
        if not obfs4:
            sys.exit("--bridge was given but `obfs4proxy` is not on PATH "
                     "(install: brew install obfs4proxy / apt install obfs4proxy)")
        config["UseBridges"] = "1"
        config["ClientTransportPlugin"] = "obfs4 exec " + obfs4
        config["Bridge"] = list(bridges)

    try:
        import shutil
        tor_path = shutil.which("tor")
        if not tor_path:
            alt_path = r"D:\tor experts\tor-expert-bundle-windows-x86_64-15.0.19\tor\tor.exe"
            if os.path.exists(alt_path):
                tor_path = alt_path
            else:
                tor_path = "tor"

        return stem_process.launch_tor_with_config(
            config=config, take_ownership=True, init_msg_handler=on_line, tor_cmd=tor_path)
    except OSError as e:
        sys.exit("Could not start Tor (is the `tor` binary installed?  "
                 "macOS: brew install tor / Linux: sudo apt install tor)\n  " + str(e))


def tor_connect(onion_host, port, socks_port, timeout=75):
    import socks  # PySocks
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "127.0.0.1", socks_port, rdns=True)
    s.settimeout(timeout)
    s.connect((onion_host, port))
    return s


def connect_with_retry(dial_fn, attempts=5, backoff=3):
    """
    Call dial_fn() (which returns a connected socket or raises) with retries and
    a growing delay. Tor connections are flaky/slow, so retrying is normal.
    """
    last = None
    for i in range(attempts):
        try:
            return dial_fn()
        except Exception as e:  # noqa: BLE001 - we genuinely want to retry on anything
            last = e
            wait = backoff * (i + 1)
            print("[net] attempt %d/%d failed (%s); retrying in %ds..."
                  % (i + 1, attempts, e, wait))
            time.sleep(wait)
    raise ConnectionError("could not connect after %d attempts: %s" % (attempts, last))
