#!/usr/bin/env python3
"""
Nullkey - Phase 0 prototype
================================
A minimal 1:1 END-TO-END-ENCRYPTED chat over a Tor v3 onion service.

Modes:
  python3 chat.py host                 # real: create an onion service, wait for a contact
  python3 chat.py join <onion-address> # real: connect to a contact's onion service
  python3 chat.py testhost             # local dev: no Tor, listen on 127.0.0.1 (fast to test)
  python3 chat.py testjoin             # local dev: no Tor, connect to 127.0.0.1

This is a LEARNING prototype, not a finished secure product:
  * Encryption = X25519 key exchange + authenticated encryption (NaCl "Box").
  * Trust-On-First-Use: you MUST compare the printed safety number with your
    contact over a different channel to be sure nobody is in the middle.
  * NO forward secrecy yet - that's the Double Ratchet, a later phase.
Do not protect anything real with it until you finish the roadmap (README) and
get a security review. See secure-messenger-prd.md for the full design.
"""
import sys
import os
import socket
import struct
import threading

try:
    from nacl.public import PrivateKey, PublicKey, Box
except ImportError:
    sys.exit("Missing PyNaCl. Run:  pip install -r requirements.txt")

import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
ONION_VPORT = 5000     # virtual port advertised on the onion service
LOCAL_PORT = 5000      # local TCP port the host listens on
MAX_FRAME = 1 << 20    # 1 MB per message - sanity cap so a peer can't blow up memory


# ----------------------------- framing ------------------------------------ #
def send_frame(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock):
    hdr = recv_exact(sock, 4)
    if hdr is None:
        return None
    (length,) = struct.unpack(">I", hdr)
    if length == 0 or length > MAX_FRAME:
        return None
    return recv_exact(sock, length)


# ----------------------------- crypto ------------------------------------- #
def safety_number(pub_a: bytes, pub_b: bytes) -> str:
    """Order-independent fingerprint of both public keys, for out-of-band checking."""
    lo, hi = sorted([pub_a, pub_b])
    digest = hashlib.blake2b(lo + hi, digest_size=10).hexdigest()
    return "-".join(digest[i:i + 5] for i in range(0, len(digest), 5))


def handshake(sock, my_priv: PrivateKey, is_host: bool) -> Box:
    my_pub = bytes(my_priv.public_key)
    # exchange raw 32-byte X25519 public keys (host reads first to avoid a deadlock)
    if is_host:
        their_pub = recv_exact(sock, 32)
        sock.sendall(my_pub)
    else:
        sock.sendall(my_pub)
        their_pub = recv_exact(sock, 32)
    if not their_pub or len(their_pub) != 32:
        raise ConnectionError("handshake failed (bad peer key)")

    box = Box(my_priv, PublicKey(their_pub))
    print("\n[secure] encrypted channel established.")
    print("[verify] SAFETY NUMBER:  " + safety_number(my_pub, their_pub))
    print("[verify] Read this to your contact over a DIFFERENT channel (call, in person).")
    print("         Same on both sides  -> nobody is in the middle.")
    print("         Different           -> STOP, you may be under attack.\n")
    return box


def chat_loop(sock, box: Box):
    def reader():
        while True:
            frame = recv_frame(sock)
            if frame is None:
                print("\n[peer disconnected]")
                os._exit(0)
            try:
                msg = box.decrypt(frame).decode("utf-8", "replace")
            except Exception:
                print("\n[!] undecryptable frame (wrong key or tampering)")
                continue
            print("\rthem > " + msg + "\nyou  > ", end="", flush=True)

    threading.Thread(target=reader, daemon=True).start()
    print("Type a message and press Enter.  /quit to leave.\n")
    try:
        while True:
            line = input("you  > ")
            if line.strip() in ("/quit", "/exit"):
                break
            if line == "":
                continue
            send_frame(sock, bytes(box.encrypt(line.encode("utf-8"))))
    except (EOFError, KeyboardInterrupt):
        pass


# ----------------------------- tor plumbing ------------------------------- #
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def launch_tor(socks_port, control_port, tag):
    try:
        from stem import process as stem_process
    except ImportError:
        sys.exit("Missing stem. Run:  pip install -r requirements.txt")

    def on_line(line):
        if "Bootstrapped" in line:
            print("[tor] " + line.strip())

    data_dir = os.path.join(HERE, ".tor-" + tag)
    os.makedirs(data_dir, exist_ok=True)
    print("[tor] starting a private Tor instance (first run is slow)...")
    try:
        return stem_process.launch_tor_with_config(
            config={
                "SocksPort": str(socks_port),
                "ControlPort": str(control_port),
                "DataDirectory": data_dir,
            },
            take_ownership=True,
            init_msg_handler=on_line,
        )
    except OSError as e:
        sys.exit("Could not start Tor. Is the `tor` binary installed? "
                 "(macOS: brew install tor / Linux: sudo apt install tor)\n  " + str(e))


def tor_connect(onion_host, port, socks_port):
    import socks  # PySocks
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "127.0.0.1", socks_port, rdns=True)
    s.settimeout(120)
    s.connect((onion_host, port))
    return s


def listen_socket(port):
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", port))
    lsock.listen(1)
    return lsock


# ----------------------------- modes -------------------------------------- #
def run_host(use_tor):
    my_priv = PrivateKey.generate()
    lsock = listen_socket(LOCAL_PORT)

    if not use_tor:
        print("\n================ LOCAL TEST (no Tor) ================")
        print("  address: 127.0.0.1   port: %d" % LOCAL_PORT)
        print("  In another terminal:  python3 chat.py testjoin")
        print("====================================================")
        print("Waiting for your contact to connect...\n")
        conn, _ = lsock.accept()
        chat_loop(conn, handshake(conn, my_priv, is_host=True))
        return

    from stem.control import Controller
    socks_port, control_port = free_port(), free_port()
    tor = launch_tor(socks_port, control_port, "host")
    try:
        with Controller.from_port(port=control_port) as controller:
            controller.authenticate()
            svc = controller.create_ephemeral_hidden_service(
                {ONION_VPORT: LOCAL_PORT}, await_publication=True
            )
            print("\n============= SHARE THIS OUT OF BAND (QR / in person) =============")
            print("  onion address:  %s.onion" % svc.service_id)
            print("==================================================================")
            print("Waiting for your contact to connect (they run: join <addr>)...\n")
            conn, _ = lsock.accept()
            chat_loop(conn, handshake(conn, my_priv, is_host=True))
    finally:
        tor.kill()


def run_join(target, use_tor):
    my_priv = PrivateKey.generate()

    if not use_tor:
        print("[local] connecting to 127.0.0.1:%d ..." % LOCAL_PORT)
        s = socket.create_connection(("127.0.0.1", LOCAL_PORT), timeout=30)
        chat_loop(s, handshake(s, my_priv, is_host=False))
        return

    socks_port, control_port = free_port(), free_port()
    tor = launch_tor(socks_port, control_port, "join")
    try:
        host = target.replace(".onion", "").strip() + ".onion"
        print("[tor] connecting to %s:%d ... (10-60s is normal)" % (host, ONION_VPORT))
        s = tor_connect(host, ONION_VPORT, socks_port)
        chat_loop(s, handshake(s, my_priv, is_host=False))
    finally:
        tor.kill()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "host":
        run_host(use_tor=True)
    elif mode == "join":
        if len(sys.argv) < 3:
            sys.exit("Usage: python3 chat.py join <onion-address>")
        run_join(sys.argv[2], use_tor=True)
    elif mode == "testhost":
        run_host(use_tor=False)
    elif mode == "testjoin":
        run_join("127.0.0.1", use_tor=False)
    else:
        print(__doc__)
        print("Usage:\n"
              "  python3 chat.py host\n"
              "  python3 chat.py join <onion-address>\n"
              "  python3 chat.py testhost      (local, no Tor)\n"
              "  python3 chat.py testjoin      (local, no Tor)")


if __name__ == "__main__":
    main()
