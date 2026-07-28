#!/usr/bin/env python3
"""
Nullkey — Phase 1
======================
A persistent, symmetric Tor onion chat with a contact book and a real input line.

What Phase 1 adds over chat.py (Phase 0):
  * PERSISTENT identity — your .onion address (and safety number) stay the same every run.
  * SYMMETRIC peers      — you're always listening; you dial a contact to start a chat.
  * CONTACTS             — saved addresses + a "verified" flag (compared out of band).
  * RECONNECT            — dialing retries with backoff.
  * A REAL INPUT LINE    — prompt_toolkit, so incoming messages don't scramble your typing.

Crypto (Phase 2): an authenticated X3DH-style handshake bootstraps a DOUBLE RATCHET
(forward secrecy + post-compromise security) — see ratchet.py / crypto.py. The safety
number is over your PERSISTENT identity key, so it's stable and worth verifying.
Still an educational build: get a security review before trusting it with anything real.

Run:
  python3 nullkey.py                       # real, over Tor (needs the `tor` binary)
  python3 nullkey.py --local               # dev mode: no Tor, 127.0.0.1 (fast to test)

Test two LOCAL peers on one machine (two terminals, separate data dirs):
  python3 nullkey.py --local --data-dir ./peerA
  python3 nullkey.py --local --data-dir ./peerB
"""
import os
import sys
import time
import random
import socket
import threading
import argparse

import shutil

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.patch_stdout import patch_stdout
    from prompt_toolkit.shortcuts import clear as clear_screen
    from prompt_toolkit.widgets import RadioList, Dialog, Label, Button, TextArea, ValidationToolbar
    from prompt_toolkit.layout.containers import HSplit
    from prompt_toolkit.application import Application, get_app
    from prompt_toolkit.layout import Layout, Dimension as D
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.key_binding.bindings.focus import focus_next, focus_previous
    from prompt_toolkit.key_binding.defaults import load_key_bindings
    from prompt_toolkit.key_binding.key_bindings import merge_key_bindings
    from prompt_toolkit.filters import Condition
except ImportError:
    sys.exit("Missing deps. Run:  pip install -r requirements.txt")

def _radiolist_dialog(title="", text="", ok_text="Ok", cancel_text="Cancel", values=None, default=None):
    if values is None:
        values = []

    radio_list = RadioList(values=values, default=default)

    def ok_handler() -> None:
        get_app().exit(result=radio_list.current_value)

    def cancel_handler() -> None:
        get_app().exit(result=None)

    dialog = Dialog(
        title=title,
        body=HSplit(
            [Label(text=text, dont_extend_height=True), radio_list],
            padding=1,
        ),
        buttons=[
            Button(text=ok_text, handler=ok_handler),
            Button(text=cancel_text, handler=cancel_handler),
        ],
        with_background=True,
    )

    bindings = KeyBindings()
    bindings.add("tab")(focus_next)
    bindings.add("s-tab")(focus_previous)

    # Keyboard support: press Enter inside the RadioList to instantly confirm the selection
    @bindings.add("enter", filter=Condition(lambda: get_app().layout.has_focus(radio_list)))
    def _submit_radio(event) -> None:
        radio_list.current_value = radio_list.values[radio_list._selected_index][0]
        event.app.exit(result=radio_list.current_value)

    return Application(
        layout=Layout(dialog),
        key_bindings=merge_key_bindings([load_key_bindings(), bindings]),
        mouse_support=True,
        full_screen=True,
    )

def _input_dialog(title="", text="", ok_text="OK", cancel_text="Cancel", default=""):
    def ok_handler() -> None:
        get_app().exit(result=textfield.text)

    def cancel_handler() -> None:
        get_app().exit(result=None)

    ok_button = Button(text=ok_text, handler=ok_handler)
    cancel_button = Button(text=cancel_text, handler=cancel_handler)

    textfield = TextArea(
        text=default,
        multiline=False,
    )

    dialog = Dialog(
        title=title,
        body=HSplit(
            [
                Label(text=text, dont_extend_height=True),
                textfield,
                ValidationToolbar(),
            ],
            padding=D(preferred=1, max=1),
        ),
        buttons=[ok_button, cancel_button],
        with_background=True,
    )

    bindings = KeyBindings()
    bindings.add("tab")(focus_next)
    bindings.add("s-tab")(focus_previous)

    # Keyboard support: press Enter inside the input text area to instantly submit it
    @bindings.add("enter", filter=Condition(lambda: get_app().layout.has_focus(textfield)))
    def _submit_input(event) -> None:
        event.app.exit(result=textfield.text)

    return Application(
        layout=Layout(dialog),
        key_bindings=merge_key_bindings([load_key_bindings(), bindings]),
        mouse_support=True,
        full_screen=True,
    )

import crypto
import net
import ratchet
import wire
import ui
import identity as identity_mod
from contacts import Contacts

ONION_VPORT = 5000
HERE = os.path.dirname(os.path.abspath(__file__))

# Files that hold identity/contact material. /panic destroys these first.
SECRET_FILES = ("contacts.json", "crypto_identity.key", "onion_identity.key")

HANDSHAKE_TIMEOUT = 30      # wall-clock seconds for a whole inbound/outbound handshake
MAX_INFLIGHT_HANDSHAKES = 4  # cap concurrent inbound handshakes so they can't be exhausted


def _hard_clear():
    """
    Clear the visible screen AND the scrollback buffer.

    prompt_toolkit's clear() only emits ESC[2J, which wipes the visible screen but
    leaves the entire session in scrollback — one Shift+PageUp from the whole
    plaintext conversation. ESC[3J is the one that clears scrollback.

    We write straight to fd 1 rather than through print()/sys.stdout because
    patch_stdout() queues writes onto a background flush thread, which could
    repaint text AFTER the clear.
    """
    seq = b"\x1b[3J\x1b[2J\x1b[H"
    try:
        os.write(1, seq)
    except Exception:  # noqa: BLE001
        try:
            sys.__stdout__.write(seq.decode())
            sys.__stdout__.flush()
        except Exception:  # noqa: BLE001
            pass


def _shred_file(path):
    """
    Overwrite a file's bytes with random data, fsync, then unlink.

    HONEST CAVEAT: on SSDs, journaling and copy-on-write filesystems the original
    blocks may still be recoverable — wear levelling means the drive, not us,
    decides where bytes physically land. This raises the bar against casual
    recovery; it is NOT a guarantee. Full-disk encryption is the real answer.

    Raises on failure so the caller can report it instead of assuming success.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            for _ in range(2):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
    except OSError:
        pass          # overwrite is best-effort; the unlink below is what must work
    os.remove(path)


class App:
    def __init__(self, data_dir, use_tor, cover=False, bridges=None, idle=180):
        self.data_dir = data_dir
        self.use_tor = use_tor
        self.cover = cover               # send decoy traffic while chatting
        self.bridges = bridges or []     # obfs4 bridge lines (hide Tor usage)
        self.idle_timeout = idle         # auto-disconnect after this many idle seconds (0 = never)
        self.last_activity = 0.0
        os.makedirs(data_dir, exist_ok=True)

        self.priv = identity_mod.load_or_create_x25519(data_dir)
        self.contacts = Contacts(os.path.join(data_dir, "contacts.json"))

        self.my_address = None
        self.socks_port = None
        self.tor = None
        self.controller = None
        self.listener = None

        # one active conversation at a time (Phase 1 scope)
        self.lock = threading.Lock()
        self.rlock = threading.Lock()      # guards the (stateful) Double Ratchet
        self.slock = threading.Lock()      # serializes sendall() on the shared socket
        self.conn = None
        self.ratchet = None
        self.peer_label = None
        self.peer_pub = None
        # True while /connect is dialing. Without this the connection slot looks
        # free for the whole dial (minutes over Tor) and an inbound peer can grab
        # it, only to be silently replaced when our dial lands.
        self.dialing = False
        # Bumped on every /account switch. Threads started under an older epoch
        # (an in-flight handshake, an old accept loop) must notice and bail out,
        # or they'd attach a session built from the PREVIOUS identity key.
        self._epoch = 0
        self._handshake_slots = threading.Semaphore(MAX_INFLIGHT_HANDSHAKES)

    # ------------------------------ startup ------------------------------- #
    def start(self):
        listen_port = net.free_port()
        self.listener = net.listen_socket(listen_port)

        if self.use_tor:
            from stem.control import Controller
            self.socks_port = net.free_port()
            control_port = net.free_port()
            print("[tor] starting a private Tor instance (first run is slow)...")
            self.tor = net.launch_tor(self.socks_port, control_port,
                                      os.path.join(self.data_dir, ".tor-data"),
                                      bridges=self.bridges)
            self.controller = Controller.from_port(port=control_port)
            self.controller.authenticate()
            self.my_address = identity_mod.create_persistent_service(
                self.controller, self.data_dir, ONION_VPORT, listen_port)
        else:
            self.my_address = "127.0.0.1:%d" % listen_port

        threading.Thread(target=self._accept_loop,
                         args=(self.listener, self._epoch), daemon=True).start()
        self._banner()
        self._command_loop()

    def _banner(self):
        ui.out(ui.banner(self.my_address, ratchet.BACKEND))

    # -------------------------- incoming peers ---------------------------- #
    def _accept_loop(self, listener, epoch):
        """
        Accept connections and hand each one to a short-lived worker.

        The handshake used to run inline here, so a single peer who connected and
        then said nothing blocked EVERY other inbound connection — you'd look
        permanently offline to all your contacts. Now accept() loops immediately.
        """
        while True:
            try:
                sock, _ = listener.accept()
            except OSError:
                return  # listener closed on shutdown or /account switch
            with self.lock:
                if epoch != self._epoch:
                    sock.close()
                    return          # this listener belongs to a previous account
                busy = self.conn is not None or self.dialing
            if busy:
                sock.close()   # Phase 1: one chat at a time
                continue
            threading.Thread(target=self._handshake_inbound,
                             args=(sock, epoch), daemon=True).start()

    def _handshake_inbound(self, sock, epoch):
        """Run one inbound handshake off the accept thread, under a wall-clock deadline."""
        if not self._handshake_slots.acquire(blocking=False):
            sock.close()          # too many half-open handshakes already
            return
        try:
            with self.lock:
                if epoch != self._epoch:
                    sock.close()
                    return
                priv = self.priv
            try:
                dr, mypub, theirpub = crypto.ratchet_handshake(
                    sock, bytes(priv), bytes(priv.public_key), initiator=False,
                    deadline=time.monotonic() + HANDSHAKE_TIMEOUT)
                sock.settimeout(None)   # then block on reads; idle loop handles inactivity
            except Exception:  # noqa: BLE001
                sock.close()
                return
            with self.lock:
                stale = epoch != self._epoch
            if stale:
                # The account was switched while we were handshaking: this session is
                # bound to the OLD identity key. Attaching it would show the new
                # account's banner over a conversation authenticated as someone else.
                sock.close()
                return
            self._attach(sock, dr, mypub, theirpub)
        finally:
            self._handshake_slots.release()

    # ---------------------- attach / detach a session --------------------- #
    def _attach(self, sock, dr, mypub, theirpub):
        """Take the single conversation slot. Returns False if someone else won it."""
        with self.lock:
            if self.conn is not None:
                try:
                    sock.close()   # lost the race — never silently orphan the socket
                except OSError:
                    pass
                return False
            self.conn = sock
            self.ratchet = dr
            self.peer_pub = theirpub
            self._rate_limiter = net.DecryptionRateLimiter()   # fresh bucket per peer
        sn = crypto.safety_number(mypub, theirpub)
        name = self.contacts.find_by_pubkey(theirpub.hex())
        verified = bool(name) and self.contacts.get(name).get("verified")
        self.peer_label = name
        print()
        ui.out(ui.ok("connected to " + (name or "unknown peer")))
        ui.out(ui.safety(sn, verified))
        ui.out(ui.note("type to chat   ·   /bye to leave"))
        print()
        self.last_activity = time.monotonic()
        threading.Thread(target=self._reader, args=(sock,), daemon=True).start()
        if self.cover:
            threading.Thread(target=self._cover_loop, args=(sock,), daemon=True).start()
        if self.idle_timeout:
            threading.Thread(target=self._idle_loop, args=(sock,), daemon=True).start()
        return True

    def _send(self, sock, frame):
        """
        Send one frame, serialized.

        send_frame() is called from three threads (your input, the cover-traffic
        loop, the priming decoy). sendall() can short-write under load, and two
        interleaved sendalls would splice the length-prefixed frames into garbage.
        """
        with self.slock:
            crypto.send_frame(sock, frame)

    def _detach(self, sock):
        with self.lock:
            if self.conn is sock:
                self.conn = None
                self.ratchet = None
                self.peer_label = None
                self.peer_pub = None
        try:
            sock.close()
        except OSError:
            pass

    def _reader(self, sock):
        while True:
            frame = crypto.recv_frame(sock)
            if frame is None:
                ui.out(ui.warn("peer disconnected"))
                self._detach(sock)
                return
            with self.rlock:
                dr = self.ratchet
                if dr is None:
                    return
                try:
                    body = dr.decrypt(frame)
                except Exception:
                    with self.lock:
                        rl = getattr(self, '_rate_limiter', None)
                    if rl and not rl.allow():
                        ui.out(ui.warn("too many bad frames — disconnecting (possible attack)"))
                        self._detach(sock)
                        return
                    ui.out(ui.warn("undecryptable frame (wrong key or tampering) — dropped"))
                    continue
            try:
                mtype, payload = wire.decode(body)
            except Exception:
                continue
            if mtype == wire.DECOY:
                continue   # cover traffic — silently ignore (does NOT count as activity)
            self.last_activity = time.monotonic()
            ui.out(ui.incoming(self.peer_label or "them", payload.decode("utf-8", "replace")))

    def _idle_loop(self, sock):
        """Auto-disconnect after idle_timeout seconds with no REAL message either way."""
        timeout = self.idle_timeout
        while True:
            time.sleep(min(10, timeout))
            with self.lock:
                if self.conn is not sock:
                    return
            if time.monotonic() - self.last_activity > timeout:
                ui.out(ui.note("idle for %d min — disconnecting" % round(timeout / 60)))
                self._detach(sock)
                return

    def _cover_loop(self, sock):
        """When --cover is on, send padded DECOY messages at random intervals so an
        observer can't tell when you're actually typing. Decoys are dropped by the peer."""
        while True:
            time.sleep(random.uniform(15, 45))
            with self.lock:
                if self.conn is not sock:
                    return
            try:
                with self.rlock:
                    if self.ratchet is None:
                        return
                    frame = self.ratchet.encrypt(wire.encode(wire.DECOY, b""))
                self._send(sock, frame)
            except Exception:
                return

    # ----------------------------- commands ------------------------------- #
    def _command_loop(self):
        session = PromptSession()
        with patch_stdout():
            while True:
                try:
                    line = session.prompt(self._prompt())
                except (EOFError, KeyboardInterrupt):
                    break
                if not line.strip():
                    continue
                self.last_activity = time.monotonic()   # any interaction keeps the chat alive
                if line.startswith("/"):
                    if self._command(line.strip()):
                        break
                else:
                    self._say(line)
        self._shutdown()

    def _prompt(self):
        return ui.prompt(self.conn is not None)

    def _say(self, text):
        with self.lock:
            conn = self.conn
        if not conn:
            ui.out(ui.warn("not connected — use /connect <name|address>"))
            return
        with self.rlock:
            # the responder can't send until it has received the initiator's first
            # message (that's how the ratchet establishes its sending chain).
            if self.ratchet is None or self.ratchet.CKs is None:
                ui.out(ui.warn("waiting for your contact's first message — try again in a second"))
                return
            frame = self.ratchet.encrypt(wire.encode(wire.REAL, text.encode("utf-8")))
        try:
            self._send(conn, frame)
            self.last_activity = time.monotonic()
        except Exception as e:  # noqa: BLE001
            ui.out(ui.err("send failed: %s" % e))
            self._detach(conn)

    def _command(self, line):
        parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]

        if cmd in ("/quit", "/exit"):
            return True
        elif cmd == "/help":
            self._help()
        elif cmd == "/me":
            ui.out("  your address: " + self.my_address)
        elif cmd == "/add":
            if len(args) < 2:
                ui.out(ui.warn("usage: /add <name> <address>"))
            else:
                self.contacts.add(args[0], args[1])
                ui.out(ui.ok("added contact '%s'" % args[0]))
        elif cmd == "/contacts":
            self._list_contacts()
        elif cmd == "/del-contacts":
            if not args:
                ui.out(ui.warn("usage: /del-contacts <name|all>"))
            elif args[0] == "all":
                self.contacts.clear_all()
                ui.out(ui.ok("all contacts deleted"))
            elif self.contacts.delete(args[0]):
                ui.out(ui.ok("deleted contact '%s'" % args[0]))
            else:
                ui.out(ui.warn("no contact named '%s'" % args[0]))
        elif cmd == "/clear":
            clear_screen()
        elif cmd == "/connect":
            if not args:
                ui.out(ui.warn("usage: /connect <name|address>"))
            else:
                self._connect(args[0])
        elif cmd == "/verify":
            self._verify(args)
        elif cmd in ("/bye", "/disconnect"):
            with self.lock:
                conn = self.conn
            if conn:
                self._detach(conn)
                ui.out(ui.note("disconnected"))
            else:
                ui.out(ui.warn("not connected"))
        elif cmd == "/panic":
            self._command_panic()          # never returns
            return True
        elif cmd == "/panic-all":
            self._command_panic(all_accounts=True)   # never returns
            return True
        elif cmd == "/account":
            self._command_account()
        else:
            ui.out(ui.warn("unknown command: %s  (try /help)" % cmd))
        return False

    # ------------------------------- panic -------------------------------- #
    def _panic_teardown(self):
        """Cut the network first, so nothing can re-create state while we wipe."""
        with self.lock:
            conn, self.conn, self.ratchet = self.conn, None, None
        for sock in (conn, self.listener):
            if sock is not None:
                try:
                    sock.close()
                except Exception:  # noqa: BLE001
                    pass
        if self.use_tor and self.tor:
            try:
                self.tor.kill()
                self.tor.wait(timeout=5)   # release .tor-data handles (matters on Windows)
            except Exception:  # noqa: BLE001
                pass

    def _wipe_data_dir(self, data_dir):
        """
        Destroy one account directory. Returns the list of paths that SURVIVED.

        Verification is the whole point: the previous version swallowed every
        error, so a wipe that did nothing at all looked exactly like a successful
        one. We now re-check the filesystem and report what's still there.
        """
        survivors = []
        if not os.path.exists(data_dir):
            return survivors
        for filename in SECRET_FILES:                 # shred the crown jewels first
            path = os.path.join(data_dir, filename)
            if os.path.exists(path):
                try:
                    _shred_file(path)
                except Exception:  # noqa: BLE001
                    pass                              # reported by the verification below
        shutil.rmtree(data_dir, ignore_errors=True)
        if os.path.exists(data_dir):                  # verify, don't assume
            for root, _dirs, files in os.walk(data_dir):
                for name in files:
                    survivors.append(os.path.join(root, name))
            if not survivors:
                survivors.append(data_dir)            # dir itself couldn't be removed
        return survivors

    def _command_panic(self, all_accounts=False):
        """Destroy identity + contacts and exit at once. No confirmation by design."""
        targets = [os.path.abspath(self.data_dir)]
        if all_accounts:
            targets = sorted({os.path.abspath(p) for _n, p in self._find_accounts()}
                             | {os.path.abspath(self.data_dir)})

        self._panic_teardown()

        survivors = []
        for directory in targets:
            survivors.extend(self._wipe_data_dir(directory))

        if survivors:
            # Do NOT clear the screen: the user must see that they are NOT safe.
            ui.out("")
            ui.out(ui.err("!!! PANIC INCOMPLETE — the following could NOT be destroyed:"))
            for path in survivors[:20]:
                ui.out("      " + path)
            if len(survivors) > 20:
                ui.out("      ... and %d more" % (len(survivors) - 20))
            ui.out(ui.err("Your identity and/or contacts are STILL ON DISK."))
            ui.out(ui.warn("Destroy the media physically if this matters."))
            try:
                sys.stdout.flush()
            except Exception:  # noqa: BLE001
                pass
            os._exit(1)

        _hard_clear()          # wipes scrollback too, not just the visible screen
        os._exit(0)            # hard exit: no atexit hook or daemon thread can repaint

    def _find_accounts(self):
        parent = os.path.dirname(os.path.abspath(self.data_dir))
        accounts = []
        try:
            entries = os.listdir(parent)
        except OSError:
            entries = []       # unreadable/missing parent must not crash the app
        for entry in entries:
            full_path = os.path.join(parent, entry)
            if os.path.isdir(full_path):
                if os.path.exists(os.path.join(full_path, "crypto_identity.key")):
                    accounts.append((entry, full_path))
        # Ensure current account is listed if it has a key
        current_abs = os.path.abspath(self.data_dir)
        current_name = os.path.basename(current_abs)
        if current_name and not any(acc[1] == current_abs for acc in accounts):
            if os.path.exists(os.path.join(current_abs, "crypto_identity.key")):
                accounts.append((current_name, current_abs))
        return sorted(accounts, key=lambda x: x[0])

    def _command_account(self):
        accounts = self._find_accounts()
        values = []
        current_abs = os.path.abspath(self.data_dir)
        for name, path in accounts:
            label = name
            if os.path.abspath(path) == current_abs:
                label += " (active)"
            values.append((os.path.abspath(path), label))
        values.append(("__create__", "[Create New Account...]"))

        result = None
        try:
            result = _radiolist_dialog(
                title="Account Switcher",
                text="Use Up/Down arrows to select, Space/Enter to confirm:",
                values=values,
                default=current_abs
            ).run()
        except Exception as e:
            ui.out(ui.err("dialog failed: %s" % e))
            return

        if result is None:
            return

        if result == "__create__":
            name = None
            try:
                name = _input_dialog(
                    title="Create New Account",
                    text="Enter a name for the new account:"
                ).run()
            except Exception as e:
                ui.out(ui.err("dialog failed: %s" % e))
                return

            if not name or not name.strip():
                return
            parent = os.path.dirname(os.path.abspath(self.data_dir))
            result = os.path.abspath(os.path.join(parent, name.strip()))

        if result == current_abs:
            return

        self._switch_account(result)

    def _switch_account(self, new_data_dir):
        # 1. Load the NEW identity before tearing anything down. If this fails we
        #    still have a working session instead of a half-dead app with no
        #    listener and no onion service.
        try:
            os.makedirs(new_data_dir, exist_ok=True)
            new_priv = identity_mod.load_or_create_x25519(new_data_dir)
            new_contacts = Contacts(os.path.join(new_data_dir, "contacts.json"))
        except Exception as e:  # noqa: BLE001
            ui.out(ui.err("could not open that account: %s" % e))
            ui.out(ui.note("staying on the current account"))
            return

        # 2. Invalidate every thread running under the old identity. Any in-flight
        #    handshake or old accept loop checks this and bails out rather than
        #    attaching a session authenticated with the PREVIOUS key.
        with self.lock:
            self._epoch += 1
            epoch = self._epoch
            conn = self.conn
            self.dialing = False

        # 3. Disconnect the current conversation
        if conn:
            self._detach(conn)
            ui.out(ui.note("disconnected active connection"))

        # 4. Remove the old onion service
        if self.use_tor and self.controller and self.my_address:
            try:
                self.controller.remove_ephemeral_hidden_service(self.my_address.split(".")[0])
            except Exception:  # noqa: BLE001
                pass

        # 5. Close the old listener (its accept loop exits on the OSError)
        if self.listener:
            try:
                self.listener.close()
            except Exception:  # noqa: BLE001
                pass

        # 6. Swap in the new identity
        self.data_dir = new_data_dir
        self.priv = new_priv
        self.contacts = new_contacts
        self.peer_label = None
        self.peer_pub = None

        # 7. New listener + address
        listen_port = net.free_port()
        self.listener = net.listen_socket(listen_port)
        if self.use_tor:
            ui.out(ui.note("publishing new onion service..."))
            self.my_address = identity_mod.create_persistent_service(
                self.controller, self.data_dir, ONION_VPORT, listen_port)
        else:
            self.my_address = "127.0.0.1:%d" % listen_port

        # 8. Accept loop for the new epoch only
        threading.Thread(target=self._accept_loop,
                         args=(self.listener, epoch), daemon=True).start()

        clear_screen()
        ui.out(ui.ok("switched to account: %s" % os.path.basename(self.data_dir)))
        self._banner()

    def _help(self):
        ui.out("  commands")
        ui.out(
            "  /me                     show your address\n"
            "  /add <name> <address>   save a contact\n"
            "  /contacts               list contacts\n"
            "  /del-contacts <name|all> delete a contact, or all contacts\n"
            "  /connect <name|addr>    start a chat\n"
            "  /verify <name>          mark the current peer verified (after comparing safety #)\n"
            "  /verify <name> force    accept a CHANGED identity key (only after checking!)\n"
            "  /clear                  clear the screen\n"
            "  /bye                    leave the current chat (stay online)\n"
            "  /account                manage and switch accounts\n"
            "  /quit                   exit\n"
            "  (any other text)        send a message to the current chat\n"
            "\n"
            "  DESTRUCTIVE — instant, no confirmation, NOT undoable:\n"
            "  /panic                  destroy THIS account's identity + contacts, then exit\n"
            "  /panic-all              destroy EVERY account in the folder, then exit")

    def _list_contacts(self):
        if not self.contacts.all():
            ui.out(ui.note("no contacts yet — /add <name> <address>"))
            return
        for name, c in self.contacts.all().items():
            ui.out(ui.contact_row(name, c.get("address"), c.get("verified")))

    def _connect(self, target):
        # Claim the connection slot for the WHOLE dial. Previously the lock was
        # released before dialing, so for the minutes a Tor dial can take the slot
        # looked free — an inbound peer could take it and then be silently
        # replaced when our dial landed, leaving you talking to someone else.
        with self.lock:
            if self.conn is not None:
                ui.out(ui.warn("already in a chat — /bye first"))
                return
            if self.dialing:
                ui.out(ui.warn("already dialing — wait for that to finish"))
                return
            self.dialing = True
            epoch = self._epoch
            priv = self.priv
        try:
            name, address = self.contacts.resolve(target)
            ui.out(ui.note("connecting to %s ..." % (name or address)))

            def dial():
                if self.use_tor:
                    host = address.replace(".onion", "").strip() + ".onion"
                    return net.tor_connect(host, ONION_VPORT, self.socks_port)
                host, _, port = address.partition(":")
                if not port:
                    raise ValueError("local address must be host:port (e.g. 127.0.0.1:5001)")
                return socket.create_connection((host, int(port)), timeout=30)

            try:
                sock = net.connect_with_retry(dial, attempts=5, backoff=3)
            except Exception as e:  # noqa: BLE001
                ui.out(ui.err("could not connect: %s" % e))
                return
            try:
                dr, mypub, theirpub = crypto.ratchet_handshake(
                    sock, bytes(priv), bytes(priv.public_key), initiator=True,
                    deadline=time.monotonic() + HANDSHAKE_TIMEOUT)
            except Exception as e:  # noqa: BLE001
                ui.out(ui.err("handshake failed: %s" % e))
                sock.close()
                return
            with self.lock:
                stale = epoch != self._epoch
            if stale:
                sock.close()
                ui.out(ui.warn("account switched while connecting — connection cancelled"))
                return
            sock.settimeout(None)   # block on reads; the idle loop is the only inactivity timeout
            if not self._attach(sock, dr, mypub, theirpub):
                return
            # Prime the ratchet: send one decoy so the OTHER side (the responder) gets a
            # sending chain and can type first too. The peer drops the decoy silently.
            try:
                with self.rlock:
                    pf = self.ratchet.encrypt(wire.encode(wire.DECOY, b""))
                self._send(sock, pf)
            except Exception:  # noqa: BLE001
                pass
        finally:
            with self.lock:
                self.dialing = False

    def _verify(self, args):
        pub = self.peer_pub
        if pub is None:
            ui.out(ui.warn("connect first, compare the safety number, then /verify <name>"))
            return
        name = args[0] if args else None
        force = len(args) > 1 and args[1].lower() == "force"
        if not name:
            ui.out(ui.warn("usage: /verify <name>   (the name to save this peer under)"))
            return

        existing = self.contacts.get(name)
        known = (existing or {}).get("pubkey")
        if known and known != pub.hex() and not force:
            # The identity key saved under this name does not match this peer. Silently
            # rebinding it — as this used to do — turns the safety number into theatre.
            ui.out(ui.err("!!! IDENTITY KEY CHANGED for '%s'" % name))
            ui.out(ui.warn(
                "  The key saved under this name is NOT the key this peer is using.\n"
                "  Expected only if they reinstalled or changed device.\n"
                "  Otherwise it can mean a man-in-the-middle — check the safety number\n"
                "  with them out of band (call them) BEFORE you accept it.\n"
                "  To accept the new key anyway:  /verify %s force" % name))
            return

        if not existing:
            self.contacts.add(name, "(inbound)")
        self.contacts.set_pubkey(name, pub.hex())
        self.contacts.set_verified(name, True)
        self.peer_label = name
        if known and known != pub.hex():
            ui.out(ui.warn("'%s' re-verified with a NEW identity key" % name))
        else:
            ui.out(ui.ok("'%s' marked verified" % name))

    # ----------------------------- shutdown ------------------------------- #
    def _shutdown(self):
        try:
            self.listener.close()
        except (OSError, AttributeError):
            pass
        with self.lock:
            if self.conn:
                try:
                    self.conn.close()
                except OSError:
                    pass
        if self.use_tor:
            try:
                self.controller.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                self.tor.kill()
            except Exception:  # noqa: BLE001
                pass
        ui.out("\n  bye.")


def main():
    ap = argparse.ArgumentParser(description="Nullkey Phase 1 — Tor onion chat")
    ap.add_argument("--local", action="store_true",
                    help="dev mode: no Tor, listen on 127.0.0.1 (fast to test the UI)")
    ap.add_argument("--data-dir", default=os.path.join(HERE, "data"),
                    help="where to store your identity + contacts (default: ./data)")
    ap.add_argument("--cover", action="store_true",
                    help="send decoy traffic while chatting (hides when you're really typing)")
    ap.add_argument("--bridge", action="append", default=[], metavar="LINE",
                    help="obfs4 bridge line (repeatable) to hide that you use Tor; needs obfs4proxy")
    ap.add_argument("--idle", type=int, default=180, metavar="SECONDS",
                    help="auto-disconnect after this many idle seconds (0 = never; default 180 = 3 min)")
    args = ap.parse_args()
    App(args.data_dir, use_tor=not args.local, cover=args.cover,
        bridges=args.bridge, idle=args.idle).start()


if __name__ == "__main__":
    main()
