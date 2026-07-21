"""
ui.py — the NULLKEY banner. Everything else is plain text: no colors, no ANSI.
The only styled thing in the whole app is this ASCII logo.
"""

LOGO = r"""
 _   _ _   _ _     _     _  _________   __
| \ | | | | | |   | |   | |/ / ____\ \ / /
|  \| | | | | |   | |   | ' /|  _|  \ V /
| |\  | |_| | |___| |___| . \| |___  | |
|_| \_|\___/|_____|_____|_|\_\_____| |_|
"""


def banner(address, backend):
    return "\n".join([
        LOGO,
        "  private, end-to-end encrypted chat over Tor",
        "",
        "  your address (share out of band):",
        "    " + address,
        "  backend: " + backend + "   |   /help for commands",
        "",
    ])


def out(s=""):
    print(s)


# plain message / notice formatting (no color) --------------------------------
def incoming(peer, text):
    return "%s > %s" % (peer, text)


def note(text):
    return text


def ok(text):
    return text


def warn(text):
    return text


def err(text):
    return text


def safety(sn, verified):
    out_ = "safety number: " + sn + (" (verified)" if verified else " (unverified)")
    if not verified:
        out_ += "\ncompare it with your contact out of band, then /verify <name>"
    return out_


def contact_row(name, address, verified):
    return "  [%s] %-12s %s" % ("*" if verified else " ", name, address)


def prompt(connected):
    return "you > " if connected else "nullkey > "
