"""Reversible mapping between corpus paths and names Windows can store."""
BAD = set('<>:"|?*\\')
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(10)} | {f"LPT{i}" for i in range(10)}
BASE = 0xF000
LONG = chr(92) * 2 + "?" + chr(92)


def enc_seg(s):
    out = "".join(chr(BASE + ord(c)) if (c in BAD or ord(c) < 32) else c for c in s)
    if out and out[-1] in ". ":
        out = out[:-1] + chr(BASE + ord(out[-1]))
    if out.split(".")[0].upper() in RESERVED:
        out = chr(BASE + ord(out[0])) + out[1:]
    return out


def dec_seg(s):
    return "".join(chr(ord(c) - BASE) if BASE <= ord(c) < BASE + 128 else c for c in s)


def enc(p):
    return "/".join(enc_seg(s) for s in p.split("/"))


def dec(p):
    return "/".join(dec_seg(s) for s in p.replace("\\", "/").split("/"))


def lp(root, rel=""):
    """Long-path safe absolute Windows path for root/enc(rel)."""
    import os
    full = os.path.abspath(os.path.join(root, enc(rel) if rel else ""))
    full = full.replace("/", "\\")
    if os.name == "nt" and not full.startswith(LONG):
        full = LONG + full
    return full
