"""Deterministic, shape-preserving pseudonyms.

A pseudonym keeps the length, letter case, digit positions and separators of
the original, so it can be written back into fixed-size binary fields without
moving anything. The same original (case-insensitive) always maps to the same
pseudonym.
"""
import hashlib
import hmac
import os

KEY = os.environ.get("DEID_KEY", "machina-deid-local").encode()

CONS = "bcdfghjklmnprstvz"
VOWS = "aeiou"


def _bytes(seed):
    i = 0
    while True:
        block = hmac.new(KEY, f"{seed}|{i}".encode("utf-8"), hashlib.sha256).digest()
        yield from block
        i += 1


_cache = {}
_KEEP_LABELS = {"www", "com", "org", "net", "edu", "gov", "io", "de", "uk", "fr", "it", "es", "nl",
                "jp", "cn", "ch", "at", "eu", "us", "ca", "au", "co", "ac", "mx", "ar", "tr", "in"}


def _domain_like(k):
    if " " in k or "/" in k or "\\" in k or k.count(".") < 1:
        return False
    labels = k.replace("@", ".").split(".")
    return len(labels) >= 2 and labels[-1] in _KEEP_LABELS and all(labels)


OVERRIDE = {}


def load_overrides(m):
    OVERRIDE.clear()
    OVERRIDE.update(m)
    _cache.clear()


def assign(keys, reserved=()):
    """Collision-free pseudonyms for a set of identities (deterministic)."""
    used = {}
    taken = {k.lower() for k in reserved}
    out = {}
    for k in sorted({k.lower() for k in keys}, key=lambda s: (len(s), s)):
        p = _raw_base(k, 0)
        n = 0
        while (p in used and used[p] != k) or (p in taken and p != k):
            n += 1
            p = _raw_base(k, n)
            if n > 50:
                break
        used[p] = k
        if n:
            out[k] = p
    return out


def _raw_base(k, n):
    if n == 0:
        return base_nocache(k)
    return _skeleton(f"{k}#{n}", k) if not _domain_like(k) else base_nocache(k + f"#{n}")[: len(k)]


def base(orig):
    """Lower-case pseudonym skeleton for orig (cached)."""
    k = orig.lower()
    p = OVERRIDE.get(k) or _cache.get(k)
    if p is not None:
        return p
    p = base_nocache(k)
    _cache[k] = p
    return p


def base_nocache(k):
    if _domain_like(k):
        # keep www/TLD labels so the result still reads as a host name
        local, at, dom = k.rpartition("@") if "@" in k else ("", "", k)
        labels = dom.split(".")
        new = []
        for i, lab in enumerate(labels):
            keep = lab in _KEEP_LABELS and (i == 0 and lab == "www" or i >= len(labels) - 2 and i > 0)
            new.append(lab if keep else base(lab))
        return (base(local) + "@" if at else "") + ".".join(new)
    return _skeleton(k, k)


def _skeleton(seed, k):
    rnd = _bytes(seed)
    out = []
    pos = 0  # position inside the current alphabetic run
    for ch in k:
        if ch.isalpha():
            if pos % 2 == 0:
                out.append(CONS[next(rnd) % len(CONS)])
            else:
                out.append(VOWS[next(rnd) % len(VOWS)])
            pos += 1
        elif ch.isdigit():
            out.append(str(next(rnd) % 10))
            pos = 0
        else:
            out.append(ch if ch.isascii() else "x")
            pos = 0
    p = "".join(out)
    if p == k:  # all separators, nothing to hide
        p = "".join("x" if c.isascii() else c for c in k)
    return p


def apply_case(p, like):
    out = []
    for a, b in zip(p, like):
        out.append(a.upper() if b.isupper() else a)
    out.extend(p[len(like):])
    return "".join(out)


def pseudonym(orig):
    """Pseudonym with the case pattern of orig."""
    return apply_case(base(orig), orig)


def fit_bytes(new, old_len, pad=b" "):
    """Fit encoded pseudonym into old_len bytes."""
    if len(new) > old_len:
        return new[:old_len]
    if len(new) < old_len:
        n = old_len - len(new)
        return new + (pad * n)[:n]
    return new
