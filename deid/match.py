"""Multi-pattern, case-insensitive, length-preserving replacement over bytes."""
import ahocorasick

from .pseudo import base, apply_case, fit_bytes


def _isalnum_byte(b):
    return (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or b >= 0x80


def _cls(b):
    if 48 <= b <= 57:
        return "d"
    if 65 <= b <= 90:
        return "U"
    if 97 <= b <= 122:
        return "l"
    if b >= 0x80:
        return "x"
    return " "


def _left_ok(prev, first):
    p, f = _cls(prev), _cls(first)
    if p == " ":
        return True
    if p == "x" or f == "x":
        return False
    if p == "d" and f != "d":
        return True
    if p != "d" and f == "d":
        return True
    if p == "l" and f == "U":
        return True
    return False


def _right_ok(last, nxt, nxt2):
    l, n = _cls(last), _cls(nxt)
    if n == " ":
        return True
    if l == "x" or n == "x":
        return False
    if l == "d" and n != "d":
        return True
    if l != "d" and n == "d":
        return True
    if n == "U" and (l == "l" or _cls(nxt2) == "l"):
        return True
    return False


class Matcher:
    """Replaces every registered identity with its pseudonym.

    Matching is ASCII case-insensitive, with word/camel-case boundary checks so
    short identities do not fire inside unrelated words.
    """

    def __init__(self, terms, loose=()):
        # loose terms skip the boundary check (emails, domains, long names)
        self.terms = {}
        for t in terms:
            t = t.strip()
            if t:
                self.terms[t.lower()] = not t.isascii()
        for t in loose:
            t = t.strip()
            if t:
                self.terms[t.lower()] = True
        self.a8 = ahocorasick.Automaton()
        self.a16 = ahocorasick.Automaton()
        for k, loose_flag in self.terms.items():
            b8 = k.encode("utf-8")
            self.a8.add_word(b8.decode("latin1"), (k, len(b8), loose_flag))
            b16 = k.encode("utf-16-le")
            self.a16.add_word(b16.decode("latin1"), (k, len(b16), loose_flag))
        if self.terms:
            self.a8.make_automaton()
            self.a16.make_automaton()

    def __bool__(self):
        return bool(self.terms)

    def _spans(self, low, auto, width, data=None):
        src = low if data is None else data
        """Non-overlapping, leftmost-longest matches -> (start, end, key)."""
        cands = []
        for end, (k, n, loose) in auto.iter(low.decode("latin1")):
            s = end - n + 1
            if width == 2 and s % 2:
                continue
            cands.append((s, end + 1, k, loose))
        if not cands:
            return []
        cands.sort(key=lambda c: (c[0], -(c[1] - c[0])))
        out = []
        last_end = -1
        L = len(low)
        for s, e, k, loose in cands:
            if s < last_end:
                continue
            if not loose:
                if width == 1:
                    prev = src[s - 1] if s > 0 else 32
                    nxt = src[e] if e < L else 32
                    nxt2 = src[e + 1] if e + 1 < L else 32
                    first, last = src[s], src[e - 1]
                else:
                    prev = src[s - 2] if s >= 2 and src[s - 1] == 0 else 32
                    nxt = src[e] if e + 1 < L and src[e + 1] == 0 else 32
                    nxt2 = src[e + 2] if e + 3 < L and src[e + 3] == 0 else 32
                    first, last = src[s], src[e - 2]
                if not (_left_ok(prev, first) and _right_ok(last, nxt, nxt2)):
                    continue
            out.append((s, e, k))
            last_end = e
        return out

    def replace(self, data, utf16=True, fixed=True):
        """Replacement in raw bytes, length-preserving when fixed. Returns (data, n)."""
        if not self.terms or not data:
            return data, 0
        low = data.lower()
        n = 0
        buf = None
        if not fixed:
            spans = self._spans(low, self.a8, 1, data)
            if not spans:
                return data, 0
            parts, pos = [], 0
            for s, e, k in spans:
                seg = bytes(data[s:e])
                orig = seg.decode("utf-8", "replace")
                parts.append(data[pos:s])
                parts.append(apply_case(base(k), orig).encode("utf-8"))
                pos = e
            parts.append(data[pos:])
            return b"".join(parts), len(spans)
        for s, e, k in self._spans(low, self.a8, 1, data):
            if buf is None:
                buf = bytearray(data)
            seg = bytes(data[s:e])
            try:
                orig = seg.decode("utf-8")
            except UnicodeDecodeError:
                orig = seg.decode("latin1")
            new = apply_case(base(k), orig).encode("utf-8")
            buf[s:e] = fit_bytes(new, e - s)
            n += 1
        if utf16 and b"\x00" in data:
            src = bytes(buf) if buf is not None else data
            low = src.lower()
            for s, e, k in self._spans(low, self.a16, 2, src):
                if buf is None:
                    buf = bytearray(data)
                orig = bytes(src[s:e]).decode("utf-16-le", "replace")
                new = apply_case(base(k), orig).encode("utf-16-le")
                buf[s:e] = fit_bytes(new, e - s, b" \x00")
                n += 1
        return (bytes(buf) if buf is not None else data), n

    def replace_text(self, text):
        """Replacement on a str (paths, metadata values)."""
        if not self.terms or not text:
            return text
        b = text.encode("utf-8")
        nb, n = self.replace(b, utf16=False, fixed=False)
        return nb.decode("utf-8", "replace") if n else text

    def find(self, data):
        """Keys present in data (for reporting / per-page search)."""
        low = data.lower()
        keys = {k for _, _, k in self._spans(low, self.a8, 1, data)}
        if b"\x00" in data:
            keys |= {k for _, _, k in self._spans(low, self.a16, 2, data)}
        return keys
