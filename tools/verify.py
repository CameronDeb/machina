#!/usr/bin/env python3
"""Spot-check an output corpus: leftover identities and file integrity.

    python tools/verify.py --input IN --output OUT --work WORK [--sample N]
"""
import argparse
import io
import json
import os
import random
import re
import sys
import zipfile
import zlib
from multiprocessing import Pool

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from deid import winpath, swfile  # noqa: E402
from deid.match import Matcher  # noqa: E402

M = None


def init(work):
    global M
    reg = json.load(open(os.path.join(work, "registry.json"), encoding="utf-8"))
    M = Matcher(reg["terms"], reg["loose"])


def payloads(data, name):
    """Yield decoded payloads we can see inside a file."""
    yield data
    if swfile.is_sw(data):
        for n, p in swfile.streams(data):
            yield p
    elif data[:4] == b"PK\x03\x04":
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            for i in z.infolist():
                yield i.filename.encode()
                yield from payloads(z.read(i), i.filename)
        except Exception:
            pass
    elif data[:4] == b"%PDF":
        try:
            import pymupdf
            d = pymupdf.open(stream=data, filetype="pdf")
            yield json.dumps(d.metadata).encode()
            yield (d.get_xml_metadata() or "").encode()
            for pg in d:
                yield pg.get_text().encode()
        except Exception:
            pass


def integrity(data, name):
    ext = name.lower().rsplit(".", 1)[-1]
    try:
        if swfile.is_sw(data):
            n = sum(1 for _ in swfile.records(data))
            return "ok" if n else "sw-broken"
        if data[:4] == b"%PDF":
            import pymupdf
            d = pymupdf.open(stream=data, filetype="pdf")
            _ = d.page_count
            return "ok"
        if data[:4] == b"PK\x03\x04":
            z = zipfile.ZipFile(io.BytesIO(data))
            bad = z.testzip()
            return "ok" if bad is None else f"zip-bad {bad}"
        if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            import olefile
            olefile.OleFileIO(io.BytesIO(data)).listdir()
            return "ok"
        if ext in ("step", "stp"):
            return "ok" if data.lstrip()[:9] == b"ISO-10303" and b"ENDSEC" in data else "step-bad"
    except Exception as e:
        return f"bad {e!r}"[:80]
    return "ok"


NUM = re.compile(rb"[-+]?\d+\.\d*(?:[eE][-+]?\d+)?")


def check(args):
    inp, out, rel, new_rel = args
    try:
        src = open(winpath.lp(inp, rel), "rb").read()
        dst = open(winpath.lp(out, new_rel), "rb").read()
    except Exception as e:
        return rel, "missing " + repr(e), [], ""
    left = set()
    for p in payloads(dst, new_rel):
        left |= M.find(p)
    left |= M.find(new_rel.encode())
    integ = integrity(dst, new_rel)
    geo = ""
    ext = rel.lower().rsplit(".", 1)[-1]
    if ext in ("step", "stp") and len(src) < 50_000_000:
        a = src.find(b"DATA;")
        if NUM.findall(src[a:]) != NUM.findall(dst[dst.find(b"DATA;"):]):
            geo = "step-numbers-changed"
    if integrity(src, rel) == "ok" and integ != "ok":
        geo += " broke"
    return rel, integ, sorted(left), geo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--sample", type=int, default=2000)
    ap.add_argument("--jobs", type=int, default=8)
    a = ap.parse_args()
    rows = [l.rstrip("\n").split("\t") for l in open(os.path.join(a.work, "results.tsv"), encoding="utf-8")]
    rows = [r for r in rows if r[1] != "None"]
    random.seed(0)
    if a.sample and len(rows) > a.sample:
        rows = random.sample(rows, a.sample)
    bad = left = broke = 0
    with Pool(a.jobs, initializer=init, initargs=(a.work,)) as pool:
        for rel, integ, lft, geo in pool.imap_unordered(check, [(a.input, a.output, r[0], r[1]) for r in rows], 4):
            if integ != "ok" or lft or geo:
                print(f"{integ}\t{geo}\t{lft[:6]}\t{rel}")
            bad += integ != "ok"
            left += bool(lft)
            broke += "broke" in geo or "changed" in geo
    print(f"checked={len(rows)} integrity_bad={bad} leftover={left} broke={broke}")


if __name__ == "__main__":
    main()
