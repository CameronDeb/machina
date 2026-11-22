#!/usr/bin/env python3
"""Attempt uploader for slow links.

Same protocol and token as the organisers' upload.py, plus:
  * smallest files first, so most files land early on a slow uplink;
  * local names written with deid/winpath.py are decoded back to the real path;
  * --reuse gs://.../attempt-K/ copies byte-identical files server side
    instead of uploading them again (falls back to a normal upload).
"""
import argparse
import hashlib
import http.client
import os
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from deid import winpath  # noqa: E402

HOST = "storage.googleapis.com"


class Token:
    def __init__(self, tok, path):
        self.tok, self.path, self.lock = tok, path, threading.Lock()

    def get(self):
        if self.path and os.path.exists(self.path):
            t = open(self.path).read().strip()
            if t:
                self.tok = t
        return self.tok

    def wait_new(self, stale):
        with self.lock:
            print("token expired; write a new one to", self.path, flush=True)
            while True:
                t = self.get()
                if t and t != stale:
                    return t
                time.sleep(5)


def enc_key(k):
    return "/".join(urllib.parse.quote(p, safe="") for p in k.split("/"))


def expired(status, body):
    return status == 401 or (status in (400, 403) and b"xpired" in body)


def list_prefix(bucket, prefix, tok):
    found, cont = {}, None
    conn = http.client.HTTPSConnection(HOST, timeout=60)
    while True:
        q = {"list-type": "2", "prefix": prefix, "max-keys": "1000", "encoding-type": "url"}
        if cont:
            q["continuation-token"] = cont
        t = tok.get()
        conn.request("GET", f"/{bucket}/?{urllib.parse.urlencode(q)}", headers={"Authorization": f"Bearer {t}"})
        r = conn.getresponse()
        body = r.read()
        if expired(r.status, body):
            tok.wait_new(t)
            continue
        if r.status != 200:
            raise RuntimeError(f"list {r.status} {body[:300]}")
        root = ET.fromstring(body)
        ns = root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""
        for it in root.findall(f"{ns}Contents"):
            k = urllib.parse.unquote_plus(it.findtext(f"{ns}Key") or "")
            found[k] = (int(it.findtext(f"{ns}Size") or 0), (it.findtext(f"{ns}ETag") or "").strip('"').lower())
        if root.findtext(f"{ns}IsTruncated") != "true":
            break
        cont = root.findtext(f"{ns}NextContinuationToken")
    conn.close()
    return found


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


tl = threading.local()


def conn():
    c = getattr(tl, "c", None)
    if c is None:
        c = tl.c = http.client.HTTPSConnection(HOST, timeout=300)
    return c


def reset():
    c = getattr(tl, "c", None)
    if c:
        try:
            c.close()
        except Exception:
            pass
    tl.c = None


def put(bucket, key, local, tok, copy_src=None):
    url = f"/{bucket}/{enc_key(key)}"
    for attempt in range(8):
        t = tok.get()
        try:
            c = conn()
            if copy_src:
                c.request("PUT", url, headers={"Authorization": f"Bearer {t}", "Content-Length": "0",
                                               "x-goog-copy-source": f"/{bucket}/{enc_key(copy_src)}"})
            else:
                size = os.path.getsize(local)
                c.putrequest("PUT", url)
                c.putheader("Authorization", f"Bearer {t}")
                c.putheader("Content-Length", str(size))
                c.putheader("Content-Type", "application/octet-stream")
                c.endheaders()
                with open(local, "rb") as f:
                    for b in iter(lambda: f.read(1 << 20), b""):
                        c.send(b)
            r = c.getresponse()
            body = r.read()
            if expired(r.status, body):
                tok.wait_new(t)
                continue
            if 200 <= r.status < 300:
                return True
            if copy_src and r.status in (403, 404, 400):
                return False
            reset()
            time.sleep(min(30, 2 ** attempt))
        except (OSError, http.client.HTTPException):
            reset()
            time.sleep(min(30, 2 ** attempt))
    raise RuntimeError(f"PUT failed {key}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", required=True)
    ap.add_argument("--corpus")
    ap.add_argument("--code")
    ap.add_argument("--readme")
    ap.add_argument("--token", default=os.environ.get("MACHINA_UPLOAD_TOKEN", ""))
    ap.add_argument("--token-file")
    ap.add_argument("--reuse", help="earlier attempt folder (gs://...) to copy identical files from")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--max-bytes", type=float, default=0, help="stop after this many GB of real uploads")
    a = ap.parse_args()
    tok = Token(a.token.strip(), a.token_file)
    rest = a.dest[len("gs://"):]
    bucket, prefix = rest.split("/", 1)
    prefix = prefix.rstrip("/") + "/"

    items = []
    for folder, sub in ((a.code, "code"), (a.corpus, "corpus")):
        if not folder:
            continue
        base = winpath.lp(folder)
        for dp, _dn, fn in os.walk(base):
            for f in fn:
                full = os.path.join(dp, f)
                rel = winpath.dec(os.path.relpath(full, base).replace("\\", "/"))
                items.append((full, f"{prefix}{sub}/{rel}", os.path.getsize(full)))
    if a.readme:
        items.append((os.path.abspath(a.readme), f"{prefix}README.txt", os.path.getsize(a.readme)))
    have = list_prefix(bucket, prefix, tok)
    reuse = {}
    if a.reuse:
        rb, rp = a.reuse[len("gs://"):].split("/", 1)
        rp = rp.rstrip("/") + "/"
        for k, (s, e) in list_prefix(rb, rp, tok).items():
            reuse.setdefault((s, e), k)
    todo = []
    for full, key, size in items:
        h = have.get(key)
        if h and h[0] == size and (len(h[1]) != 32 or md5(full) == h[1]):
            continue
        todo.append((full, key, size))
    # README and code first, then corpus smallest first
    todo.sort(key=lambda x: (not x[1].startswith(prefix + "corpus/") and 0 or 1, x[2]))
    print(f"{len(items)} files, {len(todo)} to send ({sum(x[2] for x in todo)/1e9:.1f} GB)", flush=True)
    sent = copied = 0
    sent_b = 0
    t0 = time.time()
    lock = threading.Lock()
    stop = threading.Event()

    def job(it):
        nonlocal sent, copied, sent_b
        full, key, size = it
        if stop.is_set():
            return
        if reuse:
            src = reuse.get((size, md5(full)))
            if src and put(bucket, key, full, tok, copy_src=src):
                with lock:
                    copied += 1
                return
        put(bucket, key, full, tok)
        with lock:
            sent += 1
            sent_b += size
            if a.max_bytes and sent_b > a.max_bytes * 1e9:
                stop.set()
            if (sent + copied) % 500 == 0:
                el = time.time() - t0
                print(f"  sent={sent} copied={copied} {sent_b/1e9:.2f}GB {sent_b/1e6/el:.2f}MB/s", flush=True)

    with ThreadPoolExecutor(a.workers) as ex:
        for f in as_completed([ex.submit(job, it) for it in todo]):
            f.result()
    print(f"done sent={sent} copied={copied} {sent_b/1e9:.2f}GB -> gs://{bucket}/{prefix}", flush=True)


if __name__ == "__main__":
    main()
