#!/usr/bin/env python3
"""De-identify the Machina CAD corpus.

    python run.py discover --input ./input --work ./work
    python run.py rewrite  --input ./input --output ./out/corpus --work ./work
    python run.py all      --input ./input --output ./out/corpus --work ./work

discover builds the identity registry (work/registry.json, private);
rewrite writes the de-identified corpus with renamed paths.
"""
import argparse
import collections
import json
import os
import sys
import time
import traceback
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from deid import seeds, discover as D  # noqa: E402
from deid.handlers import Ctx, process, ext_of  # noqa: E402
from deid.match import Matcher  # noqa: E402
from deid.pseudo import pseudonym  # noqa: E402
from deid import winpath  # noqa: E402

MAX_SIZE = 3 * 1024 ** 3


def list_files(root):
    out = []
    base = winpath.lp(root)
    for dp, dn, fn in os.walk(base):
        for f in fn:
            if f.endswith(".part"):
                continue
            full = os.path.join(dp, f)
            rel = os.path.relpath(full, base).replace("\\", "/")
            if rel.startswith(".get-input"):
                continue
            out.append(winpath.dec(rel))
    out.sort()
    return out


# ------------------------------------------------------------------ discovery

def _discover_one(args):
    root, rel = args
    found = {}
    try:
        p = winpath.lp(root, rel)
        if os.path.getsize(p) > MAX_SIZE:
            return rel, found, "skipped-large"
        with open(p, "rb") as f:
            data = f.read()
        ctx = Ctx(collect=found)
        process(data, rel, ctx)
        return rel, found, ";".join(ctx.notes)
    except Exception as e:
        return rel, found, f"error {e!r}"


def build_registry(paths, found_by_file, work):
    owners = seeds.owners_from_paths(paths)
    domains = seeds.domains_from_paths(paths)
    terms = set()
    loose = set()
    for t in seeds.seed_terms():
        if len(t) >= 4 or not t.isascii():
            terms.add(t)
    for o in owners:
        if o.lower() not in seeds.OWNER_PATH_ONLY and len(o) >= 4:
            terms.add(o)
    loose |= domains
    # discovered values; skip ones that look like vocabulary (seen everywhere)
    counts = collections.Counter()
    roots = collections.defaultdict(set)
    for rel, found in found_by_file.items():
        root = "/".join(rel.split("/")[:3])
        for kind, vals in found.items():
            for v in vals:
                counts[(kind, v)] += 1
                roots[(kind, v)].add(root)
    users, fields, emails = set(), set(), set()
    for (kind, v), n in counts.items():
        if kind == "user":
            if len(v) >= 4 and not D.is_generic(v):
                users.add(v)
        elif kind in ("field_strong", "field"):
            parts = D.split_saved_by(v)
            for p in parts:
                if len(p) >= 4 and not D.is_generic(p):
                    fields.add(p)
            if kind == "field_strong" and not parts and len(roots[(kind, v)]) <= 25:
                fields.add(v)
        elif kind == "email":
            emails.add(v)
    terms |= users
    terms |= fields
    for e in emails:
        loose.add(e)
        local, _, dom = e.partition("@")
        if dom.lower() not in D.EMAIL_PROVIDERS and "." in dom:
            loose.add(dom)
        if len(local) >= 5 and not D.is_generic(local) and local.lower() not in (
                "info", "support", "sales", "contact", "admin", "office", "hello", "mail", "service", "noreply"):
            terms.add(local)
    weak = {v for (k, v) in counts if k == "field"}
    every = set(terms) | set(loose) | weak | set(owners) | set(users)
    for (k, v) in counts:
        if k in ("field", "field_strong"):
            every |= set(D.split_saved_by(v))
    from deid.pseudo import assign
    pmap = assign(every, reserved=every)
    reg = {
        "pmap": pmap,
        "terms": sorted(terms),
        "loose": sorted(loose),
        "owners": sorted(owners),
        "path_only": sorted(seeds.OWNER_PATH_ONLY),
        "discovered": {
            "users": sorted(users),
            "fields": sorted(fields),
            "fields_weak": sorted({v for (k, v) in counts if k == "field"}),
            "emails": sorted(emails),
        },
    }
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(work, "registry.json"), "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=1, ensure_ascii=False)
    return reg


def cmd_discover(a):
    paths = list_files(a.input)
    if a.only:
        paths = [p for p in paths if any(s in p for s in a.only.split(","))]
    print(f"{len(paths)} files", flush=True)
    os.makedirs(a.work, exist_ok=True)
    cache_path = os.path.join(a.work, "discover_cache.json")
    cache = {}
    if os.path.exists(cache_path) and not a.fresh:
        with open(cache_path, encoding="utf-8") as f:
            cache = json.load(f)
    found_by_file = {}
    notes = {}
    todo = []
    for p in paths:
        size = os.path.getsize(winpath.lp(a.input, p))
        c = cache.get(p)
        if c and c[0] == size:
            if c[1]:
                found_by_file[p] = {k: set(v) for k, v in c[1].items()}
        else:
            todo.append(p)
    print(f"  {len(todo)} need scanning", flush=True)
    t0 = time.time()
    with Pool(a.jobs) as pool:
        for i, (rel, found, note) in enumerate(pool.imap_unordered(
                _discover_one, [(a.input, p) for p in todo], chunksize=16)):
            if found:
                found_by_file[rel] = found
            if note:
                notes[rel] = note
            cache[rel] = [os.path.getsize(winpath.lp(a.input, rel)), {k: sorted(v) for k, v in found.items()}]
            if i % 5000 == 0:
                print(f"  discover {i}/{len(todo)} {time.time() - t0:.0f}s", flush=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False)
    reg = build_registry(paths, found_by_file, a.work)
    with open(os.path.join(a.work, "discover_notes.json"), "w", encoding="utf-8") as f:
        json.dump(notes, f, indent=0, ensure_ascii=False)
    print(f"registry: {len(reg['terms'])} terms, {len(reg['loose'])} loose", flush=True)


# ------------------------------------------------------------------ rewrite

_M = None
_REG = None


def _load(work):
    with open(os.path.join(work, "registry.json"), encoding="utf-8") as f:
        return json.load(f)


def _init(work):
    global _M, _REG
    _REG = _load(work)
    from deid import pseudo
    pseudo.load_overrides(_REG.get("pmap", {}))
    _M = Matcher(_REG["terms"], _REG["loose"])


def rename_segment(seg, m, is_file):
    if is_file:
        stem, dot, ext = seg.rpartition(".")
        if not dot or not stem:
            return m.replace_text(seg)
        # Creo versions: name.prt.3
        if ext.isdigit() and "." in stem:
            s2, _, e2 = stem.rpartition(".")
            return m.replace_text(s2) + "." + e2 + "." + ext
        return m.replace_text(stem) + "." + ext
    return m.replace_text(seg)


def rename_path(rel, m, owners_mode=True):
    segs = rel.split("/")
    out = []
    for i, s in enumerate(segs):
        is_file = i == len(segs) - 1
        if owners_mode and ((i == 2 and segs[0] == "sources" and segs[1] in ("github", "gitlab"))
                            or (i == 1 and segs[0] == "archives")):
            parts = s.split("__")
            if segs[1] == "gitlab" and parts and parts[0] == "gitlab.com" and len(parts) > 1:
                parts[1] = pseudonym(parts[1])
                rest = [m.replace_text(x) for x in parts[2:]]
                head = parts[:2]
            else:
                parts[0] = pseudonym(parts[0])
                head = parts[:1]
                rest = parts[1:]
                if is_file and rest:
                    last = rest[-1]
                    rest = [m.replace_text(x) for x in rest[:-1]] + [rename_segment(last, m, True)]
                    out.append("__".join(head + rest))
                    continue
                rest = [m.replace_text(x) for x in rest]
            out.append("__".join(head + rest))
            continue
        out.append(rename_segment(s, m, is_file))
    return "/".join(out)


def _rewrite_one(args):
    root, out_root, rel = args
    try:
        new_rel = rename_path(rel, _M)
        src = winpath.lp(root, rel)
        size = os.path.getsize(src)
        ctx = Ctx(matcher=_M)
        ctx.rename = lambda r: "/".join(rename_segment(s, _M, i == len(r.split("/")) - 1)
                                        for i, s in enumerate(r.split("/")))
        with open(src, "rb") as f:
            data = f.read()
        if size > MAX_SIZE:
            new = data
            ctx.notes.append("large:copied")
        else:
            new = process(data, rel, ctx)
        dst = winpath.lp(out_root, new_rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(new)
        return rel, new_rel, size, new != data, ";".join(ctx.notes)
    except Exception as e:
        return rel, None, 0, False, "error " + repr(e) + " " + traceback.format_exc(limit=3).replace("\n", " | ")


def cmd_rewrite(a):
    paths = list_files(a.input)
    if a.only:
        paths = [p for p in paths if any(s in p for s in a.only.split(","))]
    print(f"{len(paths)} files", flush=True)
    os.makedirs(a.work, exist_ok=True)
    t0 = time.time()
    log = open(os.path.join(a.work, "results.tsv"), "w", encoding="utf-8")
    n_changed = n_err = 0
    with Pool(a.jobs, initializer=_init, initargs=(a.work,)) as pool:
        for i, (rel, new_rel, size, changed, note) in enumerate(pool.imap_unordered(
                _rewrite_one, [(a.input, a.output, p) for p in paths], chunksize=8)):
            log.write(f"{rel}\t{new_rel}\t{size}\t{int(changed)}\t{note}\n")
            n_changed += changed
            n_err += new_rel is None
            if i % 5000 == 0:
                print(f"  rewrite {i}/{len(paths)} changed={n_changed} err={n_err} {time.time() - t0:.0f}s", flush=True)
    log.close()
    print(f"done: changed={n_changed} errors={n_err} {time.time() - t0:.0f}s", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["discover", "rewrite", "all"])
    ap.add_argument("--input", required=True)
    ap.add_argument("--output")
    ap.add_argument("--work", required=True)
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--only", help="substring filter on paths (testing)")
    ap.add_argument("--fresh", action="store_true", help="ignore the discovery cache")
    a = ap.parse_args()
    if a.cmd in ("discover", "all"):
        cmd_discover(a)
    if a.cmd in ("rewrite", "all"):
        cmd_rewrite(a)


if __name__ == "__main__":
    main()
