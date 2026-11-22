"""Per-format rewriting.

Every handler takes (data, relpath, ctx) and returns new bytes. In discovery
mode (ctx.collect is not None) handlers only record identities they see.
"""
import io
import os
import re
import struct
import zlib
import zipfile
import tarfile
import gzip

from . import swfile
from .discover import (find_users, find_emails, PEOPLE_FIELD, clean_value, is_generic, strong,
                       EMAIL_PROVIDERS)
from .pseudo import pseudonym, fit_bytes
from .match import Matcher

TEXT_EXT = {
    ".step", ".stp", ".p21", ".igs", ".iges", ".dxf", ".obj", ".wrl", ".vrml", ".svg", ".ps", ".eps",
    ".x_t", ".xmt_txt", ".unv", ".brep", ".sat", ".sab", ".txt", ".md", ".csv", ".tsv", ".json",
    ".xml", ".html", ".htm", ".scad", ".py", ".yaml", ".yml", ".ini", ".cfg", ".gcode", ".nc", ".ngc",
    ".tap", ".mtl", ".ply", ".off", ".amf", ".urdf", ".sdf", ".xacro", ".dae", ".kicad_pcb", ".kicad_sch",
    ".sch", ".brd", ".lib", ".rst", ".tex", ".bib", ".log", ".bat", ".sh", ".js", ".css", ".ipj",
}
ZIP_EXT = {".zip", ".fcstd", ".3mf", ".f3d", ".f3z", ".docx", ".xlsx", ".pptx", ".odt", ".ods",
           ".odg", ".fcmacro.zip", ".kmz", ".epub", ".ipt.zip", ".smg", ".skp_zip"}
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp"}


class Ctx:
    def __init__(self, matcher=None, collect=None, path_matcher=None):
        self.m = matcher or Matcher([])
        self.collect = collect  # dict kind -> set, or None in rewrite mode
        self.notes = []
        self.depth = 0
        self.rename = None  # function(relpath) -> new relpath, set by runner

    def add(self, kind, value):
        if self.collect is not None and value:
            self.collect.setdefault(kind, set()).add(value)


def ext_of(path):
    name = path.rsplit("/", 1)[-1].lower()
    # Creo versioned files: part.prt.3 -> treat by real extension
    m = re.match(r"^(.*?)(\.[a-z0-9_]+)\.\d+$", name)
    if m:
        return m.group(2) + ".N"
    return os.path.splitext(name)[1]


# ---------------------------------------------------------------- generic

def scan_generic(data, ctx):
    for u in find_users(data):
        ctx.add("user", u)
    for e in find_emails(data):
        ctx.add("email", e)


USERCTX8 = re.compile(
    rb"(?i)((?:[a-z]:[\\/]+(?:users|documents and settings|docume~1)[\\/]+|/home/|/users/))([^\\/:*?\"<>|\x00-\x1f%$]{2,3})(?=[\\/])")


def generic(data, ctx, local=None):
    """Length-preserving replacement of every known identity in raw bytes."""
    if ctx.collect is not None:
        scan_generic(data, ctx)
        return data
    out, _ = ctx.m.replace(data)
    if local:
        out, _ = local.replace(out)
    # short user folder names only in path context
    if b"sers" in out or b"SERS" in out or b"home/" in out or b"DOCUME" in out:
        out = USERCTX8.sub(lambda m: m.group(1) + fit_bytes(pseudonym(m.group(2).decode("latin1")).encode(), len(m.group(2))), out)
    return out


def field_value(v, ctx, local_terms):
    """Pseudonym for an identity field value; registers it."""
    v2 = clean_value(v)
    if not v2 or not any(c.isalpha() for c in v2):
        return v
    if ctx.collect is not None:
        ctx.add("field_strong" if strong(v2) else "field", v2)
        return v
    local_terms.add(v2)
    new = pseudonym(v2)
    # keep surrounding whitespace / padding of the original
    i = v.find(v2)
    return v[:i] + new + v[i + len(v2):]


# ---------------------------------------------------------------- xml-ish fields

XML_FIELDS = [
    re.compile(rb"(<(?:dc:creator|cp:lastModifiedBy|dc:contributor|dc:publisher|meta:initial-creator|"
               rb"meta:creator|Company|Manager|Author|LastAuthor|cp:contentStatus|xmp:CreatorTool_x)>)([^<]{1,200})(</)"),
    re.compile(rb"(<metadata\s+name=\"(?:Designer|Copyright|LicenseTerms|DesignerUserId|DesignerCover|"
               rb"Rating|Origin|Author|CreatedBy|Creator)\"[^>]*>)([^<]{1,300})(</metadata>)"),
    re.compile(rb"(<Property\s+name=\"(?:CreatedBy|LastModifiedBy|Company|Author)\"[^>]*>\s*<String\s+value=\")([^\"]{1,200})(\")"),
    re.compile(rb"(<dc:(?:creator|rights|publisher|contributor)>\s*<cc:Agent>\s*<dc:title>)([^<]{1,200})(</dc:title>)"),
    re.compile(rb"(<dc:creator>\s*<rdf:(?:Seq|Bag)>\s*<rdf:li[^>]*>)([^<]{1,200})(</rdf:li>)"),
]
SW_PROP = re.compile(rb"(<property\s+name=\")([^\"]{1,80})(\"[^>]*>\s*<vt:lpstr>)([^<]{0,300})(</vt:lpstr>)")
SW_FPVAL = re.compile(rb"(<vt:lpstr>)([^<]{1,300})(</vt:lpstr>)")


def xml_fields(data, ctx, local_terms, rdf_ok=False):
    def sub_simple(m):
        if m.re is XML_FIELDS[4] and not rdf_ok:
            return m.group(0)
        raw = m.group(2)
        txt = raw.decode("utf-8", "replace")
        new = field_value(txt, ctx, local_terms)
        nb = new.encode("utf-8")
        return m.group(1) + fit_bytes(nb, len(raw)) + m.group(3)

    for rx in XML_FIELDS:
        data = rx.sub(sub_simple, data)

    def sub_prop(m):
        name = m.group(2).decode("utf-8", "replace")
        if not PEOPLE_FIELD.match(name.replace("SW-", "SW-")):
            return m.group(0)
        raw = m.group(4)
        txt = raw.decode("utf-8", "replace")
        if not txt.strip() or txt.strip().startswith('"SW-') or txt.strip().startswith("$PRP"):
            return m.group(0)
        new = field_value(txt, ctx, local_terms).encode("utf-8")
        return m.group(1) + m.group(2) + m.group(3) + fit_bytes(new, len(raw)) + m.group(5)

    data = SW_PROP.sub(sub_prop, data)
    return data


# ---------------------------------------------------------------- STEP

STEP_FN = re.compile(rb"FILE_NAME\s*\(", re.I)


def _step_strings(hdr, start):
    """Positions of quoted strings in FILE_NAME(...) starting at start."""
    out = []
    i = start
    depth = 1
    n = len(hdr)
    while i < n and depth > 0:
        c = hdr[i]
        if c == 0x27:  # '
            j = i + 1
            while j < n:
                if hdr[j] == 0x27:
                    if j + 1 < n and hdr[j + 1] == 0x27:
                        j += 2
                        continue
                    break
                j += 1
            out.append((i + 1, j, depth))
            i = j + 1
            continue
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
        i += 1
    return out


def step(data, ctx):
    head_end = data.find(b"ENDSEC", 0, 1 << 20)
    hdr = data[:head_end] if head_end > 0 else b""
    local_terms = set()
    m = STEP_FN.search(hdr)
    new_hdr = hdr
    if m:
        strs = _step_strings(hdr, m.end())
        # order: name, time_stamp, (author...), (organization...), preprocessor, originating, authorisation
        top = [s for s in strs if s[2] == 1]
        nested = [s for s in strs if s[2] == 2]
        targets = list(nested)
        if len(top) >= 5:
            targets.append(top[-1])  # authorisation
        buf = bytearray(hdr)
        for s, e, _d in sorted(targets, reverse=True):
            raw = bytes(hdr[s:e])
            txt = raw.decode("latin1")
            if not txt.strip():
                continue
            new = field_value(txt, ctx, local_terms)
            if ctx.collect is None and new != txt:
                buf[s:e] = new.encode("latin1", "replace")
        new_hdr = bytes(buf)
    data = new_hdr + data[len(hdr):] if ctx.collect is None else data
    lm = Matcher(local_terms) if local_terms else None
    return generic(data, ctx, lm)


# ---------------------------------------------------------------- IGES

def iges(data, ctx):
    # global section: lines with 'G' in column 73
    lines = data.split(b"\n")
    g = [i for i, l in enumerate(lines[:400]) if len(l) >= 73 and l[72:73] == b"G"]
    local_terms = set()
    if g:
        text = b"".join(lines[i][:72] for i in g)
        pd = b","
        if text[:2].endswith(b"H"):
            pd = text[2:3]
        # walk hollerith strings: nHxxxx
        params = []
        i = 0
        while i < len(text):
            mm = re.match(rb"\s*(\d+)H", text[i:])
            if mm:
                n = int(mm.group(1))
                s = i + mm.end()
                params.append((s, s + n))
                i = s + n
            else:
                params.append(None)
            j = text.find(pd, i)
            if j < 0:
                break
            i = j + 1
        # 1-based: 21 author, 22 organization
        for idx in (20, 21):
            if idx < len(params) and params[idx]:
                s, e = params[idx]
                txt = text[s:e].decode("latin1")
                new = field_value(txt, ctx, local_terms)
                if ctx.collect is None and new != txt:
                    nb = new.encode("latin1", "replace")
                    # map back onto the physical lines
                    flat = bytearray(text)
                    flat[s:e] = fit_bytes(nb, e - s)
                    text = bytes(flat)
        if ctx.collect is None and local_terms:
            for k, i in enumerate(g):
                lines[i] = text[k * 72:(k + 1) * 72] + lines[i][72:]
            data = b"\n".join(lines)
    lm = Matcher(local_terms) if local_terms else None
    return generic(data, ctx, lm)


# ---------------------------------------------------------------- DXF

DXF_VAR = re.compile(rb"(\$(?:LASTSAVEDBY|AUTHOR)\r?\n\s*1\r?\n)([^\r\n]*)")


def dxf(data, ctx):
    local_terms = set()

    def sub(m):
        txt = m.group(2).decode("latin1")
        new = field_value(txt, ctx, local_terms)
        return m.group(1) + fit_bytes(new.encode("latin1", "replace"), len(m.group(2)))

    data2 = DXF_VAR.sub(sub, data)
    if ctx.collect is None:
        data = data2
    lm = Matcher(local_terms) if local_terms else None
    return generic(data, ctx, lm)


# ---------------------------------------------------------------- SolidWorks 2015+

def _sw_stream(name, payload, ctx, local_terms):
    if name.endswith(".xml") or name.startswith("swXml") or payload[:5] == b"<?xml":
        payload = xml_fields(payload, ctx, local_terms)
    return payload


def solidworks(data, ctx, relpath):
    local_terms = set()
    ext = ext_of(relpath)
    if ctx.collect is not None:
        for name, payload in swfile.streams(data):
            _sw_stream(name, payload, ctx, local_terms)
            scan_generic(payload, ctx)
        return data
    # first pass: field values of this file
    for name, payload in swfile.streams(data):
        _sw_stream(name, payload, Ctx(ctx.m), local_terms)
    lm = Matcher(local_terms) if local_terms else None
    blank_preview = ext in (".slddrw", ".drwdot")

    def fn(name, payload):
        if blank_preview and name in ("PreviewPNG", "Preview"):
            return _blank_image(payload)
        p = _sw_stream(name, payload, ctx, set())
        return generic(p, ctx, lm)

    out, changed, failed = swfile.rewrite(data, fn)
    if failed:
        ctx.notes.append(f"sw:{failed} streams kept (no room to recompress)")
    return generic_outer(out, ctx, lm)


def generic_outer(data, ctx, lm):
    # uncompressed regions between records (rare) still get the plain pass
    return generic(data, ctx, lm)


def _blank_image(payload):
    """Same-size neutral replacement for a preview image."""
    if payload[:8] == b"\x89PNG\r\n\x1a\n":
        try:
            w, h = struct.unpack(">II", payload[16:24])
            png = _solid_png(w, h)
            if len(png) <= len(payload):
                return png + b"\x00" * (len(payload) - len(png))
        except Exception:
            return payload
        return payload
    return payload


def _solid_png(w, h, rgb=(235, 235, 235)):
    w = max(1, min(w, 4096))
    h = max(1, min(h, 4096))
    row = b"\x00" + bytes(rgb) * w
    raw = zlib.compress(row * h, 9)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", raw) + chunk(b"IEND", b""))


# ---------------------------------------------------------------- OLE

FMTID_SUMMARY = "f29f85e0-4ff9-1068-ab91-08002b27b3d9"
FMTID_DOCSUM = "d5cdd502-2e9c-101b-9397-08002b2cf9ae"
FMTID_USER = "d5cdd505-2e9c-101b-9397-08002b2cf9ae"
FMTID_INV_DESIGN = "32853f0f-3444-11d1-9e93-0060b03c1ca6"
FMTID_INV_SUMMARY = "f29f85e0-4ff9-1068-ab91-08002b27b3d9"
# string pids that hold a person or organisation, per property set
PEOPLE_PIDS = {
    FMTID_SUMMARY: {4, 8},                     # author, last saved by
    FMTID_DOCSUM: {14, 15},                    # manager, company
    FMTID_INV_DESIGN: {10, 12, 30, 34, 41, 42, 43, 48},  # checked/approved by, vendor, designer, engineer, authority, manufacturer
}


def _guid(b):
    import uuid
    return str(uuid.UUID(bytes_le=bytes(b)))


def _propset_values(buf):
    """Yield (offset, length, encoding, pid, fmtid, name) for string properties."""
    try:
        nsec = struct.unpack_from("<I", buf, 24)[0]
        for k in range(min(nsec, 4)):
            fmtid = _guid(buf[28 + k * 20:28 + k * 20 + 16])
            off = struct.unpack_from("<I", buf, 28 + k * 20 + 16)[0]
            size, n = struct.unpack_from("<II", buf, off)
            codepage = 1252
            entries = []
            for j in range(min(n, 2000)):
                pid, poff = struct.unpack_from("<II", buf, off + 8 + j * 8)
                entries.append((pid, off + poff))
            for pid, p in entries:
                if pid == 1:
                    t = struct.unpack_from("<H", buf, p)[0]
                    if t == 2:
                        codepage = struct.unpack_from("<h", buf, p + 4)[0] & 0xFFFF
            names = {}
            for pid, p in entries:
                if pid == 0:  # dictionary: count, then (pid, len, name)
                    cnt = struct.unpack_from("<I", buf, p)[0]
                    q = p + 4
                    for _ in range(min(cnt, 2000)):
                        npid, ln = struct.unpack_from("<II", buf, q)
                        q += 8
                        if codepage == 1200:
                            nm = buf[q:q + ln * 2].decode("utf-16-le", "replace")
                            q += ln * 2
                            q += (-q) % 4
                        else:
                            nm = buf[q:q + ln].decode("cp1252", "replace")
                            q += ln
                        names[npid] = nm.split("\x00")[0]
            for pid, p in entries:
                if pid < 2:
                    continue
                t = struct.unpack_from("<H", buf, p)[0]
                if t == 30:
                    ln = struct.unpack_from("<I", buf, p + 4)[0]
                    enc = "utf-16-le" if codepage == 1200 else ("utf-8" if codepage == 65001 else "cp1252")
                    yield p + 8, ln, enc, pid, fmtid, names.get(pid, "")
                elif t == 31:
                    ln = struct.unpack_from("<I", buf, p + 4)[0]
                    yield p + 8, ln * 2, "utf-16-le", pid, fmtid, names.get(pid, "")
    except Exception:
        return


def _people_prop(pid, fmtid, name):
    if fmtid in PEOPLE_PIDS:
        return pid in PEOPLE_PIDS[fmtid]
    if name:
        return bool(PEOPLE_FIELD.match(name))
    return False


def _whiten_dib(buf, off):
    """Paint a packed DIB (BITMAPINFOHEADER + pixels) at off white, in place."""
    try:
        hsize, w, h, planes, bpp = struct.unpack_from("<IiiHH", buf, off)
        if hsize not in (40, 108, 124) or bpp not in (1, 4, 8, 16, 24, 32):
            return buf
        clr = struct.unpack_from("<I", buf, off + 32)[0]
        pal = (clr or (1 << bpp)) * 4 if bpp <= 8 else 0
        comp = struct.unpack_from("<I", buf, off + 16)[0]
        if comp == 3:
            pal = 12
        start = off + hsize + pal
        size = ((w * bpp + 31) // 32) * 4 * abs(h)
        end = min(len(buf), start + size)
        if end <= start:
            return buf
        b = bytearray(buf)
        if bpp <= 8:
            # point every pixel at the palette's last (usually white) entry
            b[start:end] = b"\xff" * (end - start)
        else:
            b[start:end] = b"\xff" * (end - start)
        return bytes(b)
    except Exception:
        return buf


def _blank_propset_thumb(buf):
    """Blank PIDSI_THUMBNAIL (VT_CF DIB) in a SummaryInformation stream."""
    try:
        nsec = struct.unpack_from("<I", buf, 24)[0]
        if not nsec:
            return buf
        off = struct.unpack_from("<I", buf, 28 + 16)[0]
        _size, n = struct.unpack_from("<II", buf, off)
        for j in range(min(n, 200)):
            pid, poff = struct.unpack_from("<II", buf, off + 8 + j * 8)
            if pid != 17:
                continue
            p = off + poff
            t = struct.unpack_from("<H", buf, p)[0]
            if t != 71:
                return buf
            tag = struct.unpack_from("<i", buf, p + 8)[0]
            if tag == -1:
                cf = struct.unpack_from("<I", buf, p + 12)[0]
                if cf == 8:  # CF_DIB
                    return _whiten_dib(buf, p + 16)
            return buf
    except Exception:
        return buf
    return buf


# SummaryInformation: 4 author, 8 last author ; DocSummary: 14 manager, 15 company
SUMMARY_PIDS = {"\x05SummaryInformation": {4, 8}, "\x05DocumentSummaryInformation": {14, 15}}
# Inventor "Design Tracking Properties" string pids that hold people / org
INV_PIDS = {"\x05Qm4ylqj0Rd1ydquiCtc3Z0b5Ga": None}


def ole(data, ctx, relpath):
    import olefile
    try:
        f = olefile.OleFileIO(io.BytesIO(data))
    except Exception:
        ctx.notes.append("ole:unreadable")
        return generic(data, ctx)
    local_terms = set()
    streams = f.listdir(streams=True, storages=False)
    contents = {}
    for st in streams:
        name = "/".join(st)
        try:
            contents[name] = f.openstream(st).read()
        except Exception:
            continue
    f.close()
    # identity fields in property sets
    edits = {}
    for name, buf in contents.items():
        leaf = name.split("/")[-1]
        if not leaf.startswith("\x05"):
            if ctx.collect is not None:
                scan_generic(buf, ctx)
            continue
        nb = bytearray(buf)
        touched = False
        for off, ln, enc, pid, fmtid, pname in _propset_values(buf):
            if not _people_prop(pid, fmtid, pname):
                continue
            raw = bytes(buf[off:off + ln])
            try:
                txt = raw.decode(enc).split("\x00")[0]
            except Exception:
                continue
            if not txt.strip() or not any(c.isalpha() for c in txt) or len(txt) > 120:
                continue
            new = field_value(txt, ctx, local_terms)
            if ctx.collect is None and new != txt:
                enc_new = new.encode(enc, "replace")
                old_len = len(txt.encode(enc))
                nb[off:off + old_len] = fit_bytes(enc_new, old_len, b"\x00" if enc != "utf-16-le" else b"\x00\x00")
                touched = True
        if touched:
            edits[name] = bytes(nb)
    if ctx.collect is not None:
        return data
    lm = Matcher(local_terms) if local_terms else None
    drawing = ext_of(relpath) in (".idw", ".slddrw", ".drwdot", ".dft", ".dwg", ".drw", ".drw.N", ".catdrawing")
    for name, buf in contents.items():
        cur = edits.get(name, buf)
        if drawing:
            leaf = name.split("/")[-1]
            if leaf == "\x05SummaryInformation":
                cur = _blank_propset_thumb(cur)
            elif leaf in ("PreviewPNG", "Preview", "Thumbnail"):
                cur = _blank_image(cur) if cur[:8] == b"\x89PNG\r\n\x1a\n" else _whiten_dib(cur, 0)
        new = generic(cur, ctx, lm)
        if new != buf:
            edits[name] = new
        elif name in edits and edits[name] == buf:
            del edits[name]
    if not edits:
        return generic(data, ctx, lm)
    # write streams back (same sizes) into a copy
    bio = io.BytesIO(bytearray(data))
    try:
        f = olefile.OleFileIO(bio, write_mode=True)
        for name, buf in edits.items():
            f.write_stream(name.split("/"), buf)
        f.close()
        # stale copies in free sectors
        return generic(bio.getvalue(), ctx, lm)
    except Exception as e:
        ctx.notes.append(f"ole:write failed {e!r}")
        return generic(data, ctx, lm)


# ---------------------------------------------------------------- PDF

PDF_PEOPLE_KEYS = ("author",)
PDF_TEXT_KEYS = ("title", "subject", "keywords", "creator", "producer")


def pdf(data, ctx, relpath):
    import pymupdf
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception:
        ctx.notes.append("pdf:unreadable")
        return generic(data, ctx)
    if doc.needs_pass:
        ctx.notes.append("pdf:encrypted")
        doc.close()
        return generic(data, ctx)
    local_terms = set()
    meta = doc.metadata or {}
    if ctx.collect is not None:
        for k in PDF_PEOPLE_KEYS:
            v = meta.get(k) or ""
            if v.strip():
                field_value(v, ctx, local_terms)
        try:
            xmp = doc.get_xml_metadata() or ""
            if xmp:
                xml_fields(xmp.encode("utf-8"), ctx, local_terms, rdf_ok=False)
        except Exception:
            pass
        for page in doc:
            try:
                t = page.get_text().encode("utf-8")
            except Exception:
                continue
            for e in find_emails(t):
                ctx.add("email", e)
            for v in titleblock_names(page):
                if len(v.split()) >= 2 or "." in v:
                    field_value(v, ctx, local_terms)
        for name in _embfiles(doc):
            try:
                content = doc.embfile_get(name)
                info = doc.embfile_info(name)
                process(content, info.get("filename") or name, ctx)
            except Exception:
                pass
        doc.close()
        return data
    changed = False
    newmeta = dict(meta)
    for k in PDF_PEOPLE_KEYS:
        v = meta.get(k) or ""
        if v.strip():
            nv = field_value(v, ctx, local_terms)
            if nv != v:
                newmeta[k] = nv
                changed = True
    lm = Matcher(local_terms) if local_terms else None
    for k in PDF_TEXT_KEYS:
        v = meta.get(k) or ""
        if v:
            nv = ctx.m.replace_text(v)
            if lm:
                nv = lm.replace_text(nv)
            if nv != v:
                newmeta[k] = nv
                changed = True
    if changed:
        try:
            doc.set_metadata({k: v for k, v in newmeta.items() if k in (
                "author", "title", "subject", "keywords", "creator", "producer", "creationDate", "modDate")})
        except Exception:
            pass
    try:
        xmp = doc.get_xml_metadata() or ""
        if xmp:
            xb = xmp.encode("utf-8")
            nxb = xml_fields(xb, ctx, local_terms)
            nxb = generic(nxb, ctx, lm)
            if nxb != xb:
                doc.set_xml_metadata(nxb.decode("utf-8", "replace"))
                changed = True
    except Exception:
        pass
    # visible text
    for page in doc:
        try:
            text = page.get_text()
        except Exception:
            continue
        tb = text.encode("utf-8")
        keys = ctx.m.find(tb)
        if lm:
            keys |= lm.find(tb)
        exact = {u.lower() for u in find_emails(tb)}
        exact |= {v.lower() for v in titleblock_names(page) if len(v) >= 3}
        keys |= exact
        hits = 0
        words = None
        for k in sorted(keys, key=len, reverse=True):
            try:
                rects = page.search_for(k)
            except Exception:
                rects = []
            for r in rects:
                if k not in exact:
                    # search_for ignores word boundaries; confirm with the matcher
                    if words is None:
                        words = page.get_text("words")
                    near = " ".join(w[4] for w in words if w[0] < r.x1 + 1 and w[2] > r.x0 - 1
                                    and w[1] < r.y1 + 1 and w[3] > r.y0 - 1).encode("utf-8")
                    if k not in ctx.m.find(near) and not (lm and k in lm.find(near)):
                        continue
                try:
                    page.add_redact_annot(r, text=pseudonym(_orig_case(text, k)), fontname="helv",
                                          fontsize=max(4, min(r.height * 0.75, 14)), align=0, fill=False)
                    hits += 1
                except Exception:
                    pass
        if hits:
            try:
                page.apply_redactions(images=0, graphics=0, text=0)
            except TypeError:
                page.apply_redactions(images=0, graphics=0)
            except Exception as e:
                ctx.notes.append(f"pdf:redact {e!r}")
            changed = True
        # annotations / links
        try:
            for a in page.annots() or []:
                info = a.info
                c = info.get("content") or ""
                nc = ctx.m.replace_text(c)
                t = info.get("title") or ""
                nt = field_value(t, ctx, local_terms) if t.strip() else t
                if nc != c or nt != t:
                    a.set_info(content=nc, title=nt)
                    a.update()
                    changed = True
        except Exception:
            pass
        try:
            for ln in page.get_links():
                uri = ln.get("uri")
                if uri:
                    nu = ctx.m.replace_text(uri)
                    if nu != uri:
                        ln["uri"] = nu
                        page.update_link(ln)
                        changed = True
        except Exception:
            pass
    # attachments
    for name in _embfiles(doc):
        try:
            info = doc.embfile_info(name)
            fname = info.get("filename") or name
            content = doc.embfile_get(name)
            new = process(content, fname, ctx)
            nname = ctx.m.replace_text(fname)
            if new != content or nname != fname:
                try:
                    doc.embfile_upd(name, buffer_=new, filename=nname, ufilename=nname)
                except Exception:
                    doc.embfile_del(name)
                    doc.embfile_add(ctx.m.replace_text(name), new, filename=nname, ufilename=nname)
                changed = True
        except Exception as e:
            ctx.notes.append(f"pdf:attach {e!r}")
    if not changed:
        doc.close()
        return generic_pdf_raw(data, ctx, lm)
    try:
        out = doc.tobytes(garbage=3, deflate=True)
    except Exception:
        try:
            out = doc.tobytes()
        except Exception as e:
            ctx.notes.append(f"pdf:save {e!r}")
            doc.close()
            return generic_pdf_raw(data, ctx, lm)
    doc.close()
    return generic_pdf_raw(out, ctx, lm)


def generic_pdf_raw(data, ctx, lm):
    # uncompressed strings (old Info dicts, plain text streams); keeps byte offsets
    return generic(data, ctx, lm)


TB_LABEL = re.compile(
    r"(?i)^(drawn(?: by)?|dwn|designed(?: by)?|designer|checked(?: by)?|chk|chkd|approved(?: by)?|"
    r"appr|author|engineer|drafter|draftsman|created by|made by|prepared by|gezeichnet|gez\.?|"
    r"gepr[uü]ft|gepr\.?|bearbeitet|bearb\.?|bearbeiter|konstrukteur|dessin[ée]|v[ée]rifi[ée]|"
    r"approuv[ée]|dibuj[oó]|dibujado|revisado|aprobado|disegnato|controllato|approvato|desenhado|"
    r"verificado|student name|drawn name)\s*(?:by)?\s*[:.\-]?\s*(.*)$")
NAME_TOKEN = re.compile(r"^(?:[A-Z][A-Za-zÀ-ſ'\-]*\.?|[A-Z]\.(?:[A-Z]\.)*[A-Za-zÀ-ſ\-]*)$")
TB_STOP = {
    "date", "datum", "fecha", "scale", "massstab", "maßstab", "title", "titel", "name", "signature",
    "sign", "material", "werkstoff", "sheet", "blatt", "rev", "revision", "size", "weight", "gewicht",
    "qty", "finish", "tolerance", "tolerances", "unless", "dwg", "drawing", "no", "part", "approved",
    "checked", "drawn", "designed", "by", "mfg", "q.a", "qa", "eng", "appr", "the", "and", "of",
    "quantity", "menge", "anzahl", "item", "description", "benennung", "teil", "stück", "notes", "note",
    "unit", "units", "mm", "inch", "general", "sheets", "page", "issue", "change", "status",
}


def titleblock_names(page):
    """Name-like values written next to drawing title-block labels."""
    out = set()
    try:
        words = page.get_text("words")
    except Exception:
        return out
    lines = {}
    for w in words:
        lines.setdefault((w[5], w[6]), []).append(w)
    keys = sorted(lines)
    for idx, k in enumerate(keys):
        ws = sorted(lines[k], key=lambda w: w[0])
        text = " ".join(w[4] for w in ws)
        m = TB_LABEL.match(text)
        if not m:
            continue
        val = m.group(2).strip()
        if not val and idx + 1 < len(keys) and keys[idx + 1][0] == k[0]:
            val = " ".join(w[4] for w in sorted(lines[keys[idx + 1]], key=lambda w: w[0])).strip()
        val = re.split(r"\s{2,}|\s+(?:date|datum|fecha|\d{1,2}[./-]\d{1,2}[./-]\d{2,4})\b", val, flags=re.I)[0]
        val = val.strip(" :.-_|")
        toks = val.split()
        if not (1 <= len(toks) <= 4) or len(val) < 2 or len(val) > 40:
            continue
        if sum(c.isdigit() for c in val) > 1 or not any(c.isalpha() for c in val):
            continue
        if any(t.lower().strip(".:") in TB_STOP for t in toks):
            continue
        if is_generic(val):
            continue
        if not all(NAME_TOKEN.match(t) for t in toks):
            continue
        if len(toks) == 1 and (len(val) > 12 or (val.isupper() and "." not in val)):
            continue
        out.add(val)
    return out


def _orig_case(text, k):
    i = text.lower().find(k)
    return text[i:i + len(k)] if i >= 0 else k


def _embfiles(doc):
    try:
        return list(doc.embfile_names())
    except Exception:
        return []


# ---------------------------------------------------------------- images

def png(data, ctx):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return generic(data, ctx)
    out = [data[:8]]
    i = 8
    changed = False
    while i + 12 <= len(data):
        ln = struct.unpack(">I", data[i:i + 4])[0]
        t = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + ln]
        if t in (b"tEXt", b"iTXt", b"eXIf"):
            nb = generic(body, ctx)
            if nb != body:
                changed = True
                body = nb
        elif t == b"zTXt":
            k, _, rest = body.partition(b"\x00")
            try:
                txt = zlib.decompress(rest[1:])
                nt = generic(txt, ctx)
                if nt != txt:
                    body = k + b"\x00\x00" + zlib.compress(nt)
                    changed = True
            except Exception:
                pass
        out.append(struct.pack(">I", len(body)) + t + body + struct.pack(">I", zlib.crc32(t + body)))
        i += 12 + ln
        if t == b"IEND":
            break
    out.append(data[i:])
    if ctx.collect is not None or not changed:
        return data
    return b"".join(out)


def jpeg(data, ctx):
    # APP/COM segments are uncompressed: plain length-preserving pass over the header part
    if data[:2] != b"\xff\xd8":
        return generic(data, ctx)
    sos = data.find(b"\xff\xda")
    if sos < 0:
        sos = len(data)
    head = generic(data[:sos], ctx)
    if ctx.collect is not None:
        return data
    return head + data[sos:]


# ---------------------------------------------------------------- archives

def zip_container(data, ctx, relpath):
    try:
        zin = zipfile.ZipFile(io.BytesIO(data))
        infos = zin.infolist()
    except Exception:
        ctx.notes.append("zip:unreadable")
        return generic(data, ctx)
    out = io.BytesIO()
    changed = False
    try:
        zout = zipfile.ZipFile(out, "w", allowZip64=True)
        for info in infos:
            try:
                content = zin.read(info)
            except Exception as e:
                ctx.notes.append(f"zip:member unreadable {e!r}")
                if ctx.collect is None:
                    content = None
                else:
                    continue
            name = info.filename
            if ctx.collect is not None:
                ctx.add("member", name)
                if content is not None and not name.endswith("/"):
                    process(content, name, ctx)
                continue
            nname = rename_rel(name, ctx)
            if content is None:
                continue
            new = content if name.endswith("/") else process(content, name, ctx)
            ni = zipfile.ZipInfo(nname, date_time=info.date_time)
            ni.compress_type = info.compress_type if info.compress_type in (0, 8) else 8
            ni.external_attr = info.external_attr
            ni.create_system = info.create_system
            ni.comment = info.comment
            zout.writestr(ni, new)
            if new != content or nname != name:
                changed = True
        zout.close()
    except Exception as e:
        ctx.notes.append(f"zip:rewrite failed {e!r}")
        return generic(data, ctx)
    if ctx.collect is not None:
        return data
    return out.getvalue() if changed else data


def tar_container(data, ctx, relpath):
    try:
        tin = tarfile.open(fileobj=io.BytesIO(data))
        members = tin.getmembers()
    except Exception:
        ctx.notes.append("tar:unreadable")
        return generic(data, ctx)
    out = io.BytesIO()
    tout = tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) if ctx.collect is None else None
    for mem in members:
        f = tin.extractfile(mem) if mem.isfile() else None
        content = f.read() if f else None
        if ctx.collect is not None:
            if content is not None:
                process(content, mem.name, ctx)
            continue
        nm = tarfile.TarInfo(rename_rel(mem.name, ctx))
        nm.mode, nm.mtime, nm.type = mem.mode, mem.mtime, mem.type
        nm.uname = nm.gname = ""
        nm.uid = nm.gid = 0
        if mem.issym() or mem.islnk():
            nm.linkname = rename_rel(mem.linkname, ctx)
        if content is not None:
            new = process(content, mem.name, ctx)
            nm.size = len(new)
            tout.addfile(nm, io.BytesIO(new))
        else:
            tout.addfile(nm)
    if tout is None:
        return data
    tout.close()
    return out.getvalue()


def gz_container(data, ctx, relpath):
    try:
        raw = gzip.decompress(data)
    except Exception:
        ctx.notes.append("gz:unreadable")
        return generic(data, ctx)
    inner = relpath[:-3] if relpath.lower().endswith(".gz") else relpath
    if inner.lower().endswith(".tgz"):
        inner = inner[:-4] + ".tar"
    new = process(raw, inner, ctx)
    if ctx.collect is not None or new == raw:
        return data
    return gzip.compress(new, 9, mtime=0)


def z_container(data, ctx, relpath):
    from . import lzw
    try:
        raw = lzw.decompress(data)
    except Exception:
        ctx.notes.append("Z:unreadable")
        return generic(data, ctx)
    inner = relpath[:-2] if relpath.lower().endswith(".z") else relpath
    new = process(raw, inner, ctx)
    if ctx.collect is not None or new == raw:
        return data
    return lzw.compress(new)


def sevenz_container(data, ctx, relpath):
    try:
        import py7zr
        with py7zr.SevenZipFile(io.BytesIO(data), "r") as z:
            names = z.getnames()
            files = z.readall() or {}
    except Exception:
        ctx.notes.append("7z:unreadable")
        return generic(data, ctx)
    newfiles = {}
    for name in names:
        bio = files.get(name)
        content = bio.read() if bio is not None else None
        if ctx.collect is not None:
            if content is not None:
                process(content, name, ctx)
            continue
        if content is None:
            continue
        newfiles[rename_rel(name, ctx)] = process(content, name, ctx)
    if ctx.collect is not None:
        return data
    out = io.BytesIO()
    try:
        with py7zr.SevenZipFile(out, "w") as z:
            for name, content in newfiles.items():
                z.writestr(content, name)
    except Exception as e:
        ctx.notes.append(f"7z:write {e!r}")
        return generic(data, ctx)
    return out.getvalue()


def rename_rel(rel, ctx):
    if ctx.rename:
        return ctx.rename(rel)
    return rel


# ---------------------------------------------------------------- dispatch

def process(data, relpath, ctx):
    if not data:
        return data
    ctx.depth += 1
    try:
        if ctx.depth > 6:
            return generic(data, ctx)
        ext = ext_of(relpath)
        head = data[:8]
        if head.startswith(b"%PDF") or (ext in (".pdf", ".ai") and b"%PDF" in data[:1024]):
            return pdf(data, ctx, relpath)
        if swfile.is_sw(data):
            return solidworks(data, ctx, relpath)
        if head == OLE_MAGIC:
            return ole(data, ctx, relpath)
        if head[:4] == b"PK\x03\x04" or (ext in ZIP_EXT and head[:2] == b"PK"):
            return zip_container(data, ctx, relpath)
        if head[:2] == b"\x1f\x8b":
            return gz_container(data, ctx, relpath)
        if head[:2] == b"\x1f\x9d":
            return z_container(data, ctx, relpath)
        if head[:6] == b"7z\xbc\xaf\x27\x1c":
            return sevenz_container(data, ctx, relpath)
        if ext == ".tar" or data[257:262] == b"ustar":
            return tar_container(data, ctx, relpath)
        if ext in (".step", ".stp", ".p21") or head.startswith(b"ISO-10303"):
            return step(data, ctx)
        if ext in (".igs", ".iges"):
            return iges(data, ctx)
        if ext == ".dxf":
            return dxf(data, ctx)
        if head[:8] == b"\x89PNG\r\n\x1a\n":
            return png(data, ctx)
        if head[:2] == b"\xff\xd8":
            return jpeg(data, ctx)
        if ext in (".svg", ".xml", ".3mf", ".urdf", ".dae", ".amf") or head[:5] == b"<?xml":
            loc = set()
            d2 = xml_fields(data, ctx, loc, rdf_ok=True)
            if ctx.collect is not None:
                return generic(data, ctx)
            return generic(d2, ctx, Matcher(loc) if loc else None)
        return generic(data, ctx)
    finally:
        ctx.depth -= 1
