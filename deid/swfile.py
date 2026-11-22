"""SolidWorks 2015+ container (sldprt/sldasm/slddrw and templates).

The file is a sequence of records: a 6-byte signature, timestamp, CRC32,
compressed size, uncompressed size, name length, nibble-rotated name and a
raw-deflate payload; a directory near the end repeats the record headers.
Streams are rewritten in place: the new payload is re-deflated into the old
slot (zero padded) and the CRC is updated in both the record and the
directory, so no offsets move.
"""
import struct
import zlib

SIG = b"\x14\x00\x06\x00\x08\x00"


def is_sw(data):
    return len(data) > 32 and data[4:8] == b"\x00\x00\x00\x04" and SIG in data[:64]


def _rot(b):
    return bytes(((x >> 4) | (x << 4)) & 0xFF for x in b)


def records(data):
    i = data.find(SIG)
    while i >= 0 and i + 26 <= len(data):
        _t, crc, cs, us, n = struct.unpack_from("<IIIII", data, i + 6)
        start = i + 26 + n
        if n > 1024 or start + cs > len(data):
            i = data.find(SIG, i + 6)
            continue
        name = _rot(data[i + 26:start])
        ok = False
        payload = None
        if us and cs:
            try:
                d = zlib.decompressobj(-15)
                payload = d.decompress(data[start:start + cs], us + 1)
                ok = len(payload) == us and zlib.crc32(payload) == crc
            except zlib.error:
                ok = False
        if ok:
            yield i, crc, cs, us, name, start, payload
            i = data.find(SIG, start + cs)
        else:
            i = data.find(SIG, i + 6)


def _deflate(raw, cap):
    best = None
    for level, mem, strat in ((9, 9, zlib.Z_DEFAULT_STRATEGY), (6, 8, zlib.Z_DEFAULT_STRATEGY),
                              (9, 8, zlib.Z_FILTERED), (1, 9, zlib.Z_DEFAULT_STRATEGY)):
        c = zlib.compressobj(level, zlib.DEFLATED, -15, mem, strat)
        out = c.compress(raw) + c.flush()
        if best is None or len(out) < len(best):
            best = out
        if len(best) <= cap:
            break
    return best


def streams(data):
    """(name, payload) for every readable stream."""
    for _i, _crc, _cs, _us, name, _start, payload in records(data):
        yield name.decode("latin1"), payload


def rewrite(data, fn):
    """fn(name, payload) -> new payload of identical length, or None.

    Returns (new_data, changed_streams, failed_streams)."""
    buf = None
    changed = failed = 0
    recs = list(records(data))
    tail_fix = []
    for i, crc, cs, us, name, start, payload in recs:
        new = fn(name.decode("latin1"), payload)
        if new is None or new == payload:
            continue
        if len(new) != len(payload):
            failed += 1
            continue
        comp = _deflate(new, cs)
        if len(comp) > cs:
            # last resort: blank the changed bytes; a run of x deflates well
            alt = bytearray(new)
            for j in range(len(alt)):
                if alt[j] != payload[j]:
                    alt[j] = 0x78
            new = bytes(alt)
            comp = _deflate(new, cs)
            if len(comp) > cs:
                failed += 1
                continue
        if buf is None:
            buf = bytearray(data)
        buf[start:start + cs] = comp + b"\x00" * (cs - len(comp))
        ncrc = zlib.crc32(new)
        struct.pack_into("<I", buf, i + 10, ncrc)
        tail_fix.append((data[i + 6:i + 26], ncrc, i))
        changed += 1
    if buf is not None and tail_fix:
        # directory copies of the record headers carry the same CRC
        last = recs[-1][5] + recs[-1][2] if recs else 0
        for hdr, ncrc, pos in tail_fix:
            j = data.find(SIG + hdr, last)
            while j >= 0:
                struct.pack_into("<I", buf, j + 10, ncrc)
                j = data.find(SIG + hdr, j + 6)
    return (bytes(buf) if buf is not None else data), changed, failed
