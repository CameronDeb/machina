"""Unix compress (.Z) reader and writer.

Bit layout follows the reference implementation: LSB-first codes, 9..maxbits
wide, and when the code width changes (or after CLEAR) the stream skips to
the end of the current group of 8 codes.
"""


def decompress(data):
    if data[:2] != b"\x1f\x9d":
        raise ValueError("not .Z")
    flags = data[2]
    maxbits = flags & 0x1F
    block = bool(flags & 0x80)
    if maxbits < 9 or maxbits > 16:
        raise ValueError("bad maxbits")
    maxmax = 1 << maxbits
    buf = data[3:]
    nbits_total = len(buf) * 8
    n_bits = 9
    maxcode = (1 << n_bits) - 1
    free_ent = 257 if block else 256
    prefix = list(range(maxmax))
    suffix = bytearray(maxmax)
    for i in range(256):
        suffix[i] = i
    out = bytearray()
    pos = 0
    seg_start = 0
    oldcode = -1
    finchar = 0
    buf = buf + bytes(3)

    while True:
        if pos + n_bits > nbits_total:
            break
        b = pos >> 3
        code = ((buf[b] | (buf[b + 1] << 8) | (buf[b + 2] << 16)) >> (pos & 7)) & ((1 << n_bits) - 1)
        pos += n_bits
        if oldcode == -1:
            if code >= 256:
                raise ValueError("bad first code")
            oldcode = finchar = code
            out.append(code)
            continue
        if code == 256 and block:
            free_ent = 256
            # skip to end of the current group
            grp = n_bits * 8
            rel = pos - seg_start
            pos = seg_start + ((rel + grp - 1) // grp) * grp
            seg_start = pos
            n_bits = 9
            maxcode = (1 << n_bits) - 1
            continue
        incode = code
        stack = bytearray()
        if code >= free_ent:
            if code > free_ent:
                raise ValueError("corrupt")
            stack.append(finchar)
            code = oldcode
        while code >= 256:
            stack.append(suffix[code])
            code = prefix[code]
        finchar = suffix[code]
        stack.append(finchar)
        stack.reverse()
        out += stack
        if free_ent < maxmax:
            prefix[free_ent] = oldcode
            suffix[free_ent] = finchar
            free_ent += 1
        oldcode = incode
        if free_ent > maxcode and n_bits < maxbits:
            grp = n_bits * 8
            rel = pos - seg_start
            pos = seg_start + ((rel + grp - 1) // grp) * grp
            seg_start = pos
            n_bits += 1
            maxcode = (1 << n_bits) - 1 if n_bits < maxbits else maxmax - 1
    return bytes(out)


def compress(data, maxbits=16):
    maxmax = 1 << maxbits
    out_codes = []  # (code, nbits, pad_after)
    acc = 0
    accbits = 0
    chunks = []
    seg_bits = 0
    n_bits = 9
    maxcode = (1 << n_bits) - 1
    free_ent = 257
    table = {}

    def emit(code):
        nonlocal acc, accbits, seg_bits
        acc |= code << accbits
        accbits += n_bits
        seg_bits += n_bits
        while accbits >= 8:
            chunks.append(acc & 0xFF)
            acc >>= 8
            accbits -= 8

    def pad_group():
        nonlocal acc, accbits, seg_bits
        grp = n_bits * 8
        extra = (-seg_bits) % grp
        # extra bits of zeros
        accbits += extra
        while accbits >= 8:
            chunks.append(acc & 0xFF)
            acc >>= 8
            accbits -= 8
        seg_bits = 0

    if not data:
        return bytes([0x1F, 0x9D, 0x80 | maxbits])
    ent = data[0]
    for c in data[1:]:
        key = (ent << 8) | c
        nxt = table.get(key)
        if nxt is not None:
            ent = nxt
            continue
        emit(ent)
        if free_ent < maxmax:
            table[key] = free_ent
            free_ent += 1
            if free_ent > maxcode + 1 and n_bits < maxbits:
                pass
        ent = c
        # the decoder widens after it has added entry free_ent-1 > maxcode
        if free_ent - 1 > maxcode and n_bits < maxbits:
            pad_group()
            n_bits += 1
            maxcode = (1 << n_bits) - 1 if n_bits < maxbits else maxmax - 1
    emit(ent)
    if accbits:
        chunks.append(acc & 0xFF)
    return bytes([0x1F, 0x9D, 0x80 | maxbits]) + bytes(chunks)
