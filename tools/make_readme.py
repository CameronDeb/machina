#!/usr/bin/env python3
"""Write README.txt for an attempt from work/results.tsv (final paths only)."""
import argparse
import collections
import os
import sys

TEMPLATE = """MACHINA DE-ID - pipeline notes
================================

Contents
  corpus/   de-identified files and archives (same layout as the input; identifying
            path parts replaced by pseudonyms, extensions unchanged)
  code/     complete pipeline source (run.py, deid/, tools/) and requirements.txt
  README.txt

How to run (Python 3.13, any OS; Windows paths are handled with a reversible
encoding for characters NTFS cannot store)
  pip install -r code/requirements.txt
  export DEID_KEY=<secret used to derive pseudonyms>     # keep private
  python code/run.py discover --input ./input --work ./work
  python code/run.py rewrite  --input ./input --output ./corpus --work ./work
  # or: python code/run.py all --input ./input --output ./corpus --work ./work
  python code/tools/verify.py --input ./input --output ./corpus --work ./work
work/ holds the identity registry and run logs; it is private and not part of
the submission.

What the pipeline does
  1. Discovery pass over every file (including inside archives, PDF attachments,
     SolidWorks/Inventor/OLE streams, zip-based CAD containers, .gz/.tar/.Z):
     - source owners, organisations, people and project names from the corpus
       layout (deid/seeds.py);
     - user names from Windows/Unix home folders embedded in files;
     - e-mail addresses and their organisation domains;
     - identity fields: STEP FILE_NAME author/organisation/authorisation, IGES
       author/organisation, PDF Info/XMP author, OLE SummaryInformation
       author/last author/company/manager, SolidWorks docProps (creator, last
       modified by, SW-Author, SW-Last Saved By, custom properties such as
       Created by / Drawn by / Checked by / Approved by / Company ...),
       FreeCAD CreatedBy/LastModifiedBy/Company, 3MF Designer/Copyright,
       SVG dc:creator, DXF $LASTSAVEDBY, drawing title-block names in PDFs.
  2. Every identity gets one deterministic pseudonym (keyed HMAC) that keeps
     the original's length, letter case, digit positions and separators, so it
     reads like a name/handle/domain and fits fixed-size binary fields. The same
     identity gets the same pseudonym everywhere (paths, text, metadata, binary
     streams); different identities get different pseudonyms.
  3. Rewrite pass, format aware and length preserving:
     - text CAD (STEP, IGES, DXF, OBJ, VRML, SAT, X_T, SVG, ...): strings only;
       numeric data, entity structure, units and tolerances are untouched;
     - SolidWorks 2015+ (sldprt/sldasm/slddrw): streams are inflated, edited,
       re-deflated into their original slots and CRCs updated in record and
       directory, so geometry streams and offsets never move; drawing
       previews are replaced by a neutral image of the same size;
     - OLE files (older SolidWorks, Inventor ipt/iam/idw/ipn, Solid Edge, ...):
       property sets and streams rewritten in place at the same size;
     - PDF: Info and XMP metadata, visible text (redacted and re-written with
       the pseudonym, vector graphics and images kept), annotations, links and
       embedded attachments (processed recursively); saved with garbage
       collection so earlier revisions do not keep old values;
     - zip-based containers (zip, FCStd, 3MF, f3d, docx, ...), tar, gz and .Z
       archives are unpacked, every member processed and renamed, and repacked;
     - PNG/JPEG metadata chunks are cleaned (CRC recomputed for PNG).
  4. Paths: identifying owner/organisation/person/project/domain parts of folder
     and file names are replaced with the same pseudonyms; everything else in
     the path and every extension is kept. References between files (assembly
     component paths, drawing model references, FreeCAD links) contain the same
     strings and are rewritten with the same pseudonyms, so links still resolve.

Limitations and exceptions
  - Text inside raster images (scanned drawings, logos in bitmaps) is not
    OCR'd; image metadata is cleaned but pixels are kept.
  - DWG and other proprietary compressed binaries (CATIA, NX, JT, Parasolid
    binary, Fusion internals) get the byte-level pass only; text stored in
    their compressed sections is not rewritten.
  - RAR archives cannot be rewritten (no free RAR writer); 7z members are
    copied unchanged. Files listed below.
  - A SolidWorks stream whose edited content would not re-deflate into its
    original slot is kept as is (listed below).
{sections}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--manifest", help="manifest.tsv for duplicate counts")
    a = ap.parse_args()
    rows = [l.rstrip("\n").split("\t") for l in open(os.path.join(a.work, "results.tsv"), encoding="utf-8")]
    empty, errors, notes = [], [], collections.defaultdict(list)
    for rel, new, size, changed, note in rows:
        if new == "None":
            errors.append(rel)
            continue
        if size == "0":
            empty.append(new)
        for n in filter(None, note.split(";")):
            key = n.split(" ")[0]
            notes[key].append(new)
    sec = []
    sec.append(f"\nCounts\n  files written: {len(rows) - len(errors)}\n  empty source files (kept as empty files): {len(empty)}\n")
    if empty:
        sec.append("Empty (0-byte) source files, kept unchanged:\n" + "".join(f"  corpus/{p}\n" for p in sorted(empty)))
    labels = {
        "pdf:unreadable": "PDF files that do not parse (source defect); byte-level pass only",
        "pdf:encrypted": "Encrypted PDF files; byte-level pass only",
        "zip:unreadable": "Archives that do not open (truncated/invalid source); byte-level pass only",
        "zip:member": "Archives with unreadable members (dropped from the repacked archive)",
        "ole:unreadable": "OLE files that do not parse (source defect); byte-level pass only",
        "ole:write": "OLE files whose streams could not be rewritten; byte-level pass only",
        "gz:unreadable": "gzip files that do not decompress (source defect)",
        "tar:unreadable": "tar files that do not open (source defect)",
        "Z:unreadable": ".Z files that do not decompress (source defect)",
        "sw:": "SolidWorks files with streams kept unchanged (no room to recompress)",
        "large:copied": "Files over 3 GB copied unchanged",
    }
    for key, items in sorted(notes.items()):
        label = labels.get(key, key)
        sec.append(f"\n{label} ({len(items)}):\n" + "".join(f"  corpus/{p}\n" for p in sorted(items)[:500]))
    if errors:
        sec.append(f"\nFiles that failed processing ({len(errors)}), not written:\n" + "".join(f"  {p}\n" for p in errors[:200]))
    rar = [r[1] for r in rows if r[1] != "None" and r[1].lower().endswith((".rar", ".7z"))]
    if rar:
        sec.append("\nRAR/7z archives copied with a byte-level pass only:\n" + "".join(f"  corpus/{p}\n" for p in rar))
    sec.append("\nDuplicates: the input contains byte-identical copies (e.g. repositories that\n"
               "appear both as a folder and as an extracted archive); each copy is processed\n"
               "independently and receives identical pseudonyms.\n")
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(TEMPLATE.format(sections="".join(sec)))


if __name__ == "__main__":
    main()
