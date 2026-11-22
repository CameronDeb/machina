# machina-deid

De-identification pipeline for the Machina CAD corpus (Builders buildathon, CAD De-ID track).

Replaces people, organisations, accounts, e-mails, domains and project names with
consistent, shape-preserving pseudonyms across paths, text, metadata and native CAD
containers (SolidWorks, Inventor/OLE, STEP, IGES, PDF, zip/tar/gz/.Z archives) while
leaving geometry and references usable.

```
pip install -r requirements.txt
python run.py all --input ./input --output ./out/corpus --work ./work
python tools/verify.py --input ./input --output ./out/corpus --work ./work
```

See `tools/make_readme.py` for the full description written into each attempt's README.txt.
