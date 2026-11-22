#!/usr/bin/env python3
"""Assemble attempt-N/: code/ and README.txt next to an already written corpus/."""
import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attempt", required=True, help="folder holding corpus/")
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    code = os.path.join(a.attempt, "code")
    if os.path.exists(code):
        shutil.rmtree(code)
    os.makedirs(code)
    for item in ("run.py", "requirements.txt", "README.md", ".gitignore"):
        shutil.copy2(os.path.join(REPO, item), code)
    for d in ("deid", "tools"):
        shutil.copytree(os.path.join(REPO, d), os.path.join(code, d),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    subprocess.check_call([sys.executable, os.path.join(HERE, "make_readme.py"), "--work", a.work,
                           "--out", os.path.join(a.attempt, "README.txt")])
    print("ok", a.attempt)


if __name__ == "__main__":
    main()
