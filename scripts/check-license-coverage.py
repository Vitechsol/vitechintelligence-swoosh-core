#!/usr/bin/env python3
from __future__ import annotations
import fnmatch, subprocess, sys, tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
EXEMPT={"REUSE.toml"}
EXEMPT_PREFIXES=("LICENSES/",)
def main()->int:
    config=tomllib.loads((ROOT/"REUSE.toml").read_text(encoding="utf-8"))
    annotations=config.get("annotations",[])
    files=subprocess.run(["git","ls-files"],cwd=ROOT,check=True,capture_output=True,text=True).stdout.splitlines()
    missing=[]; overlaps=[]
    for path in files:
        if path in EXEMPT or path.startswith(EXEMPT_PREFIXES): continue
        matches=[]
        for ann in annotations:
            patterns=ann.get("path",[])
            if isinstance(patterns,str): patterns=[patterns]
            if any(fnmatch.fnmatchcase(path,p) for p in patterns):
                matches.append(ann.get("SPDX-License-Identifier",""))
        uniq=sorted(set(matches))
        if not uniq: missing.append(path)
        elif len(uniq)>1: overlaps.append((path,uniq))
    if missing or overlaps:
        if missing:
            print("Unclassified tracked files:",file=sys.stderr)
            for p in missing: print(f"  - {p}",file=sys.stderr)
        if overlaps:
            print("Conflicting license classifications:",file=sys.stderr)
            for p,v in overlaps: print(f"  - {p}: {v}",file=sys.stderr)
        return 1
    print(f"License coverage: PASS ({len(files)} tracked files)")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
