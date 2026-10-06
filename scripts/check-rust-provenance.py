#!/usr/bin/env python3
"""Fail closed on unexpected Rust dependency sources or license expressions."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Exact external license expressions reviewed for the v0.1 open-core candidate.
# An expression containing OR is acceptable because the distribution may be
# consumed under an approved alternative (e.g. MIT or Apache-2.0). Any new or
# changed expression intentionally forces another human review.
REVIEWED_LICENSE_EXPRESSIONS = {
    "(MIT OR Apache-2.0) AND Unicode-3.0",
    "Apache-2.0 / MIT",
    "Apache-2.0 OR MIT",
    "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
    "BSD-2-Clause OR Apache-2.0 OR MIT",
    "BSD-3-Clause",
    "MIT",
    "MIT OR Apache-2.0",
    "MIT OR Apache-2.0 OR BSD-1-Clause",
    "MIT OR Apache-2.0 OR LGPL-2.1-or-later",
    "MIT/Apache-2.0",
    "Unlicense OR MIT",
}


def main() -> int:
    workspace = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(proc.stdout)
    failures = []
    licenses = set()

    for package in metadata["packages"]:
        source = package.get("source")
        if source is None:
            # Workspace/path crates are governed by the reviewed public release mapping.
            continue

        if not (
            source.startswith("registry+https://github.com/rust-lang/crates.io-index")
            or source.startswith("sparse+https://index.crates.io/")
        ):
            failures.append(f"{package['name']} {package['version']}: unexpected source {source}")

        expression = (package.get("license") or "").strip()
        if not expression:
            failures.append(f"{package['name']} {package['version']}: missing license metadata")
            continue

        licenses.add(expression)
        if expression not in REVIEWED_LICENSE_EXPRESSIONS:
            failures.append(
                f"{package['name']} {package['version']}: unreviewed license expression {expression!r}"
            )

    print("Reviewed external Rust license expressions:")
    for value in sorted(licenses):
        print(f"  {value}")

    if failures:
        print("\nRust provenance gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("\nRust dependency provenance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
