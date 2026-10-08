#!/usr/bin/env python3
"""Exercise CI-packaged V3 tools through their actual CLI with fresh synthetic authority."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    root = args.tools.resolve()
    expected = args.source_commit
    if len(expected) != 40 or any(c not in "0123456789abcdef" for c in expected):
        raise RuntimeError("an independently selected full source commit is required")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if (manifest.get("sourceCommit") != expected or manifest.get("platform") != "linux-x86_64"
        or manifest.get("purpose") != "synthetic-native-conformance"):
        raise RuntimeError("unexpected artifact source, platform or purpose")
    for name in ("trust-console", "halibut-fixture"):
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != manifest.get("sha256", {}).get(name):
            raise RuntimeError("artifact digest mismatch: " + name)

    cases = []
    with tempfile.TemporaryDirectory(prefix="swoosh-native-tools-") as directory:
        fixture = Path(directory)
        subprocess.run([str(root / "halibut-fixture"), str(fixture)], check=True,
            capture_output=True, text=True, timeout=10)
        request = json.loads((fixture / "host-request.json").read_text(encoding="utf-8"))
        checkpoint = (fixture / "checkpoint.txt").read_text(encoding="utf-8").strip()
        command = [str(root / "trust-console"), "evaluate-action-v3",
            "--envelope", str(fixture / "action.bin"), "--trust-pack", str(fixture / "current.tpack"),
            "--expected-checkpoint", checkpoint, "--minimum-epoch", "1", "--host-request"]

        def evaluate(value: dict) -> subprocess.CompletedProcess:
            path = fixture / "probe.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return subprocess.run(command + [str(path)], check=False, capture_output=True, text=True, timeout=10)

        # Without this positive control, schema/command failures could masquerade as denials.
        good = evaluate(request)
        if good.returncode != 0:
            raise RuntimeError("positive control failed: " + good.stdout + good.stderr)
        receipt = json.loads(good.stdout)
        if type(receipt.get("profile_version")) is not int or receipt["profile_version"] != 3 or receipt.get("trust", {}).get("decision") != "ALLOW":
            raise RuntimeError("positive control did not return a V3 ALLOW receipt")

        probes = [("authenticated_subject", [0]*32, "SubjectMismatch"),
            ("authenticated_role", "other-worker", "RoleMismatch"),
            ("action", "other-action", "ScopeMismatch"),
            ("resource", "other-resource", "ScopeMismatch")]
        for field, value, reason in probes:
            modified = copy.deepcopy(request)
            modified[field] = value
            cases.append((field, modified, reason))
        for field in ("workflow_id", "task_id", "generation", "role_id", "cognitive_profile_digest",
            "purpose", "destination", "effect_digest", "policy_version", "trust_epoch"):
            modified = copy.deepcopy(request)
            value = modified["binding"][field]
            modified["binding"][field] = ([v ^ 1 for v in value] if isinstance(value, list)
                else value+1 if type(value) is int else value+"-tampered")
            cases.append(("binding."+field, modified, "ScopeMismatch"))
        for label, modified, reason in cases:
            result = evaluate(modified)
            if result.returncode == 0 or "action denied: " + reason not in result.stdout + result.stderr:
                raise RuntimeError("negative control failed for " + label + ": " + result.stdout + result.stderr)
    print(json.dumps({"status": "PASS", "profile": 3, "positiveControls": 1,
        "canonicalDenialControls": len(cases), "sourceCommit": expected}))


if __name__ == "__main__":
    main()
