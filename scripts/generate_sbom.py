#!/usr/bin/env python3
"""Generate a small SPDX-2.3 JSON SBOM from Cargo metadata or an installed Python package closure."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+")

def spdx_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    safe = re.sub(r"[^A-Za-z0-9.-]", "-", value)[:80]
    return f"SPDXRef-{prefix}-{safe}-{digest}"

def document(name: str, namespace: str, packages: list[dict], relationships: list[dict]) -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": namespace,
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": [
                "Organization: ViTech Intelligence Solutions",
                "Tool: ViTech scripts/generate_sbom.py",
            ],
        },
        "packages": packages,
        "relationships": relationships,
    }

def write(doc: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {output} with {len(doc['packages'])} packages")

def cargo_sbom(output: Path, repo: str, commit: str) -> None:
    proc = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        check=True, capture_output=True, text=True,
    )
    data = json.loads(proc.stdout)
    id_map = {}
    packages = []
    workspace = set(data.get("workspace_members", []))
    for pkg in data["packages"]:
        sid = spdx_id("Cargo", f"{pkg['name']}@{pkg['version']}:{pkg['id']}")
        id_map[pkg["id"]] = sid
        packages.append({
            "name": pkg["name"],
            "SPDXID": sid,
            "versionInfo": pkg["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": pkg.get("license") or "NOASSERTION",
            "supplier": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
        })
    relationships = []
    for pkg_id in workspace:
        if pkg_id in id_map:
            relationships.append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": id_map[pkg_id],
            })
    resolve = data.get("resolve") or {}
    for node in resolve.get("nodes", []):
        source = id_map.get(node["id"])
        if not source:
            continue
        for dep in node.get("deps", []):
            target = id_map.get(dep["pkg"])
            if target:
                relationships.append({
                    "spdxElementId": source,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": target,
                })
    ns = f"https://github.com/{repo}/sbom/{commit or 'local'}/cargo"
    write(document("ViTech Swoosh Core Cargo SBOM", ns, packages, relationships), output)

def canon(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")

def req_name(req: str) -> str | None:
    match = NAME_RE.match(req.strip())
    return canon(match.group(0)) if match else None

def dist_license(dist: md.Distribution) -> str:
    value = (dist.metadata.get("License-Expression") or dist.metadata.get("License") or "").strip()
    if value:
        return value
    classifiers = dist.metadata.get_all("Classifier") or []
    vals = [c.split(" :: ")[-1] for c in classifiers if c.startswith("License ::")]
    return " OR ".join(vals) if vals else "NOASSERTION"

def python_sbom(output: Path, root_name: str, repo: str, commit: str) -> None:
    installed = {canon(d.metadata["Name"]): d for d in md.distributions() if d.metadata.get("Name")}
    root = canon(root_name)
    if root not in installed:
        raise SystemExit(f"root distribution not installed: {root_name}")
    queue = [root]
    seen = set()
    edges: list[tuple[str, str]] = []
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        dist = installed[name]
        for requirement in dist.requires or []:
            dep = req_name(requirement)
            if dep and dep in installed:
                edges.append((name, dep))
                if dep not in seen:
                    queue.append(dep)
    ids = {}
    packages = []
    for name in sorted(seen):
        dist = installed[name]
        sid = spdx_id("PyPI", f"{name}@{dist.version}")
        ids[name] = sid
        packages.append({
            "name": dist.metadata.get("Name") or name,
            "SPDXID": sid,
            "versionInfo": dist.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": dist_license(dist),
            "supplier": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
        })
    relationships = [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": ids[root],
    }]
    for source, target in edges:
        if source in ids and target in ids:
            relationships.append({
                "spdxElementId": ids[source],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": ids[target],
            })
    ns = f"https://github.com/{repo}/sbom/{commit or 'local'}/python"
    write(document(f"{root_name} Python SBOM", ns, packages, relationships), output)

def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="kind", required=True)
    cargo = sub.add_parser("cargo")
    cargo.add_argument("--output", type=Path, required=True)
    python = sub.add_parser("python")
    python.add_argument("--output", type=Path, required=True)
    python.add_argument("--root-name", required=True)
    args = parser.parse_args()
    repo = os.environ.get("GITHUB_REPOSITORY", "vitechintelligence/local")
    commit = os.environ.get("GITHUB_SHA", "local")
    if args.kind == "cargo":
        cargo_sbom(args.output, repo, commit)
    else:
        python_sbom(args.output, args.root_name, repo, commit)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
