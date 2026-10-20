"""Collect notices from the locked native/CLI/MCP dependency closure.

Run after cargo metadata --format-version 1 > target/release-metadata.json.
Output stays under target/; original dependencies are never modified.
"""
import json
import shutil
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
metadata = json.loads((ROOT / "target/release-metadata.json").read_text(encoding="utf-8-sig"))
packages = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
pending = [p["id"] for p in packages.values() if p["name"] in {"ura-native", "ura-cli", "ura-mcp"}]
seen = set()
while pending:
    package_id = pending.pop()
    if package_id in seen:
        continue
    seen.add(package_id)
    pending.extend(d["pkg"] for d in nodes[package_id]["deps"])

output = ROOT / "target/release-licenses"
output.mkdir(parents=True, exist_ok=True)
index = ["# Dependency inventory", "", "Generated from Cargo.lock via cargo metadata. Unmodified dependency sources are linked below.", "", "| Package | Declared license | Source |", "|---|---|---|"]
missing = []
upstream_cache = {}
for package in sorted((packages[i] for i in seen if packages[i]["source"]), key=lambda p: (p["name"], p["version"])):
    name, version = package["name"], package["version"]
    folder = Path(package["manifest_path"]).parent
    candidates = [p for p in folder.rglob("*") if p.is_file() and any(term in str(p.relative_to(folder)).lower() for term in ("license", "licence", "copying", "copyright", "notice")) and p.suffix.lower() not in {".rs", ".py", ".js", ".c", ".h"}]
    if package.get("license_file"):
        candidates.append(folder / package["license_file"])
    copied = 0
    for source in sorted(set(candidates)):
        if source.is_file():
            destination = output / f"{name}-{version}" / source.relative_to(folder)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            copied += 1
    copyright_lines = set()
    for source in folder.rglob("*.rs"):
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
            if "SPDX-FileCopyrightText:" in line:
                copyright_lines.add(line.strip().lstrip("/* ").rstrip("*/ "))
    if copyright_lines:
        destination = output / f"{name}-{version}" / "SPDX-COPYRIGHT.txt"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("\n".join(sorted(copyright_lines)) + "\n", encoding="utf-8")
    if not copied:
        # Workspace crates sometimes omit root license files from the published
        # tarball. Fetch only their recorded immutable source revision.
        vcs_file = folder / ".cargo_vcs_info.json"
        vcs = json.loads(vcs_file.read_text()) if vcs_file.exists() else {}
        commit = vcs.get("git", {}).get("sha1")
        repository = (package.get("repository") or "").rstrip("/").removesuffix(".git")
        if repository.startswith("https://github.com/"):
            repository = "/".join(repository.split("/")[:5])
            base = repository.replace("https://github.com/", "https://raw.githubusercontent.com/") + f"/{commit}/"
        elif repository.startswith("https://codeberg.org/"):
            base = repository + f"/raw/commit/{commit}/"
        else:
            base = None
        sources = []
        if base and commit:
            for filename in ("LICENSE", "LICENSE.txt", "LICENSE-MIT", "LICENSE-APACHE", "LICENSE-MIT.txt", "LICENSE-APACHE.txt", "NOTICE"):
                url = base + filename
                if url not in upstream_cache:
                    try:
                        with urllib.request.urlopen(url, timeout=15) as response:
                            upstream_cache[url] = response.read()
                    except (urllib.error.URLError, TimeoutError):
                        upstream_cache[url] = None
                data = upstream_cache[url]
                if data:
                    destination = output / f"{name}-{version}" / ("UPSTREAM-" + filename)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                    sources.append(url)
            if sources:
                (output / f"{name}-{version}" / "PROVENANCE.txt").write_text("\n".join(sources) + "\n", encoding="utf-8")
        if not sources:
            missing.append(f"{name}-{version}")
    index.append(f"| {name} {version} | {package.get('license') or 'UNDECLARED'} | [crate source](https://crates.io/crates/{name}/{version}) |")
(output / "INVENTORY.md").write_text("\n".join(index) + "\n", encoding="utf-8")
(output / "MISSING-TEXTS.txt").write_text("\n".join(missing), encoding="utf-8")
print(f"Collected {len(seen)} packages; {len(missing)} without bundled notice files")
if missing:
    print("\n".join(missing))
