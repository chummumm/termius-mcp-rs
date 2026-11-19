"""Collect actual license/notice texts for the target's non-dev Cargo dependency closure.

Do not silently replace missing notices with a generic SPDX license template.
Known crates with incomplete published archives have exact-commit copies under
license-overrides; all other unknown or missing license material blocks release.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess

from release_common import ROOT, sha256, target_settings

LICENSE_NAME = re.compile(r"^(?:licen[cs]e|copying|copyright|notice)(?:[._-].*)?$", re.IGNORECASE)
KNOWN_SPDX = {
    "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "CC0-1.0",
    "CDLA-Permissive-2.0", "ISC", "MIT", "MPL-2.0", "Unicode-3.0", "Unlicense",
    "Zlib", "LLVM-exception",
}
COMPLETE_LICENSE_MARKERS = (
    ("Permission is hereby granted, free of charge", 'THE SOFTWARE IS PROVIDED "AS IS"', "DEALINGS IN THE SOFTWARE"),
    ("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION", "END OF TERMS AND CONDITIONS"),
    ("Redistribution and use in source and binary forms", "THIS SOFTWARE", "LIABLE FOR ANY"),
    ("Permission to use, copy, modify, and/or distribute this software", "THE SOFTWARE IS PROVIDED", "IN NO EVENT"),
)


def dependency_packages(target: str) -> list[dict]:
    target_settings(target)
    output = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
    )
    metadata = json.loads(output)
    root = metadata["resolve"]["root"]
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    selected: set[str] = set()
    pending = [root]
    while pending:
        package_id = pending.pop()
        if package_id in selected:
            continue
        selected.add(package_id)
        for dependency in nodes[package_id]["deps"]:
            if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    return sorted(
        (package for package in metadata["packages"] if package["id"] in selected and package["id"] != root),
        key=lambda package: (package["name"], package["version"]),
    )


def validate_license_declaration(package: dict) -> str:
    declaration = package.get("license")
    if not declaration:
        raise ValueError(f"{package['name']} {package['version']} has no SPDX declaration; review its license before release")
    # Older Cargo manifests used '/' for an OR expression. Preserve the original
    # declaration in the report, but recognize this legacy spelling for validation.
    normalized = declaration.replace("/", " OR ")
    tokens = re.findall(r"[A-Za-z0-9.+-]+|[()]", normalized)
    if re.sub(r"[A-Za-z0-9.+()\s-]", "", normalized):
        raise ValueError(f"Unrecognized license syntax for {package['name']}")
    identifiers = set(tokens) - {"AND", "OR", "WITH", "(", ")"}
    if not identifiers or not identifiers <= KNOWN_SPDX:
        raise ValueError(f"Unreviewed SPDX identifiers for {package['name']}: {sorted(identifiers - KNOWN_SPDX)}")
    return declaration


def packaged_texts(package_root: Path, package: dict) -> list[Path]:
    files = [path for path in package_root.rglob("*") if path.is_file() and LICENSE_NAME.fullmatch(path.name)]
    explicit = package.get("license_file")
    if explicit:
        path = (package_root / explicit).resolve()
        if not path.is_relative_to(package_root.resolve()) or not path.is_file():
            raise ValueError(f"Invalid license-file path for {package['name']}")
        files.append(path)
    # A README is acceptable only when it contains a license grant itself. A
    # badge, SPDX identifier, or link to an absent LICENSE is not sufficient.
    if not files:
        for path in package_root.glob("README*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                if any(all(marker.casefold() in text.casefold() for marker in markers) for markers in COMPLETE_LICENSE_MARKERS):
                    files.append(path)
    result = sorted(set(files))
    for path in result:
        if path.is_symlink() or not path.resolve().is_relative_to(package_root.resolve()):
            raise ValueError(f"Unsafe license path for {package['name']}")
        if not path.read_text(encoding="utf-8").strip():
            raise ValueError(f"Empty license material for {package['name']}")
    return result


def override_texts(package_root: Path, package: dict) -> list[dict]:
    directory = ROOT / "scripts" / "license-overrides"
    records = json.loads((directory / "sources.json").read_text(encoding="utf-8"))
    matched = [record for record in records if record["package"] == package["name"] and record["version"] == package["version"]]
    if not matched:
        raise ValueError(f"Missing actual license text for {package['name']} {package['version']}; add a reviewed exact-version override")
    vcs = json.loads((package_root / ".cargo_vcs_info.json").read_text(encoding="utf-8"))
    result = []
    for record in matched:
        if vcs["git"]["sha1"] != record["ref"]:
            raise ValueError(f"License override source commit mismatch for {package['name']}")
        relative = Path(f"{record['package']}-{record['version']}") / record["path"]
        path = directory / relative
        if not path.resolve().is_relative_to(directory.resolve()) or sha256(path) != record["sha256"]:
            raise ValueError(f"License override checksum mismatch for {package['name']}")
        path.read_text(encoding="utf-8")
        result.append({"file": path, "relative": Path(record["path"]), "source": record["url"]})
    return result


def collect_licenses(target: str, destination: Path) -> int:
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for package in dependency_packages(target):
        declaration = validate_license_declaration(package)
        package_root = Path(package["manifest_path"]).parent
        texts = packaged_texts(package_root, package)
        material = [{"file": path, "relative": path.relative_to(package_root), "source": "published crate archive"} for path in texts]
        if not material:
            material = override_texts(package_root, package)
        name = f"{package['name']}-{package['version']}"
        included = []
        for item in material:
            relative = Path(name) / item["relative"]
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item["file"], output)
            included.append({"path": relative.as_posix(), "sha256": sha256(output), "source": item["source"]})
        source = package.get("source") or ""
        if source not in {"registry+https://github.com/rust-lang/crates.io-index", "registry+https://index.crates.io/"}:
            raise ValueError(f"Unreviewed dependency source for {name}")
        records.append({
            "name": package["name"], "version": package["version"], "license": declaration,
            "repository": package.get("repository"), "authors": package.get("authors", []),
            "source_archive": f"https://crates.io/api/v1/crates/{package['name']}/{package['version']}/download",
            "license_files": included,
        })
    report = {"target": target, "scope": "Cargo target-filtered normal and build dependency closure; dev-only dependencies excluded", "packages": records}
    (destination / "index.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = ["# Third-party licenses", "", report["scope"] + ".", "",
             "The following unmodified dependencies are distributed with this build. Actual license and notice texts are included beside this index. Source archives for the exact versions are linked below and in index.json.", "",
             "| Package | Declared license | Source |", "| --- | --- | --- |"]
    lines.extend(f"| {record['name']} {record['version']} | {record['license']} | [source]({record['source_archive']}) |" for record in records)
    (destination / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(records)
