"""Verify all platform archives before constructing release checksums and notes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tarfile
import zipfile

from release_common import BINARIES, ROOT, TARGETS, archive_name, requested_version, sha256, source_commit, target_settings


def verify_archive(path: Path, build: dict) -> None:
    target, version = build["target"], build["version"]
    prefix = f"termius-mcp-rs-{version}-{target}/"
    if path.name.endswith(".zip"):
        archive = zipfile.ZipFile(path)
        entries = archive.infolist()
        names = [item.filename for item in entries]
        for item in entries:
            mode = item.external_attr >> 16
            if item.is_dir() or mode & 0o170000 not in (0, 0o100000):
                archive.close()
                raise ValueError("Unexpected link or non-file member in release ZIP")
        read_member = archive.read
    else:
        archive = tarfile.open(path, "r:gz")
        entries = archive.getmembers()
        names = [item.name for item in entries]
        if any(not item.isfile() for item in entries):
            archive.close()
            raise ValueError("Unexpected link or non-file member in release tarball")
        def read_member(name: str) -> bytes:
            stream = archive.extractfile(name)
            if stream is None:
                raise ValueError("Missing archive member")
            with stream:
                return stream.read()
    try:
        if len(names) != len(set(names)):
            raise ValueError("Duplicate release archive member")
        for name in names:
            if not name.startswith(prefix) or ".." in PurePosixPath(name).parts or "\\" in name:
                raise ValueError("Unsafe or unexpected archive member path")
        suffix = target_settings(target)["suffix"]
        required = {prefix + name + suffix for name in BINARIES}
        required |= {prefix + name for name in ("README.md", "README.zh-CN.md", "LICENSE", "NOTICE", "CHANGELOG.md", "BUILD_INFO.json", "THIRD_PARTY_LICENSES/index.json", "THIRD_PARTY_LICENSES/README.md")}
        if not required <= set(names):
            raise ValueError("Release archive lacks required binaries, documentation, or licenses")
        if any(PurePosixPath(name).name in ("termius-mcp-rs", "termius-mcp-rs.exe") for name in names):
            raise ValueError("Unexpected Rust-only CLI alias in release archive")
        embedded = json.loads(read_member(prefix + "BUILD_INFO.json"))
        for field in ("version", "commit", "target", "binaries", "cargo_lock_sha256", "dependency_count"):
            if embedded[field] != build[field]:
                raise ValueError("Embedded build metadata disagrees with platform manifest")
        licenses = json.loads(read_member(prefix + "THIRD_PARTY_LICENSES/index.json"))
        if licenses["target"] != target or len(licenses["packages"]) != build["dependency_count"]:
            raise ValueError("Dependency license index disagrees with platform metadata")
        for package in licenses["packages"]:
            if not package.get("license") or not package.get("license_files"):
                raise ValueError("Incomplete third-party license record")
            for material in package["license_files"]:
                name = prefix + "THIRD_PARTY_LICENSES/" + material["path"]
                if name not in names or hashlib.sha256(read_member(name)).hexdigest() != material["sha256"]:
                    raise ValueError("Missing or corrupted third-party license material")
    finally:
        archive.close()


def verify_platform(directory: Path, version: str, commit: str, target: str) -> dict:
    metadata_path = directory / f"{target}.build.json"
    build = json.loads(metadata_path.read_text(encoding="utf-8"))
    if (build["version"], build["commit"], build["target"]) != (version, commit, target):
        raise ValueError("Platform artifact was built from a different version, commit, or target")
    expected = archive_name(version, target)
    if build["archive"] != expected:
        raise ValueError("Unexpected platform archive filename")
    settings = target_settings(target)
    if build["binaries"] != [name + settings["suffix"] for name in BINARIES]:
        raise ValueError("Platform artifact does not contain the original CLI names")
    path = directory / expected
    if not path.is_file() or path.is_symlink() or path.stat().st_size != build["size"] or sha256(path) != build["sha256"]:
        raise ValueError("Platform archive checksum or size does not match")
    verify_archive(path, build)
    return build


def release_notes(version: str, commit: str) -> str:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    marker = f"## {version}\n"
    if marker not in changelog:
        raise ValueError("CHANGELOG.md has no section for this version")
    changes = changelog.split(marker, 1)[1].split("\n## ", 1)[0].strip()
    return (
        f"<!-- termius-mcp-rs-release:{commit}:{version} -->\n\n"
        f"{changes}\n\n"
        "## Downloads\n\n"
        "Each platform package contains the original `termius` and `termius-mcp` commands, documentation, the BSD license, project notices, and full third-party license texts. No Python runtime is required.\n\n"
        "- Linux x86_64: built and tested natively on Ubuntu 22.04 (GNU/glibc).\n"
        "- Windows x86_64: native MSVC build.\n"
        "- macOS arm64: native Apple Silicon build.\n\n"
        "Verify downloaded archive hashes against `SHA256SUMS`. Windows binaries are not Authenticode signed; macOS binaries are not Developer ID signed or notarized. Real-account cloud login and a graphical OS keychain require separate user-environment validation.\n\n"
        f"Source commit: `{commit}`. Target/compiler details are in `release-manifest.json` and each archive's `BUILD_INFO.json`.\n"
    )


def assemble(directory: Path, version: str, commit: str) -> dict:
    builds = [verify_platform(directory, version, commit, target) for target in TARGETS]
    if len({build["cargo_lock_sha256"] for build in builds}) != 1:
        raise ValueError("Platform builds used different Cargo.lock files")
    allowed = {build["archive"] for build in builds} | {f"{target}.build.json" for target in TARGETS}
    # Re-running assembly may find its own outputs, but never accepts an extra platform archive.
    allowed |= {"SHA256SUMS", "release-manifest.json", "release-notes.md"}
    if any(path.name not in allowed or not path.is_file() for path in directory.iterdir()):
        raise ValueError("Unexpected downloaded release artifact")
    checksums = "".join(f"{build['sha256']}  {build['archive']}\n" for build in sorted(builds, key=lambda build: build["archive"]))
    (directory / "SHA256SUMS").write_text(checksums, encoding="utf-8")
    manifest = {"version": version, "commit": commit, "platforms": builds}
    (directory / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (directory / "release-notes.md").write_text(release_notes(version, commit), encoding="utf-8")
    print(f"Verified all {len(builds)} platform archives and their license texts")
    return manifest


if __name__ == "__main__":
    assemble(Path(os.environ["RELEASE_OUTPUT"]).resolve(), requested_version(), source_commit())
