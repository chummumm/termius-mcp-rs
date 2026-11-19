"""Shared release contracts. Python is used only to build and publish packages."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tomllib

# A recovery can use corrected publishing code while retaining the exact source
# checkout that produced the already verified binaries. The caller still has to
# prove that checkout's HEAD equals RELEASE_COMMIT before reading its metadata.
AUTOMATION_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("RELEASE_SOURCE_DIR", AUTOMATION_ROOT))
if not ROOT.is_absolute():
    ROOT = AUTOMATION_ROOT / ROOT
ROOT = ROOT.resolve()
BINARIES = ("termius", "termius-mcp")
TARGETS = {
    "x86_64-unknown-linux-gnu": {"runner": "ubuntu-22.04", "extension": ".tar.gz", "suffix": ""},
    "x86_64-pc-windows-msvc": {"runner": "windows-2025", "extension": ".zip", "suffix": ".exe"},
    "aarch64-apple-darwin": {"runner": "macos-15", "extension": ".tar.gz", "suffix": ""},
}
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")


def run_output(arguments: list[str], *, cwd: Path = ROOT) -> str:
    return subprocess.check_output(arguments, cwd=cwd, text=True, encoding="utf-8").strip()


def validate_version(version: str) -> str:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Version must be a stable MAJOR.MINOR.PATCH number without a v prefix")
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    if manifest["package"]["version"] != version:
        raise ValueError("Release version does not match Cargo.toml")
    names = sorted(binary["name"] for binary in manifest.get("bin", []))
    if names != sorted(BINARIES):
        raise ValueError("Cargo.toml must declare exactly the original termius and termius-mcp binaries")
    return version


def validate_commit(commit: str) -> str:
    if not COMMIT_PATTERN.fullmatch(commit):
        raise ValueError("Expected a full lowercase Git commit SHA")
    if run_output(["git", "rev-parse", "HEAD"]) != commit:
        raise ValueError("Checkout does not match the release commit")
    return commit


def requested_version() -> str:
    return validate_version(os.environ.get("RELEASE_VERSION", ""))


def source_commit() -> str:
    return validate_commit(os.environ.get("RELEASE_COMMIT", ""))


def target_settings(target: str) -> dict[str, str]:
    if target not in TARGETS:
        raise ValueError("Unsupported release target")
    return TARGETS[target]


def archive_name(version: str, target: str) -> str:
    return f"termius-mcp-rs-{version}-{target}{target_settings(target)['extension']}"


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
