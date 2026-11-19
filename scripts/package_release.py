"""Create a platform archive containing both original commands and full notices."""
from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import time
import zipfile

from collect_licenses import collect_licenses
from release_common import BINARIES, ROOT, archive_name, requested_version, run_output, sha256, source_commit, target_settings


def binary_signature(path: Path, target: str) -> None:
    with path.open("rb") as executable:
        prefix = executable.read(4)
    valid = prefix == b"\x7fELF" if "linux" in target else prefix[:2] == b"MZ" if "windows" in target else prefix in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    if not valid or path.stat().st_size < 100_000:
        raise ValueError(f"Missing or unexpected native executable format: {path.name}")


def create_archive(staging: Path, archive: Path, timestamp: int) -> None:
    files = sorted(path for path in staging.rglob("*") if path.is_file())
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for path in files:
                relative = path.relative_to(staging.parent).as_posix()
                info = zipfile.ZipInfo(relative, time.gmtime(max(timestamp, 315532800))[:6])
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o100755 if path.suffix == ".exe" else 0o100644) << 16
                output.writestr(info, path.read_bytes())
        return
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=timestamp, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as output:
                for path in files:
                    info = output.gettarinfo(str(path), arcname=path.relative_to(staging.parent).as_posix())
                    info.mtime = timestamp
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mode = 0o755 if path.name in BINARIES else 0o644
                    with path.open("rb") as contents:
                        output.addfile(info, contents)


def main() -> None:
    version, commit = requested_version(), source_commit()
    target = os.environ["RELEASE_TARGET"]
    settings = target_settings(target)
    compiler = run_output(["rustc", "-vV"])
    host = next(line.removeprefix("host: ") for line in compiler.splitlines() if line.startswith("host: "))
    if host != target:
        raise ValueError("Release target does not match the native compiler host")
    destination = Path(os.environ["RELEASE_OUTPUT"]).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / archive_name(version, target)
    if archive.exists():
        raise FileExistsError("Refusing to overwrite an existing local release archive")
    timestamp = int(run_output(["git", "show", "-s", "--format=%ct", commit]))
    with tempfile.TemporaryDirectory(prefix="termius-package-") as temporary:
        staging = Path(temporary) / f"termius-mcp-rs-{version}-{target}"
        staging.mkdir()
        for name in BINARIES:
            binary = ROOT / "target" / "release" / (name + settings["suffix"])
            binary_signature(binary, target)
            shutil.copyfile(binary, staging / binary.name)
        for filename in ("README.md", "README.zh-CN.md", "LICENSE", "NOTICE", "CHANGELOG.md"):
            shutil.copyfile(ROOT / filename, staging / filename)
        dependencies = collect_licenses(target, staging / "THIRD_PARTY_LICENSES")
        build = {
            "version": version, "commit": commit, "target": target, "runner": settings["runner"],
            "binaries": [name + settings["suffix"] for name in BINARIES], "source_date_epoch": timestamp,
            "rustc": compiler, "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"), "dependency_count": dependencies,
        }
        (staging / "BUILD_INFO.json").write_text(json.dumps(build, indent=2) + "\n", encoding="utf-8")
        create_archive(staging, archive, timestamp)
    build.update({"archive": archive.name, "sha256": sha256(archive), "size": archive.stat().st_size})
    (destination / f"{target}.build.json").write_text(json.dumps(build, indent=2) + "\n", encoding="utf-8")
    print(f"Packaged {archive.name}: {build['size']} bytes, {dependencies} dependency license records")


if __name__ == "__main__":
    main()
