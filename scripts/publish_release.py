"""Publish verified assets using only the release job's ephemeral GITHUB_TOKEN.

Build/test jobs never receive repository write permission. This script never
puts the token in command arguments or logs, moves existing tags, replaces a
published release, or overwrites an uploaded asset with different bytes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from assemble_release import assemble
from release_common import requested_version, sha256, source_commit


def github(arguments: list[str], *, allow_missing: bool = False) -> str | None:
    result = subprocess.run(["gh", *arguments], text=True, encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return result.stdout
    if allow_missing and "HTTP 404" in result.stderr:
        return None
    # Do not reflect response text or environment variables in CI logs.
    raise RuntimeError(f"GitHub operation failed (exit {result.returncode}); inspect repository access and API status")


def read_api(endpoint: str) -> dict | None:
    output = github(["api", endpoint], allow_missing=True)
    return None if output is None else json.loads(output)


def existing_release(repository: str, tag: str, marker: str) -> dict | None:
    # The tag endpoint returns published releases only. An authenticated release
    # listing also includes drafts; pagination is required to resume older ones.
    output = github(["api", "--paginate", "--slurp", f"repos/{repository}/releases?per_page=100"])
    pages = json.loads(output) if output is not None else None
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise ValueError("Unexpected GitHub release listing")
    matches = []
    for page in pages:
        for release in page:
            if not isinstance(release, dict):
                raise ValueError("Unexpected GitHub release listing")
            if release.get("tag_name") == tag:
                matches.append(release)
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("Multiple releases use this version; refusing to modify them")
    listed = matches[0]
    release_id = listed.get("id")
    if type(release_id) is not int or release_id <= 0:
        raise ValueError("Invalid GitHub release identifier")
    release = read_api(f"repos/{repository}/releases/{release_id}")
    # Re-read by ID so draft state, ownership marker, and assets are current.
    # A disappearing or retagged release is an error, never permission to create
    # or modify another release.
    for candidate in (listed, release):
        if not isinstance(candidate, dict) or candidate.get("id") != release_id or candidate.get("tag_name") != tag:
            raise ValueError("Release identity changed while preparing publication")
        if candidate.get("draft") is not True:
            raise ValueError("This release is already public; refusing to modify it")
        if not isinstance(candidate.get("body"), str) or marker not in candidate["body"]:
            raise ValueError("An unrelated draft already uses this version")
    return release


def upload_missing(repository: str, tag: str, assets: list[Path], marker: str) -> None:
    release = existing_release(repository, tag, marker)
    if release is None:
        raise ValueError("Expected a draft release before uploading")
    expected = {path.name: path for path in assets}
    uploaded = {asset["name"]: asset for asset in release["assets"]}
    if not set(uploaded) <= set(expected):
        raise ValueError("Draft release contains unexpected assets")
    missing = []
    for name, path in expected.items():
        if name not in uploaded:
            missing.append(str(path))
        elif uploaded[name]["size"] != path.stat().st_size:
            raise ValueError("Existing draft asset differs in size; refusing to overwrite it")
    if missing:
        github(["release", "upload", tag, *missing, "--repo", repository])
    # Re-download every asset and verify its hash before making the draft public.
    # This also validates assets left by an interrupted earlier run.
    with tempfile.TemporaryDirectory(prefix="termius-release-verify-") as temporary:
        github(["release", "download", tag, "--repo", repository, "--dir", temporary])
        downloaded = Path(temporary)
        if {path.name for path in downloaded.iterdir()} != set(expected):
            raise ValueError("Uploaded release asset set is incomplete")
        for name, original in expected.items():
            if sha256(downloaded / name) != sha256(original):
                raise ValueError("Uploaded release asset checksum differs; refusing to publish")


def main() -> None:
    if os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get("GITHUB_EVENT_NAME") not in {"push", "workflow_dispatch"}:
        raise ValueError("Release publication requires a main-branch release trigger")
    if not os.environ.get("GH_TOKEN"):
        raise ValueError("The release job must provide its ephemeral GitHub token")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid GitHub repository identifier")
    version, commit = requested_version(), source_commit()
    directory = Path(os.environ["RELEASE_OUTPUT"]).resolve()
    manifest = assemble(directory, version, commit)
    tag = f"v{version}"
    marker = f"<!-- termius-mcp-rs-release:{commit}:{version} -->"
    release = existing_release(repository, tag, marker)
    reference = read_api(f"repos/{repository}/git/ref/tags/{tag}")
    if reference is not None:
        if reference["object"]["type"] != "commit" or reference["object"]["sha"] != commit:
            raise ValueError("Existing tag does not point directly to this exact release commit")
    else:
        github(["api", "--method", "POST", f"repos/{repository}/git/refs", "-f", f"ref=refs/tags/{tag}", "-f", f"sha={commit}"])
    if release is None:
        github(["release", "create", tag, "--repo", repository, "--draft", "--verify-tag", "--target", commit,
                "--title", f"Termius MCP Rust {tag}", "--notes-file", str(directory / "release-notes.md")])
    assets = [directory / build["archive"] for build in manifest["platforms"]]
    assets.extend(directory / name for name in ("SHA256SUMS", "release-manifest.json"))
    upload_missing(repository, tag, assets, marker)
    github(["release", "edit", tag, "--repo", repository, "--draft=false", "--latest"])
    published = read_api(f"repos/{repository}/releases/tags/{tag}")
    if published is None or published["draft"] or {asset["name"] for asset in published["assets"]} != {path.name for path in assets}:
        raise RuntimeError("Could not confirm the published release and all assets")
    print(f"Published https://github.com/{repository}/releases/tag/{tag}")


if __name__ == "__main__":
    main()
