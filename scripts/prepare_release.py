"""Validate the one version requested by a manual run or release manifest push."""
from __future__ import annotations

import json
import os
from pathlib import Path

from release_common import ROOT, validate_commit, validate_version


def prepare() -> None:
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("Releases must start from main")
    event = os.environ.get("GITHUB_EVENT_NAME")
    if event == "workflow_dispatch":
        requested = os.environ.get("REQUESTED_VERSION", "")
    elif event == "push":
        manifest = json.loads((ROOT / ".github" / "release.json").read_text(encoding="utf-8"))
        if set(manifest) != {"version"} or not isinstance(manifest["version"], str):
            raise ValueError("Release manifest must contain only a string version")
        requested = manifest["version"]
    else:
        raise ValueError("Unsupported release trigger")
    version = validate_version(requested)
    commit = validate_commit(os.environ.get("GITHUB_SHA", ""))
    output = Path(os.environ["GITHUB_OUTPUT"])
    with output.open("a", encoding="utf-8") as stream:
        stream.write(f"version={version}\ncommit={commit}\n")
    print(f"Validated release v{version} from commit {commit}")


if __name__ == "__main__":
    prepare()
