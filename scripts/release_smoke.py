"""Exercise the packaged commands without credentials or external network calls."""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

from release_common import BINARIES, ROOT, requested_version, target_settings


def command(binary: Path, arguments: list[str], environment: dict[str, str], stdin: str | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run([str(binary), *arguments], input=stdin, text=True, encoding="utf-8",
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=30)
    if result.returncode:
        raise RuntimeError(f"Smoke command failed: {binary.name} {' '.join(arguments)} (exit {result.returncode})")
    return result


def smoke(binary: Path, state: Path, version: str) -> None:
    environment = os.environ.copy()
    environment.update({"TERMIUS_DATA_DIR": str(state), "TERMIUS_KEYRING": "0", "TERMIUS_SECRETS_KEY": secrets.token_hex(32)})
    environment.pop("TERMIUS_VAULT_PASSWORD", None)
    help_text = command(binary, ["--help"], environment).stdout
    if not all(name in help_text for name in ("login", "logout", "status")):
        raise AssertionError("Original CLI commands are missing from --help")
    status = command(binary, ["status"], environment)
    if (status.stdout + status.stderr).strip() != "Not signed in.":
        raise AssertionError("Signed-out CLI status differs from the original interface")
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "release-smoke", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "ping"},
    ]
    response = command(binary, [], environment, "".join(json.dumps(request) + "\n" for request in requests))
    messages = [json.loads(line) for line in response.stdout.splitlines() if line.strip()]
    results = {message["id"]: message["result"] for message in messages}
    if set(results) != {1, 2, 3} or results[1]["protocolVersion"] != "2025-11-25":
        raise AssertionError("MCP initialization or ping failed")
    if results[1]["serverInfo"]["version"] != version:
        raise AssertionError("Release executable reports a different package version")
    expected = {"status", "login", "login_complete", "logout", "sync", "hosts", "host", "exec", "files", "inventory"}
    if {tool["name"] for tool in results[2]["tools"]} != expected:
        raise AssertionError("MCP tool catalog is incomplete")
    print(f"Smoke passed: {binary.name} (--help, signed-out status, MCP handshake/catalog/ping)")


def main() -> None:
    version = requested_version()
    target = os.environ["RELEASE_TARGET"]
    settings = target_settings(target)
    directory = ROOT / "target" / "release"
    with tempfile.TemporaryDirectory(prefix="termius-release-smoke-") as temporary:
        for name in BINARIES:
            binary = directory / (name + settings["suffix"])
            if not binary.is_file():
                raise FileNotFoundError(f"Missing release executable: {binary.name}")
            smoke(binary, Path(temporary) / name, version)


if __name__ == "__main__":
    main()
