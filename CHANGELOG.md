# Changelog

## 0.1.3

### Changed

- Show an existing team-vault-key warning in `status` and `sync` only for accounts marked `is_team:true`; omit it for personal accounts, including diagnostic output. Other cached warnings remain opt-in with `status(diagnostics=true)`. Shared-key retrieval and unreadable-resource failures are unchanged.
- Match Python's account-level `host.agent_forwarding` preference and use the same value in the reference `ssh_command`. Preserve the saved-setting default and raw cloud truthiness semantics; native MCP SSH/SFTP do not gain local-agent forwarding.
- Omit `host_key_verification` when all endpoints have checking disabled. Keep the complete ordered jump/target mapping whenever any endpoint uses strict checking. Verification and connection errors remain unchanged.

### Validation

- Add account-aware warning, raw setting conversion, host/command consistency, shell quoting and mixed-mode verification regressions, including real OpenSSH/SFTP checks.
- Preserve the original `termius` and `termius-mcp` commands, synchronization, Host Chaining and transfer behavior.

## 0.1.2

### Changed

- Stop repeating optional cloud/keyserver warning strings in ordinary tool results. `status(diagnostics=true)` exposes cached details when troubleshooting.
- Omit zero `unreadable_entities` counts and unrelated global diagnostics from successful single-host operations. Positive counts remain on inventory/status/sync results, and real operation errors and stale-cache warnings remain visible.
- Clarify that tools already auto-sync, avoiding redundant manual `sync` calls. Preserve the original terminal commands, SSH/SFTP behavior and compatible MCP text/structured result representations.

### Added

- Optional `limit`/`offset` pagination for `hosts`, `inventory` and SFTP `list`, with `total` and `next_offset`; default calls still return all results.
- Optional `inventory(include_script=false)` to list snippets without their bodies; the default still includes scripts.
- Optional `exec(max_output_chars=0..200000)` to bound each output stream and its capture buffer. The default remains 200000 characters; truncated output is still drained so execution and exit status are preserved.
- Regression coverage for quiet diagnostics, incomplete inventories, pagination, protocol compatibility and real SSH output draining with small/zero capture budgets.

## 0.1.1

### Changed

- Restore the Python 3.2.0 command names: `termius` and `termius-mcp`. Both start the same native Rust implementation.
- Preserve the original terminal commands and option surface, including the interactive email/Google login flow, OTP retry, signed-out status, and logout behavior. Invoking either executable without a subcommand starts the stdio MCP server.
- Remove the earlier Rust-only executable alias and CLI options. `TERMIUS_DATA_DIR` selects an isolated local state directory.
- Keep the MCP tool names and native SSH/SFTP implementation from the initial Rust port.

### Distribution

- Build and test native Linux x86_64, Windows x86_64, and macOS Apple Silicon binaries in GitHub Actions.
- Package the two original commands, English and Chinese documentation, project license/notices, exact dependency license texts, and build metadata.
- Publish archives only after all platform jobs succeed; include `SHA256SUMS` and a release manifest recording the exact source commit and target/compiler details.

## 0.1.0

- Initial BSD-licensed Rust source port of the supplied Termius MCP 3.2.0 snapshot.
- Add cloud/SRP and vault cryptography, the ten MCP tools, encrypted local storage, SSH jump chains, and SFTP operations.
- Add independent security, compatibility, construction, and design reviews with regression tests.
