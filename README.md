# Termius MCP Rust

[English](README.md) · [简体中文](README.zh-CN.md)

A native Rust, stdio MCP server for Termius Cloud inventory, SSH execution and
SFTP. This is an independent port of the supplied **Termius MCP 3.2.0** source
snapshot, originally from [MiaM1ku/termius-mcp](https://github.com/MiaM1ku/termius-mcp).
It is not affiliated with or endorsed by Termius.

The executable has no Python runtime dependency and does not shell out to
`ssh` or `sftp`. It uses `russh` and `russh-sftp` for the SSH transport.

## Status

This Rust port includes offline cryptographic compatibility tests,
MCP integration tests and disposable localhost OpenSSH tests are included.
**Live Termius account login, Google SSO, team-vault synchronization and desktop
OS-keychain integration still need validation with real accounts.** The service
endpoints and wire behavior come from the uploaded desktop-10.0.6-compatible
snapshot, not a public supported Termius API contract.

See [the porting notes](docs/PORTING.md) and [independent review](docs/REVIEW.md)
for the exact scope and limitations.

## Install

Download a compiled archive for your system from
[GitHub Releases](https://github.com/chummumm/termius-mcp-rs/releases/latest).
Each archive contains the original Python package's two executable names:
`termius` and `termius-mcp` (`.exe` on Windows). Extract the archive and put its
directory on `PATH`, or use an absolute path in your MCP client. No Rust or
Python installation is needed to run these binaries. `SHA256SUMS` accompanies
the release, and each archive includes dependency license notices.

### Build from source

Rust **1.89 or newer** and Cargo are required. Install Rust from
[rustup.rs](https://rustup.rs/), then:

```sh
git clone https://github.com/chummumm/termius-mcp-rs.git
cd termius-mcp-rs
cargo install --path . --locked
termius login
```

Both `termius` and `termius-mcp` run the same CLI and stdio server, as in the
Python package. There is no `termius-mcp-rs` executable. If the Python package is
also installed, select the Rust executable by its absolute path or `PATH` order.
The Rust data directory is **`~/.termius-rs`**, separate from Python's `~/.termius`.
Sign in again; existing Python data is not automatically migrated. Set
`TERMIUS_DATA_DIR` to use a different Rust data directory.

### MCP configuration

Start the executable **without a subcommand**. `login` is an interactive CLI
command and must not appear in the MCP client's `args`.

```json
{
  "mcpServers": {
    "termius": {
      "command": "termius",
      "args": []
    }
  }
}
```

If the client cannot find Cargo's binary directory, use the absolute executable
path. Examples are in [contrib/mcp](contrib/mcp).

For a Codex client configuration:

```toml
[mcp_servers.termius]
command = "termius"
args = []
startup_timeout_sec = 30.0
tool_timeout_sec = 240.0
```

The server supports MCP revisions `2025-11-25` and `2025-06-18`, matching the
source snapshot. It negotiates supported revisions during `initialize` and
requires `notifications/initialized` before tool calls. It does not claim the
different `2026-07-28` protocol. Output is newline-delimited JSON-RPC; legacy
`Content-Length` input frames are also accepted. Diagnostics go to stderr.

## Sign in

```sh
termius login
termius login email -u you@example.com
termius login google
termius status
termius logout
```

The command names, login arguments, interactive prompts and human-readable
status/logout messages follow the Python source. `login` without a method asks
you to choose Google or email; `login -u you@example.com` selects email. As in
Python, **`sync` is an MCP tool, not a terminal subcommand**. Starting either
executable without arguments starts the stdio MCP server.

Passwords are entered without terminal echo. Callback URLs and OTP use the
original visible input prompts; they are not saved to command history.
For email login, use the Termius account/vault password. For Google login, use
the **Termius vault encryption password**, not the Google password. The CLI
prompts for an authenticator code when required; `--otp` is also accepted.

Google login prints the desktop SSO URL. Complete sign-in, decline launching the
desktop app, then paste the `termius://app/continue-sso?...` callback. The callback
must belong to the request started by this instance and expires after one hour.
If the redirect page has no copy control, the browser-console helper in
[docs/GOOGLE_SSO.md](docs/GOOGLE_SSO.md) reconstructs the callback from that page's
authenticated state. Treat the callback as a credential.

By default the vault password is remembered inside encrypted local state.
`login --no-remember` saves the DeviceToken but removes the remembered password.
Supply `TERMIUS_VAULT_PASSWORD` to the MCP process, or call the `sync` MCP tool
with a `password` when needed. Set its `remember` argument to `false` to use
that password for the current pull without saving it.

## Tools

| Tool | Purpose |
| --- | --- |
| `status` | Safe session metadata, cache age and counts; no network request |
| `login` | Email/SRP login or start Google desktop SSO |
| `login_complete` | Finish Google SSO with callback, vault password and optional OTP |
| `logout` | Clear session, password, SSO state and inventory from local state |
| `sync` | Force a cloud pull and decrypt personal/team inventory |
| `hosts` | List safe host summaries; optional case-insensitive `query` |
| `host` | Host details and inherited SSH settings; password/key presence only |
| `exec` | Execute a remote command and return stdout, stderr, exit status |
| `files` | SFTP `list`, `stat`, `read`, `write`, `get`, `put`, `mkdir`, `rm`, `rename` |
| `inventory` | `groups`, `identities`, `keys`, or `snippets` |

Use the IDs returned by this server: they are stable **cloud IDs**, which can
differ from the Python client's local IDs. Duplicate labels are rejected as
ambiguous. Snippet inventories intentionally include their script contents.

`hosts` and `host` automatically refresh after 600 seconds; a failed refresh may
return cached data with `stale: true` and `sync_error`. Sign-in/password errors
remain errors. `exec`, `files` and `inventory` refresh according to
`TERMIUS_SYNC_TTL` (default 60 seconds) and do not execute on a failed refresh.
Incomplete identities, keys, group relations and host chains fail closed.

### SSH trust, timeouts and file limits

- An unspecified `strict_host_key_check` defaults to **false** for compatibility:
  a new or changed server key does not block SSH/SFTP. This mode does not verify
  server identity and cannot detect impersonation through host-key changes.
  Explicit host/group settings are inherited; `true` enables strict checking.
- The same rule applies independently to every jump and the target. Strict
  endpoints use enrolled Termius keys, or user/system OpenSSH `known_hosts` when
  no Termius key exists. Compatibility endpoints ignore saved host-key records.
  A missing/invalid chain still never falls back to direct SSH.
- `exec`/`files` results expose `host_key_verification` with `target` and ordered
  `jumps` values of `strict` or `disabled`. These describe configured modes, not
  proof that a handshake completed (for example, an execution may time out).
- Strict checking supports ordinary SSH host public keys and rejects host CA
  certificates. Compatibility mode does not validate certificate trust.
  Agent forwarding is not enabled.
- Local SSH agent and automatic local-key lookup are used only for direct
  connections without explicit vault credentials. Password, encrypted private
  key and key passphrase authentication are implemented.
- `timeout` accepts 1–86400 seconds, default 60. It covers the **SSH phase**,
  including connection and command/transfer. An automatic cloud refresh may
  precede it and has a separate 120-second limit. Login/cloud mutations are
  serialized; allow for queueing when choosing the MCP client's tool timeout.
- SSH timeout closes the route and returns `timed_out: true`, `exit_code: null`
  and captured output. This does not guarantee the remote process has stopped.
  MCP cancellation closes the route and suppresses the cancelled response.
- stdout and stderr each retain up to 200000 decoded characters with bounded
  byte buffers. They are still drained after truncation.
- SFTP inline `read`/`write` remain limited to 200000 bytes because their content
  travels inside MCP messages. File `get`/`put` have **no application-imposed
  total-size cap** and stream in 32 KiB chunks. Available disk space, filesystem
  limits and operation deadlines still apply. Increase both `files.timeout` and
  the MCP client's tool timeout for large transfers.
  `get` writes a temporary local file and replaces the destination only after a
  successful transfer. Remote writes may be partial after interruption.
- A directory listing is limited to 10000 entries; recursive removal is limited
  to 100000 entries and depth 128. Removal uses `lstat` and does not follow
  directory symlinks. Removing a remote filesystem root is rejected.

## Local state and environment

| Setting | Purpose |
| --- | --- |
| `TERMIUS_DATA_DIR` | Override the independent `~/.termius-rs` directory |
| `TERMIUS_VAULT_PASSWORD` | Supply the vault password, ahead of the remembered value |
| `TERMIUS_SYNC_TTL` | Automatic refresh interval in seconds; `0` refreshes every read |
| `TERMIUS_SECRETS_KEY` | Passphrase protecting local state; set before the first start |
| `TERMIUS_KEYRING` | `1` requires OS keychain, `0` selects file key; initial default detects availability |

Local storage is an encrypted state file, **not SQLite**. `state` is a JSON
envelope containing one versioned authenticated ciphertext, including session,
inventory and any remembered vault password. The key comes from an explicit
passphrase, the OS keychain, or a random `state.key` in headless environments.
Argon2id derives the encryption key; XChaCha20-Poly1305 authenticates the state,
key-backend metadata and revision. This **local** format is distinct from cloud
vault encryption.

On Unix, the directory must be owned by the current user with mode `0700` and
state files with mode `0600`. Symlinks and hard-linked state files are rejected.
Windows relies on filesystem ACLs and the OS credential store for access
control. Files are saved atomically with locking and stale-writer detection.
The CLI and a running MCP process reload each other's state; retry a reported
concurrent-update conflict.

The input or output transport closing ends the MCP session and cancels active
operations; a broken output pipe does not leave the server waiting for more input.

Possessing **both `state` and `state.key` permits decryption**. A passphrase or
OS keychain separates the key from a copied data directory. Encryption does
not protect against a process already running as the same user. For containers,
set a strong `TERMIUS_SECRETS_KEY` from the first start and retain it in the
container's secret configuration. Do not store it in a public MCP configuration.

A wrong key, damaged ciphertext or unavailable saved key backend produces an
error and preserves the original state. Backend changes are not automatic.
Do not remove the old key merely to make startup succeed. `logout` writes an
empty encrypted state; it is not a secure erase of filesystem backups.

## Development and verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --test ssh_openssh --locked -- --ignored
cargo build --release --locked
```

The explicit OpenSSH test command needs `sshd` and `ssh-keygen`; it generates
temporary keys and only listens on localhost. It does not change existing SSH
configuration or any account password. `TERMIUS_TEST_SSHD` can specify the
server executable. The optional Python script under `tests/fixtures` regenerates
independent development vectors; it is not used by the Rust build or runtime.

CI checks Linux, macOS and Windows, and separately checks the stated minimum
Rust version. CI results describe the actual runs; inclusion in the matrix does
not itself claim a platform has already passed. See [SECURITY.md](SECURITY.md)
for the security boundary and vulnerability reporting.

## License

[BSD 3-Clause](LICENSE). The upstream copyright and conditions are retained.
See [NOTICE](NOTICE) for provenance.
