# Source analysis and porting decisions

## Provenance

Input: user-supplied `termius-mcp-3.2.0-source-redacted(1).zip`, containing
54 Python application modules plus tests, documentation and the upstream
BSD-3-Clause license. The source identifies itself as Termius MCP 3.2.0,
compatible with Termius desktop 10.0.6. No local application state was supplied
or used. The Rust repository does not redistribute the input archive.

| Original area | Rust implementation |
| --- | --- |
| `mcp/protocol.py`, `mcp/server.py` | `src/protocol.rs`: bounded framing, lifecycle, concurrent calls and cancellation |
| `mcp/tools.py`, `sync.py`, `session.py` | `src/tools.rs`, `src/tool_catalog.json`: same ten tools and safe envelopes |
| `cli.py`, `runtime.py` | `src/cli.rs`, `src/main.rs`: original CLI contract, isolated data directory and default stdio mode |
| `core/api.py`, `account/managers.py`, cloud controllers | `src/cloud.rs`: fixed TLS endpoints, login, keyring and full sync |
| `srp_session.py`, `grpc_login.py`, `sodium.py`, `cryptor.py` | `src/crypto.rs`, `src/cloud.rs`: SRP, token unwrap and authenticated decryption |
| cloud transformers, models, `ssh_merge.py` | `src/inventory.rs`: raw cloud-ID relationships, inheritance and safe routes |
| `ssh_exec.py`, `ssh_files.py`, `ssh_control.py` | `src/ssh.rs`: native asynchronous SSH/SFTP |
| `keychain.py`, storage, settings, vault migration | `src/storage.rs`: new versioned encrypted state, fresh login |

## Compatibility retained

The tool names, primary arguments, safe inventory fields, Google/email flows,
OTP support, 600-second host cache behavior, configurable refresh TTL,
concurrent SSH operations, timeout output and cancellation semantics are kept.
All nine SFTP operations are implemented. Group inheritance and visible identity
precedence are retained, including shared-identity linking and ordered host chains.

Release 0.1.1 restores the Python package's `termius` and `termius-mcp` executable
names and terminal interface: `login [google|email]`, `-u/--username`, `--otp`,
`--no-remember`, `status` and `logout`. The CLI prints the original human-readable
messages. There is no `sync` terminal subcommand or `termius-mcp-rs` executable;
`sync` remains an MCP tool. No arguments start the stdio server. Callback and OTP
input follow the source's visible prompts, while vault passwords use hidden input.

Cloud crypto follows the source implementation: RNCryptor v3 is
PBKDF2-HMAC-SHA1 plus AES-256-CBC/HMAC-SHA256; Sodium v4/v5 uses
Argon2id and **XSalsa20-Poly1305 secretbox**, with X25519/XSalsa20-Poly1305
`crypto_box` for shared-key envelopes. The original README incorrectly called
these XChaCha20 constructions. The Rust **local state format**, separately,
does use XChaCha20-Poly1305.

SRP uses the RFC 5054 8192-bit group and Blake2b-512. Tests cover source-compatible
integer/hex/byte-array/Node-Buffer encodings, proof values and token envelopes.
The original Python SRP module was independently executed during review and
matched the deterministic fixture's modulus, client public value and both proofs.

## Intentional changes

| Area | Rust behavior and reason |
| --- | --- |
| Local state | `~/.termius-rs`, configurable through `TERMIUS_DATA_DIR`; separate from Python state |
| IDs | Stable cloud IDs; call `hosts` again instead of reusing old locally assigned IDs |
| State migration | No automatic Python/Fernet migration; fresh login is required |
| Secret storage | Versioned encrypted JSON envelope, not SQLite; Argon2id-derived key and explicit, remembered backend; no machine-ID-only sealing |
| Concurrency | Short file locks, authenticated revisions and optimistic commit checks prevent stale writers resurrecting old sessions |
| SRP proof | Invalid or absent server proof is fatal; the Python source only warned for a mismatch |
| SSO state | Requires the generated request ID and unexpired login attempt; arbitrary unbound identity-token callbacks are rejected |
| Team keys | No unauthenticated plaintext-key fallback after unwrap fails |
| Optional key APIs | Shared-key retrieval is unchanged; team warnings appear in status/sync only for team accounts, other cached warnings require diagnostics; unreadable shared rows fail closed |
| Required APIs | Authentication/network errors on required endpoints remain errors; legacy sync fallback is limited to endpoint-unavailable responses |
| SSH trust | Unspecified policy defaults false so rotation does not block compatibility connections; explicit inherited true uses enrolled keys or known_hosts; configured-mode metadata is omitted only when every endpoint is disabled |
| Jump chains | Each hop honors its own trust setting; malformed or unknown owners still block routing |
| Explicit keys | Missing private material does not fall back to the local agent |
| Agent forwarding | `host` and its reference command reflect the account preference like Python; native MCP exec/files do not forward the local agent |
| Input bounds | Explicit frame, in-flight request, timeout, inline-content, output and directory bounds; file get/put have no total-size cap and use fixed chunks |
| SFTP downloads | Atomic local replacement; portable basename validation blocks Windows drive/ADS escapes |
| Transport failure | A broken output pipe ends the session and cancels active work even if input remains open |
| Errors | Cloud and SFTP error bodies are not echoed into tool results |

The SSH timeout starts after automatic cloud refresh, as in the Python source.
Tool descriptions now state this explicitly. Cloud refresh is separately capped
at 120 seconds; queued login/sync mutations can add waiting time.

Unreadable cloud entities remain marked as unavailable and are hidden from safe
inventories. `unreadable_entities` and optional `sync_warnings` make incomplete
syncs visible. No route is permitted to substitute another credential or bypass
a saved chain because a shared entity cannot be decrypted.

## Known validation boundaries

- Offline vectors and localhost protocols do not establish compatibility with
  every live Termius account or future desktop/server release.
- No real email/Google login, real personal/team vault or live desktop keychain
  was used during this port. README describes those as pending validation.
- Real OpenSSH tests use generated Ed25519 client keys. Password, encrypted-key
  and agent paths compile and are implemented but were not all exercised with
  real external authentication backends.
- The initial local validation ran on Linux. Other platforms have a CI matrix;
  report their actual run results rather than assuming success.
- Each login currently generates a device UUID. Repeated login/OTP retries can
  leave multiple device entries in Termius; per-installation device identity is
  a future compatibility improvement.
- Test fixture generation uses Python and libsodium only as an independent
  development reference. The shipped binary contains the complete Rust code.

## Protocol references

- [MCP 2025-11-25 tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP 2025-11-25 lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
- [MCP 2025-11-25 cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation)
- [RFC 5054 SRP groups](https://www.rfc-editor.org/rfc/rfc5054.html#appendix-A)

The source archive and executable tests are the primary evidence for Termius's
undocumented wire formats. This project does not imply vendor support.
