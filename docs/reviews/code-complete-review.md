# Independent construction review — Code Complete

Date: 2026-11-19

Reviewer: an independent AI reviewer who did not implement production code

Method: the user-supplied `code-complete` skill and its `code-complete.mini.md` rules

## Scope and requirements

This follow-up builds on the initial [implementation and security review](security-review.md). It examines the construction boundaries affected by the user's subsequent requirements: explain the actual storage format, avoid blocking ordinary connections solely because a host key changed, retain explicitly enabled strict verification, and remove the application-level 50 MiB limit from file uploads and downloads.

The reviewed policy is deliberate: an unspecified `strict_host_key_check` now means `false`. A host or group can still enable strict checking, and the nearest explicit setting applies to each endpoint. This review checks that the implementation follows that authorized policy; it does not classify the requested default as an accidental security regression. Disabled verification cannot authenticate the server or detect an impersonator through its host key.

I read the skill before reviewing the changes. I applied its rules to input validation, explicit data meaning, consistent policy across layers, loop progress and bounds, arithmetic, resource ownership, error propagation, and tests at real integration boundaries. I did not request cosmetic restructuring or rewrite working code merely to match a preferred style.

The current source paths inspected were:

| Area | Construction boundaries inspected |
| --- | --- |
| `src/inventory.rs` | Inheritance, effective trust policy, malformed relations, jump order, trust-record parsing, public metadata |
| `src/ssh.rs` | Host verification, authentication order, connection ownership, deadlines, cancellation, SFTP loops, path handling, streaming offsets, local replacement |
| `src/storage.rs` | Encrypted representation, key selection, locks, atomic persistence, authenticated revisions, reload behavior |
| `src/tools.rs` | Cache-refresh timing, storage integration, safe error envelopes, dispatch into SSH/SFTP |
| `src/cloud.rs`, `src/crypto.rs` | Size/encoding boundaries, authenticated data, key and integer length checks, cache snapshot origin |
| `src/protocol.rs`, `src/main.rs` | Tool errors and cancellation, terminal-secret input, CLI/storage boundary; the separate design reviewer owns the additional output-lifecycle finding |

I inspected the SSH and inventory diffs, the relevant dependency implementation of `russh::client::connect_stream`, and the native OpenSSH tests. I added only `tests/code_complete_review.rs` and this report. I did not edit production files or use live account credentials.

## Finding: trust policy was still enforced before the transport

**CC1 — Medium integration issue; fixed and independently retested.**

Locations: `inventory::endpoint`, `inventory::resolve`, `inventory::host_details`, and `ssh::connect_route`.

While the compatibility change was being integrated, disabling verification in the transport was insufficient. The resolver still called `trusted_keys` unconditionally. Two saved keys for the same hostname and algorithm could therefore produce `Conflicting trusted SSH host keys` before a disabled verifier ever ran. The separate all-jump enrollment gate could similarly reject a route whose endpoint deliberately disabled verification. This would have left normal connections blocked despite the selected compatibility policy.

The construction problem was that one effective setting had enforcement spread across multiple layers. The fix makes the policy explicit and consistent:

- `strict_host_key_check` supplies one interpretation for both endpoint resolution and host-detail metadata. Missing settings are false; invalid non-null values are errors rather than implicitly disabling checks.
- `endpoint` parses enrolled keys only for strict endpoints. Disabled endpoints carry an empty trust-key list and do not fail on stale or conflicting saved pins.
- The global all-hop enrollment requirements were removed. Each endpoint's verifier enforces its own effective setting.
- Group inheritance, nearest explicit false values, saved route order, malformed-chain rejection, and explicit credential requirements remain independent of the trust-mode change.
- Invalid policy values produce null policy metadata and no generated SSH command instead of displaying a misleading valid policy.

The independent regression file failed before the inventory change landed: the old default was still true, conflicting rotation records were rejected, and a mixed-policy jump route failed its enrollment gate. After the fix, all three tests passed. These failures are evidence of the integration gap against the newly authorized requirements; the previous release's intentionally stricter default was not itself a construction defect.

No additional unresolved blocking construction defect was found in the reviewed paths. The separate software-design report records its independently discovered MCP output-lifecycle issue and remediation; those tests are not counted as executions by this reviewer.

## Storage answer and persistence checks

The Rust implementation does **not** use SQLite. `Store` serializes `StoredState`, encrypts it, and places it in a JSON envelope in the `state` file. The envelope contains format, key-backend, salt, revision, nonce, and base64 ciphertext fields. The plaintext state contains the session, optional remembered vault password, inventory snapshot, last-sync timestamp, and pending SSO state.

The default directory is `~/.termius-rs`, selected by the CLI; `TERMIUS_DATA_DIR` can override it. Release 0.1.1 removes the former `--data-dir` extension to restore the Python command interface. The directory is separate from the Python application's state. `state.lock` coordinates writers. A `state.key` file exists for the headless key-file backend; other installations use the saved OS-keychain backend or the supplied `TERMIUS_SECRETS_KEY` passphrase.

Relevant routines are `Store::open_with`, `derive_key`, `decrypt`, `Store::reload`, and `Store::save_locked`. The implementation derives a 32-byte local key with Argon2id and uses XChaCha20-Poly1305 for the ciphertext. Metadata and revision are authenticated. Writes use a temporary file and atomic replacement; revisions reject cooperating stale writers. Lock acquisition uses `try_lock_exclusive`, so ordinary lock contention returns a retry error instead of waiting indefinitely.

This is encrypted file storage, with whole-state serialization, rather than an indexed relational database. Possessing both a key-file installation's `state` and `state.key` permits decryption. Encryption does not protect against an already compromised user account or guarantee erasure of all in-memory copies.

## Changed host keys: exact current behavior

### Account login and SSH authentication are separate

The `login` and `login_complete` tool paths call Termius Cloud authentication. They do not connect to the inventory's SSH hosts and do not consult those hosts' public keys. A changed host fingerprint therefore does not invalidate a Termius account login.

For `exec` and `files`, the effective endpoint policy controls the SSH behavior:

| Effective policy | New, changed, or conflicting saved host key |
| --- | --- |
| Missing setting or explicit false | Host-key checking is disabled. Saved trust records do not block routing or authentication. The server identity is not verified. |
| Explicit or inherited true, enrolled Termius keys present | The received public key must match an enrolled key. A mismatch is an error; local `known_hosts` does not override those pins. |
| Explicit or inherited true, no enrolled Termius keys | The verifier checks system and user `known_hosts`. An unknown/mismatched key is an error. |

The rules apply separately to every jump and to the destination. Disabled trust does not erase a saved jump chain, relax malformed identity/route checks, enable agent forwarding, or permit an unintended credential fallback.

`HostVerifier::verify` compares complete public-key data rather than a display fingerprint string. In strict mode it rejects host certificates. `HostVerifier::new` reads `/etc/ssh/ssh_known_hosts` and `~/.ssh/known_hosts` only when no enrolled Termius keys are available; neither file silently takes precedence over the other. A matching plain key in either can establish trust, while a matching revoked entry returns an error. Hashed names, wildcard patterns and exclusions are supported. Port 22 uses the address; other ports use `[address]:port`. These files are read anew for a new connection and are not automatically rewritten.

### Cache refresh and recovery

Enrolled Termius keys come from `knownhost_set` in the locally cached cloud snapshot. `Runtime::ensure_fresh` reloads local state and normally refreshes `exec`, `files`, and `inventory` according to `TERMIUS_SYNC_TTL`, default 60 seconds. Host-list/detail reads use a 600-second interval. These are refreshes on calls, not a background watcher. The `sync` command or tool forces a pull and replaces the snapshot after success. An already-started connection continues with the endpoint snapshot it resolved.

In compatibility mode, key rotation needs no trust-record change to avoid a host-key rejection. In intentionally strict mode, first verify the replacement server key through an independent trusted channel, then update its saved Termius trust record and call the `sync` MCP tool. If the endpoint has no Termius pin and relies on `known_hosts`, update the verified matching entry in the applicable file. Updating only `known_hosts` cannot override a still-present Termius pin. Repeating account login or deleting the encrypted state is not required to repair a known-host record. The former Rust-only `sync` terminal command was removed in 0.1.1 to match Python.

The current MCP API does not include a tool that edits Termius's enrolled host-key records. The integration neither automatically enrolls a newly received key nor asks an interactive acceptance question during an MCP connection.

### Error and deadline behavior

Strict mismatches are returned during the SSH handshake, before the subsequent user-authentication routine. For an enrolled mismatch, the diagnostic is `SSH host key does not match the enrolled Termius keys`. The `russh` connection function propagates the verifier's handshake error. `Runtime::call` reports `ssh_failed` for command transport errors and `file_failed` for SFTP transport errors; a route-resolution failure is `ssh_failed`. The protocol sends a tool result with `isError: true` and the safe error/code fields.

The key-mismatch path contains no acceptance prompt, retry loop, or indefinite wait. TCP setup and the handshake have endpoint connection timeouts. The enclosing SSH operation also has a deadline, default 60 seconds and configurable from 1 to 86400 seconds. Dropping a route aborts its owned transport pump; cancellation closes the underlying route and the MCP protocol suppresses the canceled response.

This is not a universal whole-request latency guarantee. Automatic cloud refresh precedes the SSH deadline and has a separate 120-second limit. Waiting behind serialized cloud/login mutations can add time, and local filesystem operations have their operating system's behavior. A long pre-sync or queue wait is distinct from host-key verification.

`host_key_verification` in results records the **configured policy** for the target and ordered jumps. It is not an attestation of completed verification: an execution can return this metadata after timing out before its handshake completed.

## Large-file change and loop invariants

The 50 MiB guards and `MAX_TRANSFER` constant were removed from `get` and `put`. Inline `read`/`write` retain their 200000-byte limit because their data is carried inside MCP messages. File transfers stream through 32 KiB chunks; they do not build a file-sized in-memory buffer or send the entire file as one MCP result.

The relevant construction checks were:

- `get` advances only after a nonempty, size-validated SFTP read. EOF terminates the loop; malformed zero/oversize chunks are rejected. Its temporary local file is flushed and synchronized, and replaces the destination only after a successful transfer and remote close.
- `put` accepts only a regular local source and reads into a fixed-size buffer. Zero bytes terminate the loop. It advances only after the corresponding remote write succeeds.
- `advance_transfer_offset` converts the chunk length deliberately and uses `checked_add`. Both directions validate the next offset before committing that chunk's write, so removing the 50 MiB bound did not introduce unchecked offset wraparound.
- The existing timeout, cancellation, path validation, portable download-basename guard, and route cleanup surround the full streamed operation.
- The result contains byte count and paths. It does not contain transferred file contents.

There is no application-level total-size cap for `get`/`put`; the SFTP offset range, disk space, filesystem constraints, and configured deadline still apply. This is not a guarantee that every arbitrarily large file will finish under the default timeout. Interrupted uploads or remote writes can leave partial remote files; only local downloads have the stage-then-replace guarantee.

The independently executed OpenSSH large-file test transferred **52,461,691 bytes** in each direction. It compared lengths and streaming SHA-256 digests, using distinct data before, across, and after the previous 50 MiB boundary. This validates the boundary removal and end-to-end content integrity for that fixture without a file-sized test buffer.

## Independent verification

| Execution by this reviewer | Result |
| --- | --- |
| New construction regressions before the inventory change | 3 failed for the described pending policy gaps |
| `cargo test --locked --test code_complete_review --test review_regression` after fixes | 3 new construction tests and 4 earlier route/framing tests passed |
| `cargo test --locked --test ssh_openssh -- --ignored` | 4 real localhost OpenSSH tests passed |
| `cargo test --locked --lib ssh::tests::streamed_transfer_offsets_are_checked_at_the_protocol_boundary` | 1 passed, including the former size boundary and 64-bit overflow cases |
| `rustfmt --edition 2024 --check tests/code_complete_review.rs` | Passed |

The four OpenSSH tests cover the new large-file and per-endpoint trust behavior, all nine SFTP actions, command output/exit status, native jumps, strict wrong-key rejection, timeout output, cancellation, a failed download preserving its prior destination, output/inline-read bounds, and deletion of a symlink without traversing its target. They use disposable keys and a localhost daemon. No existing user SSH configuration or account password is modified.

The root remains responsible for the final complete formatting, lint, MSRV, regression, release-build, and publication checks after all reviewers' fixes. This report does not claim to have independently rerun those complete gates.

## Limits and conclusion

The tested environment was Linux. No live Termius email/Google/OTP account, real personal/team vault, or desktop OS keychain was used. Native Windows/macOS acceptance, external authentication backends, and live cloud compatibility remain separate validation tasks. The directory-removal checks do not make the SFTP v3 path interface immune to a hostile remote filesystem changing concurrently.

The requested compatibility policy intentionally trades host-key authentication for uninterrupted connections when keys change. Explicit strict policies remain enforceable, and the tests demonstrate that disabling one hop does not disable a different strict endpoint. Result metadata makes the configured modes visible without claiming a handshake succeeded.

The discovered policy-enforcement integration gap is corrected and independently retested. The large-file delta preserves bounded per-chunk memory, checked offsets, local-download replacement, deadlines, and cancellation. No unresolved blocking construction finding remains in this report's reviewed scope. This is independent AI review and reproducible local verification, not a professional security certification or real-account acceptance test.
