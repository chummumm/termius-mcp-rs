# Independent review and release verification

Date: **2026-11-19** · Initial Rust release: **0.1.0**

Two separate AI reviewers, neither of whom implemented production code, reviewed
this Rust port against the uploaded Python Termius MCP 3.2.0 snapshot. They
created reproductions, reported findings to the implementers, and independently
checked the fixes. They then reviewed the requested follow-up using the newly
installed `code-complete` and `a-philosophy-of-software-design` skills. This is
independent AI code review, not an external security
certification or a real-account acceptance test.

## Reports

- [Implementation and security review](reviews/security-review.md)
- [Source-compatibility review](reviews/compatibility-review.md)
- [Code Complete construction review](reviews/code-complete-review.md)
- [A Philosophy of Software Design review](reviews/software-design-review.md)

The first two reports document the initial baseline. The latter two review the
current connection-policy, streaming-transfer and transport-lifecycle changes.

## Requested follow-up and skill-based review

- An absent `strict_host_key_check` now means compatibility mode (`false`).
  Explicit inherited `true` still verifies the corresponding jump or target.
  Disabled endpoints ignore saved pins, including conflicting rotation records;
  malformed routing and missing credentials still fail before connecting.
  Compatibility mode does not authenticate the server's identity and cannot
  detect impersonation through a changed host key.
- `exec` and `files` report configured per-endpoint modes in
  `host_key_verification`. This is not proof that a handshake completed.
- SFTP `get`/`put` no longer impose a 50 MiB file-size ceiling. They stream in
  fixed 32 KiB chunks with checked 64-bit offsets, cancellation and deadlines.
  Inline MCP `read`/`write` retain the 200000-byte message-content limit.
- The design reviewer reproduced a medium-severity lifetime defect: a failed
  output pipe left `serve` awaiting open input and delayed cancellation of active
  work. The implementer fixed it by observing writer completion in the input
  loop and entering the existing shared cleanup path. Independent tests verify
  termination and closure of an actual stalled SSH connection.
- The cloud-sync comment now documents the existing atomic session-plus-snapshot
  commit invariant. One low-priority maintenance observation remains: the CLI's
  OTP retry classification depends on normalized error wording. Current messages
  work; a stable OTP discriminator is recommended when authentication errors are
  next changed. This is not a reproduced current login failure.

The construction reviewer independently checked the complete updated inventory
and transport policy, a 52,461,691-byte upload/download with streaming SHA-256,
and strict versus compatibility behavior for direct and mixed jump connections.
Neither follow-up reviewer found an unresolved blocking defect in their scope.

## Findings resolved before publication

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| R1 | High | Invalid chain owner silently became a direct SSH route | Reject all non-deleted unknown-owner chains; independent failing-then-passing regression |
| R2 | Medium | Windows drive/ADS basename changed a download destination | Require one normal filename component and reject colon/backslash/NUL |
| R3 | Medium contract issue | Timeout description included pre-sync but code bounded only SSH | Explicit phase contract, with separate 120-second cloud-refresh limit |
| R4 | Low | Legacy frame headers lacked case/order compatibility | Bounded case-insensitive header parsing in any order |
| C1 | Medium | Inventory tool double-wrapped its result | Return one flat envelope; full dispatch regression |
| C2 | Medium | SRP hex in a Buffer/array parsed as a raw large integer | Match the source's text/binary/base64 distinctions |
| C3 | Medium, conditional | Optional key discovery blocked readable personal sync | Preserve readable personal data, fail shared credentials closed, expose warnings |
| C4 | Low | Mixed legacy login responses lacked top-level fallback | Source-compatible per-field credential normalization |
| C5 | Low, conditional | Naive ISO timestamps always appeared stale | Interpret timezone-free timestamps as UTC |

Both reviewers concluded that no unresolved blocking finding remained in their
reviewed code paths. The reports include exact scope, reproductions and limits.

## Final local verification

The root ran the complete post-follow-up test suite on Linux with Rust 1.100.0,
and checked all targets against Rust 1.89.0. The 64 executed tests consist of:

| Suite | Passed |
| --- | ---: |
| Library unit tests | 45 |
| CLI parser test | 1 |
| Independent Code Complete regressions | 3 |
| Independent compatibility regressions | 2 |
| Full MCP transport/dispatch integration | 3 |
| Independent security/protocol regressions | 4 |
| Independent software-design regressions | 2 |
| Real localhost OpenSSH integration (explicitly enabled) | 4 |
| **Total** | **64** |

The four OpenSSH tests are intentionally ignored in the default test invocation
because they require `sshd`/`ssh-keygen`; they were explicitly enabled and passed.
The MCP integration test verifies that a stalled SSH handshake does not block
status, cancellation closes the actual TCP connection, and no cancelled response
is emitted. The OpenSSH tests cover all nine SFTP operations, native jumps,
strict wrong-key rejection, compatibility and mixed trust modes, transfers larger
than the former 50 MiB cap, partial timeout output and safe local replacement.

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --all-targets --locked -- -D warnings`: passed.
- `cargo test --all-targets --locked`: 60 passed, 4 OpenSSH tests deferred.
- `cargo test --test ssh_openssh --locked -- --ignored`: 4 passed.
- `cargo +1.89.0 check --all-targets --locked`: passed.
- `cargo build --release --locked`: passed.

The publication scan found no GitHub/AWS token patterns, JWTs, PEM private keys,
user contact address or private workspace paths in the deliverable. This targeted
scan is additional evidence, not a guarantee of absence of every possible secret.
Deterministic cryptographic fixture values are public synthetic test data.

### Dependency audit

`cargo audit` 0.23.0 completed on 2026-11-19 against the final lockfile:
**zero known vulnerabilities and four informational unmaintained-package
warnings**. This is a point-in-time advisory database check, not a proof of
dependency security. The database contained 1,541 advisories at commit
`5c6e809b6c79eea026dd79324477f7d5d020c452` (updated
2026-11-19T09:42:17+01:00).

| Package | Advisory | Dependency path / disposition |
| --- | --- | --- |
| `chrono` 0.4.45 | RUSTSEC-2026-0543 | Remains through `russh-sftp` 3.0.1; application timestamps now use `time` 0.3.55 |
| `zbus_names` 4.3.5 | RUSTSEC-2026-0371 | Linux Secret Service keyring backend |
| `zvariant` 5.15.1 | RUSTSEC-2026-0370 | Linux Secret Service keyring backend |
| `zvariant_derive` 5.15.1 | RUSTSEC-2026-0372 | Linux Secret Service keyring backend |

The currently selected stable SFTP and keyring backends still bring these
transitive packages. They are recorded rather than suppressed. Removing them
requires upstream backend adoption or a separately reviewed backend change;
this release does not introduce an unreviewed fork or prerelease dependency.
The direct timestamp-library migration was independently reviewed and the full
test, lint, MSRV and release-build gates were rerun afterward.
The follow-up connection and transfer changes do not change `Cargo.toml` or
`Cargo.lock`; this audit applies to the same dependency graph.

### Reviewed source fingerprint

SHA-256: `72f1d71b043687593c4cced3e5983ad85823c96e054aac061d605b8eab13d3c4`

The digest covers sorted file paths and bytes under `src/` and `tests/`, plus
`Cargo.toml` and `Cargo.lock`; each path and content is followed by a NUL byte.
Documentation and reports are outside that digest to avoid a circular hash.

## Remaining validation boundaries

- No live Termius email/Google/OTP login or real personal/team vault was tested.
- No native Windows/macOS runtime or live desktop OS-keychain acceptance was
  performed locally. CI is configured for these operating systems; only actual
  completed runs can establish their outcomes.
- OpenSSH integration used temporary Ed25519 keys; real password/agent/encrypted
  key authentication environments are not all represented in that test fixture.
- Optional API access failures can leave shared entities unreadable. The tools
  expose their count and warnings rather than claiming a complete vault.
- Headless state and its colocated key file are jointly decryptable. Same-user
  compromise and complete erasure of all in-memory JSON/string copies are outside
  the claimed protection.
- Interrupted remote writes/uploads may leave partial files. Only local downloads
  have a stage-then-replace guarantee.
- Termius's undocumented APIs may change independently of this source snapshot.
