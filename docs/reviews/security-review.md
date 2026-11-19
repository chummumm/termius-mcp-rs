# Independent implementation and security review

> Maintainer scope note: this report records the initial reviewed baseline
> (`13fbe03`). The subsequent user-requested compatibility default, per-hop
> host-key policy and uncapped streamed file transfers are reviewed in
> [the Code Complete review](code-complete-review.md) and
> [the software-design review](software-design-review.md). Statements below
> about the earlier default or transfer cap are historical.

Review date: 2026-11-19
Target: Termius MCP Rust 0.1.0
Reference: user-supplied Termius MCP 3.2.0 Python source snapshot
Reviewer: a separate AI agent that did not implement the production code

## Scope and method

I read all production Rust modules (`cloud`, `crypto`, `inventory`, `ssh`, `storage`, `protocol`, `tools`, and the CLI), and compared the corresponding Python authentication, cryptography, transformation, relationship, SSH, SFTP, storage, and MCP paths. I checked the interfaces between independently implemented modules, rather than relying only on unit-test counts. I also read the OpenSSH fixture and independently executed its two real localhost integration tests.

The review emphasized failure boundaries: whether missing or malformed route metadata can silently change the server contacted; whether credentials can fall back to an unintended source; whether stored state survives corruption and concurrent writes; whether host-key and ciphertext authentication are enforced; and whether protocol framing, output and transfers remain bounded.

This is an independent AI review, not third-party professional certification, a formal verification, a penetration test of Termius Cloud, or a claim that the service's undocumented APIs will remain compatible.

## Findings and disposition

### R1 — High: malformed SSH chain ownership silently bypassed a saved route

**Location:** `src/inventory.rs`, `jump_hosts`.

The initial implementation rejected an unknown chain owner only when the row already had `_undecryptable: true`. An otherwise plaintext or decrypted `hostchain_set` row with `ssh_config: null`, zero, an invalid string, or an empty object was ignored by the matching loop. Resolving a host then returned an empty jump list, converting an unknown route into a direct connection.

The Python transformer explicitly records an unknown-owner sentinel for any invalid saved chain owner, and its SSH resolver refuses to proceed. This is a security boundary, because the client must not invent a direct route when it cannot determine which host or group owns a saved chain.

**Reproduction:** the independent test `malformed_chain_owner_cannot_silently_turn_into_direct_connection` failed on the original Rust implementation. A normal empty-chain control passed.

**Fix reviewed:** the resolver now skips explicitly deleted rows, then rejects every remaining chain with an invalid or absent owner before considering direct fallback. It does not depend on a previous decryption-error flag.

**Status:** fixed and independently retested. Three independent tests cover invalid owners, a deliberately empty chain set, and an explicitly deleted invalid chain.

### R2 — Medium: remote filenames could change the Windows download destination

**Location:** `src/ssh.rs`, the SFTP `get` directory-destination branch.

The initial remote-basename guard rejected slash-related traversal and backslashes, but permitted a POSIX filename such as `C:payload`. On Windows, passing this to `PathBuf::push` introduces a drive prefix rather than appending an ordinary filename, so the final path can escape the requested destination directory. A colon also has alternate-stream meaning on Windows.

**Fix reviewed:** `local_download_name` requires exactly one `Component::Normal` and rejects colon, backslash and NUL on all platforms before calling `push`.

**Status:** fixed. I read the complete guard and independently ran `download_basenames_cannot_change_local_directory_or_drive`; it passes with drive-relative, drive-absolute, UNC, slash, dot and ordinary Unicode/space filename cases. This establishes the portable lexical guard; a full native Windows SFTP runtime test was not available during this review.

### R3 — Medium contract issue: tool timeout did not include automatic cloud synchronization

**Location:** `src/tools.rs`, `Runtime::call`, and MCP tool descriptions.

`exec` and `files` perform cache refresh before starting the SSH operation's timeout. A stale cache may therefore spend up to the separately configured 120-second cloud-sync deadline, plus a short wait for another serialized cloud mutation, before an SSH timeout of one second begins. The original description called this a whole-call timeout.

**Resolution reviewed:** preserve the Python source's phase ordering and document the real contract. The catalog now explicitly says that `timeout` bounds the SSH connection plus command or transfer phase, and that an automatic cloud pull may precede it with a separate 120-second limit. The README must use the same contract. This is a documentation resolution, not an assertion that the complete MCP invocation is globally deadline-bounded.

**Status:** catalog corrected; operational documentation should retain that wording.

### R4 — Low: legacy frame header case and ordering were narrower than the Python source

**Location:** `src/protocol.rs`, `read_message`.

The initial first-header check accepted only literal `Content-Length:` or lowercase `content-length:`. It rejected `CONTENT-LENGTH:` and a valid `Content-Type` header preceding `Content-Length`, even though the subsequent header parser and the Python source support case-insensitive header names. Modern JSONL traffic was unaffected.

**Fix reviewed:** the first-line recognizer now accepts a syntactically valid header name independent of capitalization, and the bounded header parser finds `Content-Length` in any position. Duplicate lengths and oversize bodies remain rejected.

**Status:** fixed. The independent `legacy_header_names_are_case_insensitive_and_order_independent` regression now passes for both cases.

### Coordinated compatibility finding

A second independent reviewer identified a mismatch between `inventory::list`, which already returns `{kind,count,items}`, and the runtime wrapper, which treated that envelope as an array. The initial result nested the envelope under `items` and reported count zero. I corroborated the mismatch from source and reviewed the corrected runtime path, which returns the helper's envelope directly. The second reviewer owns that finding's end-to-end regression evidence.

## Checks performed by this reviewer

| Check | Result |
| --- | --- |
| Independent malformed-chain regression, before fix | Failed as expected; direct-connection control passed |
| Independent route/header regression suite, after fixes | 4 passed |
| Real localhost OpenSSH integration suite | 2 passed |
| Portable download-basename guard | 1 passed |
| Existing protocol framing and negotiation tests | 4 passed |
| Legacy header case/order regression | Passed as part of the four-case independent suite |

The OpenSSH integration suite uses freshly generated ephemeral server/client keys and a disposable localhost SSH daemon. It covers stdout/stderr/exit status, all nine SFTP operations, a real direct-tcpip jump, output limits, command timeout with partial output, cancellation, host-key mismatch rejection, preservation of an existing local file after a failed download, and deleting a symlink without traversing its target. No user SSH configuration or cloud account was used.

## Security properties observed in the reviewed implementation

- Cloud requests use fixed TLS endpoints. HTTP redirects do not forward DeviceTokens. Authentication errors do not echo server response bodies or SSO tokens.
- The Rust port validates the SRP server proof and authenticated ciphertext instead of continuing after an authentication failure. Its cryptographic primitives are provided by Rust libraries; the protocol construction is compared with the source and reference vectors.
- The cloud Sodium format correctly uses XSalsa20-Poly1305/crypto_box; the separate local-state format uses XChaCha20-Poly1305. These are distinct and should not be conflated in documentation.
- Explicit unavailable identity/key references are errors. An explicitly selected private key with missing private material does not become an SSH-agent fallback.
- Direct SSH uses strict host-key verification by default. Jump routes require enrolled Termius host keys at every hop. An explicitly saved direct-host `strict_host_key_check=false` remains an explicit policy exception.
- The transport pump is owned by the route and aborted when the operation is dropped. This covers connections still negotiating, as well as established command/transfer channels.
- Local state is authenticated and encrypted, written with atomic replacement and revision checks, and isolated from the Python application's directory. On Unix it checks ownership, permissions, symlinks and hard links. A wrong key or malformed state is not silently replaced with an empty vault.
- SFTP download content is staged to a temporary file and only replaces the destination after a complete bounded transfer. Recursive removal uses `lstat`, does not intentionally descend through symlinks, bounds traversal, and refuses the canonical remote root.
- Framing has input-size limits, tool concurrency is capped, output capture is bounded, and destructive booleans are not permissively coerced from strings.

## Remaining validation limits and operational boundaries

1. No live Termius account, Google SSO flow, OTP account, real personal/team vault, or private production host was available for end-to-end validation. Offline crypto vectors and mock protocol responses are evidence of implementation compatibility, not evidence of a successful production login.
2. The review environment exercised Linux. Native macOS/Windows execution and real desktop keychain integration still require their respective CI/user environments. In particular, Unix mode/owner checks do not establish Windows ACL policy.
3. The headless key-file backend protects a separately copied state file, but someone who possesses both `state` and `state.key`, or operates as the same OS user, can decrypt it. A separately supplied passphrase or OS credential store provides a different key-separation boundary.
4. SFTP `write` and `put` intentionally preserve the source's in-place upload behavior; interruption may leave a partial remote file. The atomicity guarantee applies to local `get` destinations, not every remote mutation. Concurrent hostile changes to a remote directory tree are not prevented by the SFTP v3 path-based interface.
5. The code zeroizes selected key/password buffers, but credentials also exist in `String` and JSON values. It does not guarantee complete memory erasure, resistance to a compromised OS user, or protection from process memory inspection.
6. The APIs emulate the supplied desktop 10.0.6-era source and are not an official Termius integration contract. Host certificates are deliberately not accepted as a substitute for enrolled plain host keys.
7. The parent must run the final whole-project build, formatting, lint and regression gates after applying review fixes, and clearly identify any platform or real-service checks that have not actually run.

## Review conclusion

The high-severity fail-open route finding and the Windows destination finding were corrected and the relevant boundaries were re-reviewed. I found no additional unresolved critical or high-severity production-code defect within the reviewed scope. The low-priority legacy-header finding is also corrected and independently retested. Publication should follow the parent's final whole-project regression/lint/build gates. These conclusions are limited to the code and tests inspected, and do not remove the live-service validation limits above.
