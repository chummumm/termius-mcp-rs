# Independent software-design review

Date: **2026-11-19**

Reviewer: a separate AI reviewer that did not author or modify production code.
Review framework: the installed `a-philosophy-of-software-design` skill and its
`a-philosophy-of-software-design.mini.md`, both read before this review. The focus
was information hiding, state invariants, temporal coupling, module depth and
public behavior. This report complements the earlier compatibility review and
the separately assigned Code Complete review.

## Scope and outcome

The reviewer traced the CLI/MCP dispatcher through local state, cloud refresh,
inventory resolution and SSH lifetime ownership. One concrete transport
lifecycle defect was independently reproduced, reported to the implementer,
fixed by the implementer and independently retested. **No unresolved blocking
design defect remains in the reviewed paths.** Two small maintenance observations
are recorded below with their actual current behavior and limited recommended
follow-up.

The review uses the user's current connection contract: an unspecified
`strict_host_key_check` means compatibility mode; an explicitly inherited true
value requires verification. Jump endpoints retain their individual policies.
Unusable routes must still fail before any connection opens. The separate
streamed-transfer change and its large-file acceptance tests belong to the
construction reviewer; this report does not claim to have repeated those tests.

## D1 — Output failure did not terminate the MCP session

**Severity: medium. Status: fixed and independently verified.**

Source: `src/protocol.rs::serve`.

The output writer was spawned as a separate task, but its result was observed
only after the input loop ended. A `BrokenPipe` from `write_all` or `flush` could
therefore leave the server waiting in `read_message` while the input peer stayed
open. Requests already executing did not immediately receive cancellation. The
input loop implicitly depended on an additional input event to discover that
the response channel was gone.

This was an ownership and lifetime boundary defect: one transport half could end
without ending the logical MCP session. Callers should not have to close both
halves in a particular order to release remote work.

### Independent reproduction

`tests/software_design_review.rs` contains a synthetic `AsyncWrite` that reports
an observed `BrokenPipe`. The first regression keeps the input stream open after
the initialize response fails. Before the fix,
`failed_output_ends_protocol_even_if_input_remains_open` failed with:

```text
MCP server stayed alive after its output pipe failed
```

The reproduction waits until the actual write attempt is observed, so the
assertion does not depend on guessing when the writer starts.

### Correction and verification

The implementer added a selection between writer completion and the next input
message. Either event can now enter the existing shared cleanup path. The writer
result is retained so the completed join handle is not polled twice; the
original output error reaches the caller. Existing cancellation and bounded
task-drain behavior remain centralized in `serve`.

The reviewer then added
`failed_output_cancels_an_active_ssh_connection`. It uses a disposable encrypted
state fixture and a real localhost TCP listener. An `exec` call reaches the
listener and stalls before receiving an SSH banner. A later ping response is
made to fail while the MCP input stays open. The regression verifies both that
the actual socket closes and that `serve` returns the output error.

Independent retest:

```text
cargo test --locked --test software_design_review
2 passed; 0 failed; 0 ignored

cargo test --locked --test mcp_integration
3 passed; 0 failed; 0 ignored
```

No real SSH server credentials, Termius account or external network service is
used by these regressions.

## Module boundaries that hold useful invariants

### State updates are assembled and committed as one change

`src/tools.rs::Runtime` owns serialization of cloud mutations. A cloud operation
works on a cloned `StoredState`; `Runtime::commit` reloads current local state
and rejects a conflicting intervening change before saving. The store separately
checks its authenticated revision while holding its file lock. These checks
protect different intervals: the Runtime comparison covers time spent awaiting
cloud work, and the storage revision covers the interval between reload and
write. The storage layer also keeps envelope authentication, key backend, file
permissions and atomic replacement together.

The reviewer checked that login replaces session/cache fields, logout writes
`StoredState::default`, and sync commits the newly decrypted inventory with its
updated session. No state mutation contract defect was found in those paths.

### Cloud relationship knowledge ends at inventory resolution

`src/inventory.rs::resolve` turns the cloud snapshot into `ConnectionSpec` and
`Endpoint` values. The SSH module consumes resolved addresses, credentials,
policies and ordered jumps; it does not reconstruct groups, cloud identity links
or encrypted-record relationships. This boundary hides meaningful complexity.

The new host-key behavior is localized at this boundary and in
`src/ssh.rs::HostVerifier`. `strict_host_key_check` distinguishes absence from an
invalid explicit value. Compatibility mode avoids interpreting saved host pins
before connecting. Explicit strict mode keeps the pin/known-host verification
path. Jump endpoints are resolved independently, and `host_key_verification`
reports their configured modes in successful exec/files results.

The reviewer inspected the route checks and independently reran:

```text
cargo test --locked --lib inventory::tests
9 passed; 0 failed; 0 ignored
```

The cases include inherited false policy, individual jump policies and ordering,
unknown chain ownership, missing ancestors, deleted/unreadable credentials and
secret-free public projections. Unknown chain owners, repeated hops and missing
referenced hosts still produce errors; changing the verification default does
not create a direct-connection fallback.

### SSH resource lifetime is owned below the dispatcher

`src/ssh.rs::Route` owns connection handles and the `TransportPump` that carries
the first TCP stream. Dropping the pump aborts that transport task. `run_exec`
and `run_files` own operation cancellation and timeout behavior. The Runtime
does not need to know how many handles a jump route created. The independent
active-socket regression above exercised this ownership through the public MCP
session boundary.

## Nonblocking maintenance observations

### N1 — Make the cloud sync's paired state contract explicit

Source: `src/cloud.rs::pull` and `src/tools.rs::Runtime::pull_state`.

**Status: documentation corrected and independently checked.**

`pull` accepts `&mut session` and returns an inventory value. A successful call
can update settings and persisted keyring material in the session, so the caller
must commit that updated session together with the returned inventory. The
current caller correctly places both in the same candidate `StoredState` and
commits them together. The original public cloud function comment described
committing the snapshot but left the session half of the invariant implicit.

The implementer updated the comment to require a detached session copy and an
atomic commit of that updated session with the returned snapshot. The reviewer
checked the comment against the current caller. If another caller is introduced,
assess whether a single semantic sync-result value would make that invariant
easier to preserve. No incorrect current commit was observed, and no new wrapper
is required now.

### N2 — OTP retry depends on human-readable error wording

Source: `src/cloud.rs::login_error`, `rest_login`, the login branches in
`src/tools.rs`, and `src/main.rs::needs_otp`.

**Status: resolved in 0.1.1 and independently rechecked.**

The subsequent [CLI compatibility review](cli-compatibility-review.md) verified
that `cloud::OtpRequired` survives the cloud/tool boundary as `otp_required` and
that the CLI retries once based on this code. Tests cover both real challenges
and unrelated errors that merely mention OTP. The original observation below
records the pre-0.1.1 implementation and the reason for that change.

The cloud layer recognized numeric OTP conditions, but the dispatcher exposed
them using the general `login_failed` code. The CLI then recovered the condition
by searching the displayed message for `otp`, `two-factor`, `2fa` or `authy`.
The messages satisfied this convention. An otherwise harmless wording or
translation change can alter the interactive retry behavior.

Recommended follow-up when changing authentication errors: preserve a stable
OTP-required discriminator through the cloud/tool boundary and let the CLI
branch on that value. This isolates presentation text from retry policy without
requiring a new service layer. This is a maintenance dependency, not a reproduced
failure with the current messages.

## Changes made by this reviewer and limits

The reviewer added `tests/software_design_review.rs` and this report. Production
changes were made by the implementer and then independently checked. The review
did not introduce a broad module split, storage migration or framework.

Validation was local source inspection and focused deterministic tests. It did
not exercise real Termius authentication, a live cloud vault, desktop OS-keychain
integration or a deployed MCP client. The localhost SSH test verifies transport
cancellation before handshake completion; the separate OpenSSH suite provides
the authenticated SSH/SFTP evidence recorded elsewhere.
