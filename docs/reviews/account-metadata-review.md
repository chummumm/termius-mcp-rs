# Independent account-metadata review

Date: **2026-11-19**

Reviewer: a separate AI reviewer that did not author or modify production code.
The review used the installed `a-philosophy-of-software-design` skill and its
complete mini rules. It covers the proposed 0.1.3 diff based on
`137e6ac507efebc32a3594c330499082ee5ea7de`.

## Scope and outcome

Reviewed the changes in `src/cloud.rs`, `src/tools.rs`, `src/inventory.rs`,
`src/ssh.rs`, the MCP tool catalog, the affected tests, both READMEs, the porting
notes, changelog and version declarations. The Python 3.2.0 source was inspected
independently for account-setting conversion, host metadata, manual command
rendering and native SSH/SFTP agent behavior.

**No unresolved blocking defect was found in the reviewed patch.** A wording
issue in the tool catalog and porting notes was reported and corrected: the
verification metadata is now explicitly described as conditional on at least
one strict endpoint, rather than promised for every result.

## Team warnings affect display only

The new helper reads the same saved team flag used by `status`: JSON `true` and
the legacy string `"yes"` mean a team account. It filters existing cached warning
strings; team membership alone does not generate a warning.

- `status` and `sync` show the existing team-vault-key failure only for a team
  account.
- A personal or unmarked account omits that warning even when
  `status(diagnostics=true)` is requested.
- Other cached warning strings remain opt-in through `status` diagnostics.
- Ordinary host, inventory, SSH and SFTP responses remain quiet. Positive
  unreadable-resource counts and actual operation failures retain their
  existing behavior.

The cached warning list is not mutated by presentation. Most importantly,
`cloud::pull` still requests team/shared keys whenever the restored private-key
state permits it. The cloud diff only replaces generated warning strings with
identical constants; it does not add an `is_team` gate to network retrieval,
key unwrapping or decryption. A false account flag therefore cannot make the
client skip shared-key retrieval or treat an unavailable referenced resource as
usable.

## Account forwarding matches the Python response contract

Python `handle_host()` overrides the merged host/group forwarding value with
`AccountManager.get_settings()`. Its saved-setting default is true. Cloud values
first pass through `set_settings()`, which uses Python truthiness to write
`yes`/`no`, and `get_settings()` reads that normalized value.

The Rust helper consumes the raw JSON held in `session.settings` and matches
that conversion: explicit null, zero and empty strings/containers are false;
nonzero numbers and nonempty strings/containers are true. In particular, the
nonempty string `"false"` is truthy in the Python source. A missing saved value
defaults to true. This is a compatibility conversion, not a new yes/no string
parser.

The selected account boolean is passed into the host projection and used for
both `host.agent_forwarding` and the reference command's `ForwardAgent=yes/no`.
Host/group values cannot override it. Destination shell quoting is preserved,
and a host chain still returns no manual command. Stale or invalid chain cases
keep their previous command-suppression behavior.

Python native MCP execution explicitly distinguishes local-agent authentication
from forwarding and never requests forwarding to the remote session. Rust's
native SSH/SFTP transport likewise remains unchanged. Reporting the account
preference and rendering a manual command do not enable agent forwarding inside
MCP `exec` or `files`; the documentation now states this distinction.

The public Rust `inventory::host_details` function gains an account-setting
argument. Source consumers embedding that Rust function must update their call
sites. This review confirms the CLI/MCP entry-point contract, not source-level
stability of the Rust library API.

## Verification metadata preserves mixed routes

`host_key_verification` is omitted only when the target is non-strict and every
jump is non-strict. If any endpoint is strict, the entire ordered target/jump
mapping remains present, including disabled entries that identify positions in
a mixed route. This covers a disabled target behind a strict jump as well as a
strict target behind a disabled jump.

The projection is used after the existing exec/file operation and does not
change verification, authentication or connection code. The metadata continues
to describe configured modes, not successful completion of every handshake.
An omitted field does not mean that checking was enabled. The reviewer also
inspected the updated real-OpenSSH/SFTP regression source, which exercises both
all-disabled omission and mixed-mode preservation while retaining strict-key
failure cases.

## Independent validation performed

After the main test build completed, the reviewer ran these focused checks:

```text
cargo test --locked --test mcp_integration team_warning_visibility_tracks_the_saved_account_without_hiding_partial_inventory -- --exact
1 passed; 0 failed; 7 filtered out

cargo test --locked --test mcp_integration host_forwarding_reads_the_saved_account_and_uses_the_same_value_in_its_command -- --exact
1 passed; 0 failed; 7 filtered out

cargo test --locked --lib verification_diagnostics
2 passed; 0 failed; 83 filtered out

git diff --check
passed
```

The MCP integration checks cover account-flag variants, explicit diagnostics,
unchanged cached warning data, incomplete inventories and host/command agreement
using the saved account setting. The verification checks cover direct and
multi-hop all-disabled routes plus full ordered mixed/strict mappings.

The reviewer did not independently rerun the complete suite, release builds or
real-OpenSSH fixture for this report; those validations belong to the main
agent's release work. No real Termius account, Google sign-in, live team vault or
production host was used. This is not a claim of live cloud end-to-end
acceptance.
