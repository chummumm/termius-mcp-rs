# Independent CLI compatibility review

Date: **2026-11-19**

Reviewer: a separate AI reviewer that did not implement the CLI changes.
Frameworks: the installed `code-complete` and
`a-philosophy-of-software-design` skills and their mini rule documents.

## Source and scope

The reference is the uploaded Python Termius MCP 3.2.0 snapshot, specifically:

- `setup.py`: console entry points.
- `termius/main.py`: selection between terminal commands and stdio MCP.
- `termius/cli.py`: parser, prompts, normalization, retry and output behavior.
- `tests/unit/cli_test.py`: the source's documented executable CLI expectations.

The user's final instruction is to expose only the two original executable
names, `termius` and `termius-mcp`. The extra `termius-mcp-rs` executable must be
removed. The Rust package/repository name is a separate packaging concern.
Storage format and the previously authorized SSH policy are outside this change.

## Independently extracted behavior contract

| Area | Python behavior to preserve |
| --- | --- |
| Executable names | `termius` and `termius-mcp` run the same entry point. |
| No arguments | Start MCP on stdin/stdout. A terminal additionally receives an informational stderr banner. The internal `cli.run([])` help/error path is not the process entry-point behavior. |
| Terminal commands | `login`, `status`, `logout`. The original CLI has no `sync` command; synchronization remains an MCP tool. |
| Login arguments | Optional `google` or `email`, `-u`/`--username`, `--otp`, `--no-remember`. Passwords are not a command-line argument. |
| Parser conventions | Unambiguous long-option abbreviations are accepted; repeated value options use the last value. |
| Method selection | An explicit method wins. A nonempty username implies email. Otherwise prompt on a TTY; blank selects Google and interactive input is stripped and lowercased. Without a TTY, report `specify google or email`. |
| Username | Strip the supplied value. If missing/blank, prompt on a TTY; otherwise report `username is required for email login (use -u)`. |
| Vault password | A nonempty `TERMIUS_VAULT_PASSWORD` takes priority; otherwise request a secret. Preserve password whitespace. Remember it by default; `--no-remember` forwards false. |
| Google | Print the browser instructions on stderr, read and trim `Paste callback URL: `, then request the vault password and complete login. Callback input is usable through a pipe. The source deliberately uses a line editor to support long pasted callbacks on a TTY. |
| OTP | When a challenge occurs and no nonempty OTP was supplied, ask for `OTP: `, trim it, reject an empty answer and retry once. Do not prompt repeatedly after a failed retry. |
| Login success | stdout: `Signed in as <username>.` |
| Signed-out status | stdout: `Not signed in.`; success exit code; no cloud synchronization. |
| Signed-in status | stdout: `Signed in as <username>, <N> hosts, cache fresh.` or `cache stale.` |
| Logout | Clear saved session/vault/cache state and print `Signed out.` on stdout. |
| Exit and error paths | Successful commands/help exit 0; expected validation/authentication failures exit 1; parser errors exit 2. CLI validation messages are concise; cloud login failures use the `Login failed: ` prefix. |

The reviewer also executed the exact uploaded `cli.py` with only its runtime and
cloud dependencies replaced by local fakes. That source-level oracle confirmed
the status/logout messages, exit codes, rejected `sync`, stripped usernames,
interactive method normalization, unmodified password whitespace and remember
flag forwarding. The exact source `build_parser` was also executed independently
to confirm long-option abbreviations and last-value handling. This does not
establish a real cloud login.

## Differences reproduced before implementation

The initial Rust CLI returned JSON for status/logout, accepted a CLI `sync`,
reported generic non-TTY failures and rejected a piped Google callback before
showing the original prompt. Source inspection also found missing username
normalization and interactive method lowercasing. The previous extra executable
name was separately removed under the user's final instruction.

The independent public-binary regression file is `tests/cli_review.rs`. Its first
run against the pre-rewrite command implementation reported **2 passed and 6
failed**. The two passing checks covered the corrected executable names and the
existing no-argument MCP entry. Failures independently reproduced the plain-text,
command-surface and prompt/validation differences above.

## Final implementation and retest

**Outcome: the reviewed original CLI contract is restored, and no unresolved
blocking CLI compatibility finding remains.**

The final implementation in `src/cli.rs` owns terminal parsing, presentation and
input. Both original executable names use the same `cli::run` entry. It exposes
only the original login/status/logout command surface and keeps no-argument
stdio MCP. CLI `sync`, `--version`, `--data-dir` and the extra Rust-named
executable were removed; the existing `TERMIUS_DATA_DIR` environment variable
continues to select the Rust state directory.

Source inspection confirmed username trimming, interactive method normalization,
environment-password precedence without password trimming, visible callback/OTP
input, non-TTY input fallback, original success/status/logout text and one OTP
retry. The private terminal/service interfaces let the implementation tests
exercise this conversation without opening the cloud, while Runtime retains
ownership of authentication and saved state.

OTP conditions now retain a typed `cloud::OtpRequired` reason through
`tools::login_failure`, which exposes `code = "otp_required"`. The CLI branches
on that code. A regular failure that merely mentions OTP does not prompt, and a
second challenge does not cause a third attempt. This also resolves the
message-wording dependency recorded as N2 in the earlier software-design review.

### Independent retest results

| Check | Result |
| --- | --- |
| `cargo test --locked --test cli_review` | **8 passed**, 0 failed, 0 ignored |
| `cargo test --locked --lib cli::tests` | **26 passed**, 0 failed, 0 ignored |
| `cargo test --locked --lib otp_` | **9 passed**, 0 failed, 0 ignored |
| Formatting check of reviewer-owned `tests/cli_review.rs` | Passed |

The 26 CLI unit tests were authored by the implementer, then inspected and
independently rerun by this reviewer. The nine OTP-filtered tests overlap seven
of those CLI cases and add the two cloud/tool error-boundary checks; they are
not nine additional unique CLI tests. The eight public-binary checks were
authored by this reviewer and cover both executable names, exact status/logout
text, fresh/stale counts, persisted logout cleanup, parser rejection, non-TTY
validation, piped Google callback prompting and an actual no-argument MCP
initialize exchange.

### Real terminal check for long Google callbacks

The reviewer launched the built `termius login google` in a real Linux
pseudoterminal, with stdin/stdout/stderr attached to the PTY and a disposable
state directory. After reading the generated SSO request ID, the reviewer pasted
a callback containing over **12,000 bytes** of synthetic padding, followed by
the matching `requestId` at the very end. The callback deliberately omitted
`firebaseToken`.

The process recognized the final request ID and returned
`SSO callback is missing firebaseToken`, with exit code 1. This demonstrates
that the long line was preserved through the actual terminal reader, rather
than cut off by the canonical input limit. The missing token is checked before
cloud requests, so the experiment used no cloud account or external login. The
production reader uses `rustyline` with automatic history disabled and no
history load/save calls. This is Linux terminal evidence; native macOS and
Windows terminal interaction was not exercised here.

The reviewer also checked that production CLI changes did not modify the
storage format or the previously authorized SSH verification behavior. Release
compilation, cross-platform builds and final archive contents are verified by
the root/release agents and are outside the results claimed in this report.

## Validation limits

All account names, passwords and tokens used in tests are synthetic. Public
binary tests use disposable local encrypted state. No real Termius account,
Google browser session, OTP service or external cloud endpoint is used. A
successful mocked or offline login test establishes argument/retry behavior,
not live service interoperability.

This reviewer edited only `tests/cli_review.rs` and this report during this
round. Production changes and release publication were owned by the other agents.
