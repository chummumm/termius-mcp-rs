# Independent response-compatibility review

Date: **2026-11-19**

Reviewer: a separate AI reviewer that did not author or modify production code.
The reviewer read the installed `a-philosophy-of-software-design` skill and its
complete mini rules before the review. The review covered the proposed 0.1.2
changes based on commit `7e9636bab1a9ea334759dd68f55029cba3c7394a`.

## Scope and outcome

Reviewed `src/tools.rs`, `src/tool_catalog.json`, the capture changes in
`src/ssh.rs`, `tests/mcp_integration.rs`, the new dispatch/drain regressions in
`tests/ssh_openssh.rs`, both READMEs and the 0.1.2 changelog. The focus was default
compatibility, observable failure behavior, parameter boundaries and context
reduction without changing SSH/SFTP work.

**No unresolved blocking defect was found in these changes.** Two documentation
clarifications were reported to the implementer and corrected: the preserved
contract is the original business fields and default result scope, while some
diagnostic fields are intentionally omitted; offset pages describe the current
result set and are not a snapshot transaction across cloud or directory changes.
The existing 10000-entry SFTP directory limit is also explicitly documented.

## Findings and verified contracts

### Quiet output does not hide an operation failure

Ordinary responses no longer repeat cached `sync_warnings`. The warnings remain
stored and are returned only by an explicit `status(diagnostics=true)` request.
Zero `unreadable_entities` counts are omitted; positive counts remain visible on
`status`, `sync`, `hosts` and `inventory`, so filtering unreadable records does
not silently present a complete vault. Successful `host`, `exec` and `files`
results do not repeat diagnostics about unrelated inventory.

The change does not alter route resolution or cloud error handling. Actual tool
errors, stale-cache `stale`/`sync_error` fields, `connection_unavailable` and
`host_key_verification` remain available. A missing or undecryptable target still
fails instead of becoming a direct SSH connection or a successful empty result.

### Pagination is opt-in and applies after filtering

Without `limit` or `offset`, the existing result arrays and default scope are
unchanged. Requested pagination applies to the already filtered host list,
visible inventory projection or sorted SFTP directory listing. `count` is the
returned page size; `total`, the requested `offset` and `next_offset` appear only
for a paginated request. The last or out-of-range page has `next_offset: null`.

The reviewer checked the arithmetic: offsets are converted with
`usize::try_from`, the start is bounded by the actual length, and the page size
is bounded by the remaining length before adding the two. Empty and oversized
offsets therefore do not overflow or create invalid drain ranges. `limit` is
restricted to 1 through 10000. Invalid types, negative numbers and out-of-range
limits are rejected by the Runtime before cloud work, SSH connection or any
file operation. File actions other than `list` reject pagination arguments.

`include_script=false` omits only snippet bodies. The default is still `true`;
other inventory kinds retain their previous projection and secret filtering.

### Output budgets preserve command completion

`max_output_chars` defaults to the existing 200000 characters per stdout/stderr
stream and accepts 0 through 200000. Both the public Runtime and direct SSH
entry point validate it before connecting. Captures retain a bounded byte
prefix and truncate after decoding at a Rust `char` boundary, including when
SSH packets split UTF-8 sequences. A zero budget discards output bodies but
still reports discarded output with `truncated` and the short marker.

The SSH read loop remains unchanged: reducing the capture budget does not stop
reading the remote channel, so a writer can finish and deliver its exit status.
The reviewer inspected the new real-OpenSSH regression that writes more than
the receive window to each stream and then exits 23, but did not independently
run the OpenSSH fixture in this review.

### MCP compatibility is intentionally preserved

The protocol and CLI implementations are unchanged. Both JSON text and
`structuredContent` remain present. This follows the official MCP 2025-11-25
[structured-content compatibility recommendation](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#structured-content).
The standard recommends the serialized text representation for older clients;
it does not establish that every client inserts both copies into model context.
The new output controls reduce either representation without assuming a client
deduplication strategy.

The original CLI entry points and commands, sync TTLs, host-chain resolution,
trust policy, default output limits and streamed file-transfer behavior were
not changed by this patch. The existing `agent_forwarding` behavior is also
unchanged; reporting forwarding as enabled without transport support would not
be an output-only optimization.

## Independent validation performed

The reviewer ran these focused regressions directly, in addition to source
inspection:

```text
cargo test --locked --test mcp_integration optional_pagination_and_script_projection_preserve_default_results -- --exact
1 passed; 0 failed; 5 filtered out

cargo test --locked --test mcp_integration optional_key_diagnostics_are_explicit_and_legacy_text_matches_structured_data -- --exact
1 passed; 0 failed; 5 filtered out

git diff --check
passed
```

The first test covers filtered pagination, last/oversized-offset pages, unchanged
default results and optional snippet projection. The second exercises the MCP
wire response and confirms quiet defaults, explicit cached diagnostics and
equivalence of the legacy JSON text with the structured result.

No real Termius account, Google sign-in, live team vault or production host was
used for this independent review. It does not claim live cloud end-to-end
acceptance or repeat the main agent's complete build/release validation.
