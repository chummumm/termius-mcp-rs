# Independent compatibility review — Termius MCP Rust

> Maintainer scope note: this report records the initial reviewed baseline
> (`13fbe03`). Follow-up policy and transport changes are covered by
> [the Code Complete review](code-complete-review.md) and
> [the software-design review](software-design-review.md). The current
> connection and file-transfer contracts are documented in the README.

Date: 2026-11-19

Reviewer: a separate AI review agent that did not implement the Rust port.

Scope: compare the supplied Termius MCP 3.2.0 Python snapshot with the Rust port, focusing on actual cloud protocol messages, credential normalization, SRP and vault cryptography, optional key discovery, snapshot relationship behavior, and MCP result shape. This is an independent code review and local verification, not a third-party security certification or a live Termius acceptance test.

## Findings

### C1 — Inventory result is wrapped twice (medium; fixed and verified)

`inventory::list` returns the complete `{kind, count, items}` object. The first implementation of `Runtime::call_inner("inventory")` assumed it returned an array, computed `count` with `as_array()` (therefore zero), and placed the complete result inside a second `items` member. Every inventory kind consequently had an incorrect public result shape.

The reviewer reported the mismatch before publication. The root changed the dispatcher to return the helper's result directly and added `all_inventory_tools_have_flat_safe_envelopes` in `tests/mcp_integration.rs`. The reviewer checked the corrected dispatcher and independently reran the integration regression successfully. This is a wiring defect that the original module-level projection tests did not detect.

### C2 — SRP parser loses supported hexadecimal byte-buffer encodings (medium; fixed and independently retested)

The Python `botan_bigint_from_str` accepts ordinary hexadecimal strings, raw binary values, and Node Buffer/byte-array values containing ASCII hexadecimal text. The initial Rust `parse_integer` recognized hexadecimal text only when the JSON value was a string. A Buffer containing the same 2048-character valid hexadecimal server public value was instead interpreted as a 2048-byte integer and rejected for exceeding the 8192-bit group.

Independent reproduction is retained in `tests/compatibility_review.rs`. Before the fix, `cargo test --test compatibility_review` failed: the ordinary string positive control succeeded, while the ASCII-hex Node Buffer failed. The exact uploaded Python parser accepted the Buffer representation.

The implementation now preserves the source's distinction between direct text and bytes: it recognizes `0x`/`0X` and long all-hex byte text for Node Buffers/arrays, retains raw binary interpretation otherwise, and does not silently reinterpret arbitrary decoded base64 as hexadecimal. The independently written regression passed after the fix. The implementation author also added `srp_integer_encodings_match_python_buffer_and_base64_rules`, which passed in the review rerun.

Source references: Python `termius/cloud/client/srp_session.py::botan_bigint_from_str`; Rust `src/crypto.rs::parse_integer`.

### C3 — Optional key APIs prevent otherwise usable personal sync (medium; fixed and verified)

The Python `load_keyring` treats keyserver and team-key discovery as optional. Its callers can still decrypt personal records when these lookups are forbidden or temporarily unavailable. The initial Rust `pull` only tolerated 404/405/410 and aborted the whole sync for an optional `/v4/team/vault/keys/` 403 or transport error. This can prevent all personal inventory access for an account whose optional team-key endpoint is unavailable.

This is a confirmed code-path difference, with a conditional precondition; no claim is made that the live API currently returns 403 for any particular user's account. The correction should keep required settings/snapshot requests fatal, allow optional key-discovery failure with a safe generic warning, and continue to mark shared entities undecryptable when their authenticated key is missing. The warning and unreadable count should reach public results so users can see partial availability.

The implementer made that correction. The reviewer inspected `src/cloud.rs::optional_key_response` and `pull`, and `src/tools.rs::append_sync_metadata`. Required settings and snapshot requests remain fatal; optional key failures record generic warnings without remote error details. Status, sync, inventory, host reads, exec and files carry the unreadable count and applicable warnings. The author's `optional_key_failures_preserve_personal_reads_and_fail_shared_closed` regression passed in the independent rerun; it checks forbidden/transport failures, sanitized warnings, a readable personal record and an unreadable shared record with retained route identifiers.

Source reference: Python `termius/cloud/client/keyring.py::load_keyring`.

### C4 — Mixed legacy credential response fallback (low; fixed and verified)

The Python account manager falls back from null/empty `credentials` to the outer payload and falls back per field for token, salt and HMAC salt. The initial Rust normalizer used any present `credentials` value and did not fall back for an empty/missing nested token. A legacy/mixed object such as `credentials: {}` plus valid outer token/salts was therefore rejected although the source accepted it.

The normalizer now preserves the nonempty object/per-field fallback. The author's `mixed_legacy_credentials_use_nonempty_top_level_fallbacks` regression passed in the independent rerun and covers a null credentials value, an empty credentials object, and a mixed nested object with empty/null fields. This is an input-compatibility finding; no live frequency assertion is made.

Source references: Python `termius/account/managers.py::_b64_field` and account login normalization; Rust `src/cloud.rs::normalize_session`.

### C5 — Timezone-free cloud timestamps are treated as stale (low; fixed and independently retested)

The other independent reviewer identified that the first Rust TTL parser accepted numeric and RFC3339 timestamps only. The compatibility reviewer checked that Python `termius/sync.py::parse_last_synced` also accepts timezone-free ISO timestamps and explicitly treats them as UTC. If such a timestamp appeared in a successful sync response, the first Rust implementation would immediately regard the cache as stale and trigger repeated synchronization.

The root added UTC interpretation of ISO timestamps with `T` or space separators in `src/tools.rs::is_stale`. This reviewer added a separate regression in `tests/compatibility_review.rs` covering fresh timestamps in both forms and an old timestamp. This is a conditional input-parity issue; live server timestamp formats were not observed.

## Cryptographic verification

The reviewer loaded the **exact uploaded Python `srp_session.py`**, provided a minimal libsodium-backed KDF adapter, and fed it the deterministic exponent and salts used by the checked-in interoperability fixture. The following matched:

- RFC 5054 modulus bytes and group size.
- Client public value A.
- Client proof M1.
- Expected server proof M2.
- Acceptance of an ASCII-hex Node Buffer by the source parser.

The fixture generator also uses system libsodium for Argon2id, XSalsa20-Poly1305 secretbox and X25519/XSalsa20-Poly1305 box, and Python cryptography for RNCryptor. These provide independent primitive implementations. The SRP fixture is a reproducible compatibility vector, not evidence of a successful live server login.

Source-level comparison found matching desktop namespace, Engine.IO framing, initial/final request field names, OTP handling, `NOT_MIGRATED` fallback trigger, DeviceToken derivation, personal-key wrapping, team-key ownership lookup and full snapshot set names. The Rust implementation deliberately rejects bad SRP server proofs, whereas the Python snapshot warned and continued.

## Deliberate differences to document

- Separate local state directory and new encrypted file format; fresh login is required.
- Public inventory identifiers are cloud IDs, not generated Python cache IDs.
- SSH verification is strict by default; unknown keys are not automatically enrolled.
- Jump routes require enrolled Termius host keys at every hop and destination.
- SSO completion is bound to the start request and expires; permissive unbound legacy URL forms are not accepted.
- A raw 32-byte fallback for unauthenticated team-key wrapping is not retained.
- The generated direct SSH command disables agent forwarding.
- Device UUID is generated per login invocation in this version, so repeated logins/OTP retries can create additional device records.
- File storage is encrypted but a copied state file together with its local master-key file is decryptable; separate passphrase or OS keychain protection has a different threat model.

## Validation limits

No user credentials, live Termius login, real personal/team cloud vault, Google browser session, or desktop OS keychain was available to this reviewer. Changes to undocumented Termius cloud behavior can only be confirmed by a subsequent authorized live acceptance test. No production Rust files were edited by this reviewer.

## Remediation retest and disposition

The reviewer reran `cargo test --test compatibility_review --lib` after the implementation fixes: **44 library tests and the independently authored SRP Buffer regression passed**, with no ignored tests. The naive-UTC timestamp regression was then added and run separately: **one passed**. The reviewer also independently ran the flat-envelope Runtime integration regression: **one passed**. Formatting validation of the reviewer-authored regression file passed. The report's source comparisons and fixture validation use the uploaded Python snapshot, not undocumented assumptions about a currently running account.

All five compatibility findings above have been addressed. No unresolved blocking compatibility finding remains in the reviewed code paths. This conclusion is limited to source inspection and local reproducible tests; it does not certify an untested live Termius login, Google SSO or real team-vault workflow.

## Addendum — timestamp dependency change, 2026-11-19

After the release dependency audit, the root replaced direct `chrono` usage with `time` 0.3.55. The reviewer independently inspected the delta in `Cargo.toml`, the resolved lockfile, `src/tools.rs` and the timestamp-generating tests. Finite numeric values and RFC3339 timestamps retain their interpretation; timezone-free timestamps with `T` or space separators retain UTC interpretation. Invalid values and timestamps more than five minutes in the future remain stale. Locally generated sync timestamps use UTC RFC3339, with an epoch-seconds fallback if formatting fails. No new blocking finding was identified.

After the lockfile was resolved, the reviewer independently ran:

- `cargo test --locked --lib tools::tests::stale_dates_are_conservative`: **1 passed**.
- `cargo test --locked --test compatibility_review naive_cloud_timestamps_are_utc_as_in_python`: **1 passed**.
- `cargo test --locked --test mcp_integration`: **3 passed**.

The locked dependency graph still contains `chrono` transitively through `russh-sftp`; removing its direct use does not remove that transitive maintenance notice. The release's complete dependency-audit disposition is recorded separately by the root.

The reviewed source fingerprint after this dependency change is `9a77658f323437590f5bbc789d457ba371a520110f687e27ca6b02ead08ef6e0`. It covers 19 files in total: files under `src/` and `tests/`, plus `Cargo.toml` and `Cargo.lock`, using the path-NUL-content-NUL SHA-256 procedure documented in `docs/REVIEW.md`. Reports themselves are excluded. No production files were modified by this reviewer, and the live-account validation limits above remain unchanged.
