# Security

## Trust boundary

This is a **local stdio MCP server** for an operator's own Termius account and
authorized SSH hosts. It is not an authenticated multi-user service. Do not
expose its stdin/stdout through an unauthenticated HTTP bridge.

An authorized MCP client can request arbitrary commands and remote file changes,
and `files get/put` can read/write paths accessible to the server process.
`exec` and `files` are marked destructive; client-side user authorization is
still essential. Tool annotations are hints, not a permission system.

Cloud/SSH responses are untrusted input. This implementation limits input and
output sizes, rejects ambiguous/missing routes and credentials, and authenticates
ciphertexts. SSH defaults to compatibility mode when `strict_host_key_check` is
unspecified: new or changed server keys are accepted without identity verification.
This mode cannot detect a server impersonator and can expose credentials or data
to an active intermediary. Explicit host/group `strict_host_key_check=true`
enables verification for that endpoint, including within jump chains. Tool results
report configured verification modes; they are not evidence that a handshake
completed. Shared-vault failures
never authorize a fallback to direct SSH. A compromised remote host can still
return malicious instructions in command output or file content: MCP clients
must treat these as data.

SFTP `get`/`put` stream without an application-imposed total-size cap; operation
deadlines and cancellation remain active. Downloads consume local disk space and
replace the destination only after completion. Inline `read`/`write`, directory
enumeration and recursive removal retain their documented bounds.

Passwords/private keys are excluded from host and identity metadata. Requested
command output, file content and snippet scripts may themselves contain secrets;
those results are intentionally returned to the requesting client. Review the
requested command or file before sharing its contents.

## Local state

Prefer an OS keychain or `TERMIUS_SECRETS_KEY` when a copied directory must not
be sufficient to decrypt the vault. In headless fallback, possession of both
`state` and `state.key` permits decryption. The same OS user can usually access
the process's memory and keychain. Rust reduces memory-safety risks, but this
project does not guarantee complete memory erasure of all JSON/string copies.

Unix permissions, symlink/hardlink rejection, authenticated metadata, atomic
replacement and revision checks protect normal local operation. These are not
a defense against a fully compromised account, privileged malware or backup
rollback by an attacker possessing the state keys. Windows deployments must
use a private user directory with appropriate ACLs.

## Review and reporting

The initial release received independent AI code review and concrete regression
tests. [docs/REVIEW.md](docs/REVIEW.md) records findings, fixes and validation
limits. This is not an external security certification or a vendor audit.

Report a suspected vulnerability to the repository owner using GitHub's private
vulnerability reporting when available. If that feature is unavailable, open a
minimal issue asking for a private contact; do not post passwords, callback
URLs, DeviceTokens, real vaults, private keys or an exploitable production setup.

No live account credentials are included in tests. Cryptographic keys under
`tests/fixtures` are deterministic public test data only.
