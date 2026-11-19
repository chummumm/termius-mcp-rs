# Changelog

## 0.1.1

### Changed

- Restore the Python 3.2.0 command names: `termius` and `termius-mcp`. Both start the same native Rust implementation.
- Preserve the original terminal commands and option surface, including the interactive email/Google login flow, OTP retry, signed-out status, and logout behavior. Invoking either executable without a subcommand starts the stdio MCP server.
- Remove the earlier Rust-only executable alias and CLI options. `TERMIUS_DATA_DIR` selects an isolated local state directory.
- Keep the MCP tool names and native SSH/SFTP implementation from the initial Rust port.

### Distribution

- Build and test native Linux x86_64, Windows x86_64, and macOS Apple Silicon binaries in GitHub Actions.
- Package the two original commands, English and Chinese documentation, project license/notices, exact dependency license texts, and build metadata.
- Publish archives only after all platform jobs succeed; include `SHA256SUMS` and a release manifest recording the exact source commit and target/compiler details.

## 0.1.0

- Initial BSD-licensed Rust source port of the supplied Termius MCP 3.2.0 snapshot.
- Add cloud/SRP and vault cryptography, the ten MCP tools, encrypted local storage, SSH jump chains, and SFTP operations.
- Add independent security, compatibility, construction, and design reviews with regression tests.
