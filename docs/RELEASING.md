# Building and publishing releases

The release workflow builds a single source commit for three native targets. It publishes the original `termius` and `termius-mcp` executables. The repository and archive stem remain `termius-mcp-rs`; there is no executable with that name.

## Request a release

First update `Cargo.toml`, `Cargo.lock`, the matching `CHANGELOG.md` section, and any changed documentation. Review and test that complete change before pushing it.

Two explicit triggers are available:

1. Change `.github/release.json` to `{"version":"0.1.3"}` for the desired version and push the reviewed change to `main`. The workflow's push filter matches only this file, so ordinary source or documentation pushes do not publish a release.
2. Run **Release binaries** manually on `main`, providing the version without a `v` prefix. For example: `gh workflow run release.yml --ref main -f version=0.1.3`.

The version must be a stable `MAJOR.MINOR.PATCH` value exactly equal to `Cargo.toml`. The workflow captures the triggering commit SHA and uses it for every checkout and the resulting tag. Later changes to `main` cannot change an already running build. Version input is passed through environment variables and strict validation, never interpolated into a shell program.

## Build matrix

| Platform | Runner | Rust target | Archive |
| --- | --- | --- | --- |
| Linux x86_64 | `ubuntu-22.04` | `x86_64-unknown-linux-gnu` | `.tar.gz` |
| Windows x86_64 | `windows-2025` | `x86_64-pc-windows-msvc` | `.zip` |
| macOS Apple Silicon | `macos-15` | `aarch64-apple-darwin` | `.tar.gz` |

These runner labels and architectures were checked against [GitHub's official hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) on 2026-11-19. Linux uses the older supported Ubuntu 22.04 image to avoid raising the GNU libc baseline unnecessarily. The packages are built and smoke-tested on the listed environments; other Linux distributions and OS versions are not claimed as validated. Windows uses the MSVC toolchain and may require the Microsoft Visual C++ runtime. macOS packages are not Developer ID signed or notarized, and Windows packages are not Authenticode signed.

The workflow pins Rust `1.100.0`, uses `Cargo.lock` with `--locked`, and checks that the actual `rustc -vV` host equals the matrix target before packaging. Builds are native, not cross compiled. Python 3.13 is used only for CI/release maintenance scripts; end users need no Python installation.

Each platform runs formatting, Clippy with warnings denied, all ordinary Rust tests, a release build of both binaries, and credential-free CLI/MCP smoke tests. The Linux job also runs the ignored integration tests against a real local OpenSSH server. Smoke tests isolate state with `TERMIUS_DATA_DIR`, force the file backend, check `--help` and the exact signed-out status, then exercise the MCP initialize/tool-catalog/ping exchange. They do not call a nonexistent `--version` option or use a real Termius account.

## Archive contents and license collection

Each archive contains:

- `termius` and `termius-mcp` (`.exe` on Windows).
- `README.md`, `README.zh-CN.md`, `CHANGELOG.md`, `LICENSE`, and `NOTICE`.
- `BUILD_INFO.json`, including version, commit, target, compiler, Cargo lockfile hash, and dependency count.
- `THIRD_PARTY_LICENSES/`, with actual license/copyright/notice texts and an index of package versions, declared licenses, file hashes, and exact source-archive URLs.

The collector follows Cargo's target-filtered normal/build dependency graph and excludes dependencies reachable only through development edges. It scans license, licence, copying, copyright, and notice filenames recursively, respects `license-file`, and accepts a README only if it contains an actual license grant. A license badge, SPDX name, or link alone does not replace the text.

A few published crate archives omit their workspace-level license files. `scripts/license-overrides/` contains the actual upstream files at each crate's recorded `.cargo_vcs_info.json` commit. `sources.json` records package/version, exact commit, URL, and SHA-256. These are checked before copying. Missing or unknown materials, unfamiliar SPDX identifiers, mismatched overrides, and unreviewed non-registry dependencies fail the package step. Add a reviewed, version-specific source when updating such a dependency; do not add a generic template fallback.

The published packages use unmodified upstream crates. Their index links to the complete source archives for the exact versions. The inclusion of build-time dependency notices is conservative and can exceed the set of code linked into a particular binary.

## Publication gate and permissions

All build jobs have `contents: read`, and checkout credentials are not persisted. Only the final publish job has `contents: write`. Its publication step passes the short-lived `${{ github.token }}` through `GH_TOKEN`; tokens never appear in command-line arguments or log messages. No personal access token is required.

The publish job starts only when all three matrix jobs succeed. It downloads artifacts from that workflow run with digest verification enabled, checks their hashes and source/target/version metadata, inspects archive members without extracting them, and verifies every recorded third-party license file. It then creates `SHA256SUMS`, `release-manifest.json`, and release notes from `CHANGELOG.md`.

Only after those checks does `gh` create a lightweight `vVERSION` tag at the exact source SHA and a draft GitHub Release. The script uploads all five assets (three platform archives, the checksums file, and the combined manifest), downloads them again, and checks their hashes before publishing the draft. Tag/release behavior follows the [GitHub CLI release-create](https://cli.github.com/manual/gh_release_create) and [release-edit](https://cli.github.com/manual/gh_release_edit) interfaces.

### Retries

A failed platform build creates no release tag. Re-run the failed jobs in the original workflow run after resolving infrastructure problems; temporary artifacts have stable per-target names so successful jobs can be reused. All builds still refer to the original source commit.

If publication stops after making a draft, rerun the publish job in that same run. It resumes only a draft bearing this exact commit/version marker, accepts an existing tag only when it directly identifies that commit, uploads missing assets without replacing existing bytes, and verifies downloaded assets before publication. A different existing tag, unrelated draft, mismatched asset, or already public release causes failure. The workflow does not move tags or overwrite published releases. A source-code fix should use a new reviewed source commit and release version.

When the publishing automation itself needs a correction after all three builds
have succeeded, **Resume verified release** reuses those completed build outputs.
Set `.github/release-resume.json` to the original version, source commit and
source workflow run ID, review the automation fix, and push that manifest on
`main` (or run the recovery workflow manually). Preparation verifies the original
run's repository, workflow, main branch, source SHA, completed attempt, successful
version-validation and three native-build jobs, and the existing tag's commit.

The recovery job checks out publishing automation from the new triggering commit
and the original source into a separate `release-source` directory.
`RELEASE_SOURCE_DIR` directs version, lockfile, changelog and Git identity checks
to that original checkout. It downloads artifacts from the verified source run
using `actions: read`, then applies the same archive, license, draft-identity and
upload/download hash checks. The release tag and binary source commit stay fixed;
only the publishing implementation changes. This path does not run a new build
or claim that a newer automation commit produced the existing binaries.

Temporary Actions artifacts expire after 14 days. Published GitHub Release attachments are separate. SHA-256 provides download-integrity checking; it is not a publisher signature or a notarization claim.

## Pinned Actions

Every action reference is a verified full commit SHA. The pins below were checked against the respective upstream repository on 2026-11-19.

| Action | Pinned commit | Verification |
| --- | --- | --- |
| `actions/checkout` | `d23441a48e516b6c34aea4fa41551a30e30af803` | [commit](https://github.com/actions/checkout/commit/d23441a48e516b6c34aea4fa41551a30e30af803) |
| `actions/setup-python` | `ece7cb06caefa5fff74198d8649806c4678c61a1` | [v6 ref](https://api.github.com/repos/actions/setup-python/git/ref/tags/v6) |
| `dtolnay/rust-toolchain` | `39008827e6b4319a349e9a42dfc90579dd25f1ca` | [commit](https://github.com/dtolnay/rust-toolchain/commit/39008827e6b4319a349e9a42dfc90579dd25f1ca) |
| `actions/upload-artifact` v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | [tag ref](https://api.github.com/repos/actions/upload-artifact/git/ref/tags/v7.0.2) |
| `actions/download-artifact` v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` | [tag ref](https://api.github.com/repos/actions/download-artifact/git/ref/tags/v8.0.2) |

## Local package check

On one of the supported native platforms, build and test first:

```sh
cargo test --all-targets --locked
cargo build --release --locked --bins
```

Set `RELEASE_VERSION` to the Cargo version, `RELEASE_COMMIT` to the full current `git rev-parse HEAD`, `RELEASE_TARGET` to the native target from the table, and `RELEASE_OUTPUT` to a new temporary output directory. Then run:

```sh
python scripts/release_smoke.py
python scripts/package_release.py
```

The packaging script selects binaries by an explicit two-name allowlist, so stale files in `target/release` cannot add the removed Rust-only command. Local packaging does not contact GitHub or publish anything. `publish_release.py` additionally requires the workflow context and token and is intended only for the final CI job.
