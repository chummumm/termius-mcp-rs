# Independent release-pipeline review — v0.1.1

Date: 2026-11-19

Reviewer: a separate AI reviewer who did not implement the release workflow or scripts.

## Scope and method

I reviewed `.github/workflows/release.yml`, `.github/release.json`, `.gitattributes`, all release Python scripts, the license-override index and materials, the Cargo binary declarations, and `docs/RELEASING.md`. I applied the user-supplied Code Complete and A Philosophy of Software Design skills to boundary validation, consistent release invariants, staging/error behavior, and the separation between building packages and publishing them.

This was a read-only production review. I wrote this report and an isolated mock test harness; I did not modify production code, create a commit or tag, call GitHub mutation APIs, or publish a release. I did not repeat the complete Rust test suite. The root and implementation author own the complete build and live Actions results.

**Initial local-review conclusion:** no publication blocker was found by the script, archive, and mocked publication checks. That conclusion missed workflow-context and draft-API errors exposed by live runs; the corrections and verification are recorded below. Local mock results alone did not establish that the complete release workflow would succeed. Publication remains conditional on verified platform artifacts and successful live publication steps.

## Release invariants checked

| Boundary | Reviewed behavior |
| --- | --- |
| User-requested commands | Cargo declares `termius` and `termius-mcp`; the packager uses this exact two-name allowlist. `termius-mcp-rs` remains the repository/archive stem, not an executable alias. |
| Version input | Stable `MAJOR.MINOR.PATCH` validation, exact Cargo version agreement, main-branch trigger restriction. Inputs are passed as environment values and subprocess argument lists, not interpolated into shell programs. |
| Source identity | The prepare job captures the full triggering commit. Every later checkout uses it; scripts compare it with `git rev-parse HEAD`; an existing tag must point directly to that same commit. Later changes to `main` do not change the running release's source. |
| Platforms | Native Linux x86_64 GNU on Ubuntu 22.04, Windows x86_64 MSVC, and macOS arm64. Packaging verifies the actual compiler host against the target; smoke tests verify the executable's MCP-reported package version. |
| Build gate | The publish job depends on the prepare job and the complete build matrix. No `always()` or `continue-on-error` bypasses a failed platform. All three platform records and archives must also be present during assembly. |
| Credentials | Build jobs have repository read permission and do not persist checkout credentials. Only the final publication step receives the ephemeral GitHub token through `GH_TOKEN`. It is not placed in command arguments or printed. Smoke tests use temporary state and synthetic secrets and remove the vault-password environment value. |
| Archive contents | Explicit binary/document allowlists include the project license, notice, changelog, build metadata, and dependency license tree. Assembly rejects duplicate/unsafe paths, links/non-files, missing required files, the removed executable alias, and inconsistent source/version/target metadata. |
| Integrity | Each platform archive has a size and SHA-256 check; embedded build information must agree with its manifest. All platform lockfile hashes must agree. Recorded dependency license material is checked against its own SHA-256. |
| Public assets | Three archives, `SHA256SUMS`, and `release-manifest.json` are uploaded to a draft. Every asset is downloaded again and hashed before the draft is made public. |

`.gitattributes` specifies `* text=auto eol=lf`. I checked this final root change: it prevents Windows checkout line-ending conversion from changing the committed Cargo lockfile or license-override bytes and breaking cross-platform hash agreement.

## Interrupted runs and existing releases

`publish_release.py` does not force-move tags, delete existing releases, use upload `--clobber`, or replace an already public release. A draft can be resumed only when its body contains the exact commit/version marker. An existing tag with another SHA, an unrelated draft, or a public release stops the operation.

For a matching draft, only missing assets are uploaded. Existing assets with a different size are rejected immediately; equal-size assets are still downloaded and hashed, so equal length cannot hide different content. Unexpected assets and incomplete downloaded sets are rejected. An upload or download-verification failure leaves the release draft rather than reaching the public transition.

The workflow serializes release jobs through one concurrency group. Temporary Actions build artifacts may be replaced during a rerun; that setting does not overwrite GitHub Release attachments. The public transition occurs only after successful verification. A failure after tag/draft creation can intentionally leave that tag and draft for a checked retry; the scripts do not try to erase remote state automatically.

## License completeness and the resolved package blocker

The collector uses Cargo's target-filtered normal/build dependency closure, excluding dev-only paths. It copies actual license/notice texts, checks explicit license-file paths, accepts a README only when it contains a grant and disclaimer, and fails on missing material or unreviewed source/license declarations. Exact-version overrides are tied to the source commit in the published crate's `.cargo_vcs_info.json` and to recorded file hashes. Only the recognized crates.io registry identifiers receive crates.io source links.

During this review, the implementation author's Windows scan stopped on omitted upstream license files for `clipboard-win` and `pageant`. The author added exact-commit copies instead of bypassing the failure. I then independently checked **all seven override files**: every local SHA-256 matched `sources.json`, and every source commit matched the corresponding published crate's recorded VCS commit. The final collector's stricter README-license checks and registry restriction were also inspected.

The implementation author reports completed target-license scans of **345 Linux**, **322 Windows**, and **304 macOS** dependency records. These counts are identified as author-run evidence, not executions by this reviewer. No missing-material blocker remained after those additions. The root is separately checking the real local release archive before the workflow is run.

## Independent executions

| Execution by this reviewer | Result |
| --- | --- |
| Repository release-script unit suite, including the final collector changes | 5 tests passed |
| Independent isolated publication-state tests with every GitHub operation mocked | 5 tests passed |
| All seven license overrides: file hashes and crate-recorded source commits | Matched |

The independent mock tests verified:

- Public releases and unrelated drafts are refused.
- A mismatched existing tag causes failure before any remote-write command would run.
- An existing asset with the right length but different bytes is rejected.
- A draft retry uploads only missing assets and does not use `--clobber`.
- Tag/draft creation and asset upload precede download verification, and a simulated checksum mismatch prevents the command that makes the draft public.

These tests did not contact GitHub. Their synthetic success message was produced by the mocked code path, not by an actual publication.

## Remaining execution limits

At the initial review, the checked-in workflow and mocked publication tests did not establish that GitHub-hosted Windows/macOS builds had run successfully. The actual Actions run is the release gate; the later native-build evidence is recorded under RR2. I did not independently repeat the action-pin provenance checks already performed by the root, perform a legal certification, or use a live Termius account. Windows Authenticode signing, macOS Developer ID signing/notarization, and acceptance on every OS version are not claimed by the release documentation.

The exact-commit guarantee assumes the workflow's fresh checkout and reviewed build scripts; a manually modified local checkout is not equivalent evidence of a clean CI build. Hashes provide integrity checks and identify the downloaded bytes, not a publisher signature.

The script-level checks support the requested publication order: build and test the exact source on all three platforms, verify complete packages, create a matching tag and draft, upload and re-download/hash all assets, then publish. Workflow acceptance is a separate boundary; the first live attempt exposed the missed defect below.

## Correction after the first live workflow attempt

### RR1 — Release-blocking workflow context error; corrected and rechecked

The root observed the first release workflow fail before creating any jobs (`jobs=[]`), while ordinary Rust CI was running. The release YAML used `${{ runner.temp }}/release-assets` in both `jobs.build.env.RELEASE_OUTPUT` and `jobs.publish.env.RELEASE_OUTPUT`.

I independently checked GitHub's official [context-availability reference](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability). Job-level `env` permits `github`, `needs`, `strategy`, `matrix`, `vars`, `secrets`, and `inputs`; it does **not** permit `runner`. The two expressions were therefore invalid at their workflow locations. Step-level `if`, `env`, and `with` permit `runner`, so the step conditions using `runner.os` were valid. This is consistent with failure before any runner job begins.

**Initial review omission:** the first review validated Python behavior, archive boundaries, publication sequencing, and ordinary YAML structure, but did not validate GitHub's location-specific expression contexts. Those checks could not establish workflow acceptance. The earlier broad no-blocker conclusion was insufficient; this section explicitly corrects it.

The author replaced both job environment values with the literal workspace-relative path `dist/release-assets`, and changed the upload and download paths to the same directory (`dist/release-assets/*` for upload). I read the final four-line diff and verified that both script output locations and both artifact action paths agree. The Python entry points already resolve `RELEASE_OUTPUT` from the workspace; no publication script or credential policy changed.

I also enumerated the complete expression inventory against the official per-key context rules. Before the fix, the targeted check identified exactly the two invalid job-level uses among 21 expressions. After the fix, all 17 remaining expressions used allowed contexts. Job outputs using `steps`, matrix names/runners, dependency outputs using `needs`, checkout references, dispatch input, the step token, and step `runner.os` conditions were checked. The `needs: [prepare, build]` publication gate remains intact.

No `actionlint` executable was available; this verification used the official reference plus a targeted read-only context/path check, not a claim of a full third-party workflow-linter run. The newly observed workflow-context blocker is corrected in the reviewed files. The next real Actions run must still confirm workflow acceptance and complete all native build/package gates before release publication.

### RR2 — Draft discovery used a published-release API; corrected and independently retested

The root observed that [release run 44498369786](https://github.com/chummumm/termius-mcp-rs/actions/runs/44498369786) completed native tests, builds, and packages for all three platforms. Its publication job created `v0.1.1` at commit `6786bb9bc7525705a1f0e9e446412450e00b5370` and draft release ID `451143230`, then stopped before uploading assets. The root verified that the draft had the matching commit/version marker and an empty asset list. These live-run observations are attributed to the root; this reviewer did not mutate the release.

The previous `existing_release` called the REST release-by-tag endpoint. GitHub's official [release API reference](https://docs.github.com/en/rest/releases/releases#get-a-release-by-tag-name) documents that endpoint for published releases. Its [list-releases endpoint](https://docs.github.com/en/rest/releases/releases#list-releases) includes drafts for callers with push access. Consequently, a by-tag 404 did not establish that the just-created draft was absent.

**Mock-model omission:** the earlier tests either supplied a draft directly from the mocked by-tag response or bypassed draft discovery when testing upload ordering. That modeled a service behavior the chosen endpoint did not provide. The tests exercised overwrite/integrity policy under that incorrect assumption; they did not validate GitHub's actual draft-discovery contract. This was a real missed publication blocker, not a build or archive failure.

The corrected helper enumerates the authenticated release listing using pagination, requires exactly one matching tag, and refreshes it by numeric release ID. Both the listed and refreshed objects must retain the expected ID, tag, draft state, and commit/version marker. A public, unrelated, retagged, disappeared, or duplicate match stops publication. The by-tag endpoint is retained only for the check after the release becomes public.

I read the complete fix and independently ran the updated repository release suite: **10 tests passed**, including the five new draft-recovery contract tests. Their raw subprocess mock models by-tag 404 while the second listing page contains the draft, refreshes assets by ID, exercises recovery from an empty draft, and verifies that changed identities, public/unrelated releases, duplicate tags, and a wrong Git tag commit cannot cause a write.

I also inspected the official [GitHub CLI release-fetch implementation](https://github.com/cli/cli/blob/trunk/pkg/cmd/release/shared/fetch.go). Its shared lookup distinguishes published and draft lookup and fetches a discovered draft by numeric ID. Retaining `gh release upload`, `download`, and `edit` therefore does not repeat this script's published-only REST lookup assumption. The recovery path must still be confirmed by the real workflow; mocked success is not reported as a completed upload.

#### Recovery workflow and source separation

I independently read `resume-release.yml`, `release-resume.json`, `prepare_release_resume.py`, the `release_common.py` source-directory change, and the consuming assembly/publication entry points. The recovery manifest fixes version `0.1.1`, source commit `6786bb9bc7525705a1f0e9e446412450e00b5370`, and original run `44498369786`. The first checkout supplies the corrected automation at the triggering commit; the separate `release-source` checkout supplies the original source. `RELEASE_SOURCE_DIR` selects that source for Cargo version/binary-name checks, `git rev-parse HEAD`, and release-note content. The corrected publication code runs from the automation checkout. No recovery step rebuilds binaries or moves the existing tag.

The preparation gate checks the current automation commit and main-branch trigger, then checks the original run's repository, source SHA, branch, event, workflow path, completed state, and attempt. It requires the validation job and every native target job to have completed successfully, rejects incomplete or duplicate job records, verifies the existing tag's exact commit, and rereads the run to reject an attempt change. The overall original run may have failed because publication failed; successful native jobs remain mandatory. Preparation uses only GET requests and a read-only token. The root separately exercised these functions against the actual run/job/tag API snapshot and confirmed that a failed native build is rejected; the preparation author reports 29 passing isolated cases.

The publication job depends on preparation and checks out its validated original SHA. The cross-run artifact download supplies `github-token`, the exact source run ID, and `actions: read`, as required by the official [download-artifact inputs](https://github.com/actions/download-artifact/blob/v8.0.2/action.yml). Its destination agrees with `RELEASE_OUTPUT`, digest mismatches fail, and the existing archive/source/license checks run again before upload. The normal and recovery workflows share the same non-cancelling concurrency group. The publisher rechecks the existing tag and matching draft, uploads only missing assets, and downloads and hashes the complete asset set before making the draft public.

Independent final checks passed: all **12 recovery-workflow expressions** use contexts allowed at their locations; source/artifact paths, permissions, dependencies, and concurrency match the reviewed contracts; the **10 release-script tests** pass; and a real detached original-source checkout passes source-directory selection, exact version/SHA checks, and rejection of an incorrect SHA. The earlier **17-expression** result applies to the normal release workflow, not this separate recovery workflow.

**Scoped recovery conclusion:** no further blocking defect was found in these corrected files. This conclusion permits the real recovery attempt; it does not claim that it has already uploaded or published anything. The review made no remote writes. Confirmation of the public release and all five downloaded assets remains a live execution gate.
