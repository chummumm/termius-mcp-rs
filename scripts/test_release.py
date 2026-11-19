"""Release boundary regressions: validation, license completeness, and tampering."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from assemble_release import verify_archive, verify_platform
from collect_licenses import override_texts, packaged_texts, validate_license_declaration
from package_release import create_archive
from prepare_release import prepare
import publish_release
from release_common import BINARIES, archive_name, sha256, validate_version


class ReleaseInputs(unittest.TestCase):
    def test_version_rejects_shell_and_path_injection(self):
        for version in ["0.1.1;echo injected", "0.1.1\nvalue=bad", "../0.1.1", "v0.1.1", "01.1.1", "0.1.1-beta"]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                validate_version(version)

    def test_non_main_release_is_rejected_before_output(self):
        with patch.dict(os.environ, {"GITHUB_REF": "refs/heads/unreviewed", "GITHUB_EVENT_NAME": "push"}), self.assertRaises(ValueError):
            prepare()

    def test_missing_and_unreviewed_licenses_fail(self):
        for declaration in [None, "LicenseRef-Unknown"]:
            with self.assertRaises(ValueError):
                validate_license_declaration({"name": "fixture", "version": "1.0.0", "license": declaration})
        self.assertEqual(validate_license_declaration({"name": "fixture", "license": "MIT/Apache-2.0"}), "MIT/Apache-2.0")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text("SPDX-License-Identifier: MIT\nSee LICENSE.\n", encoding="utf-8")
            package = {"name": "fixture", "version": "1.0.0", "license": "MIT", "license_file": None}
            self.assertEqual(packaged_texts(root, package), [])
            with self.assertRaises(ValueError):
                override_texts(root, package)
            full_license = (Path(__file__).parent / "license-overrides" / "delegate-0.13.5" / "LICENSE-MIT").read_text(encoding="utf-8")
            (root / "README.md").write_text("# Fixture project\n\n" + full_license, encoding="utf-8")
            self.assertEqual(packaged_texts(root, package), [root / "README.md"])

    def test_explicit_license_cannot_escape_crate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "crate"
            root.mkdir()
            (root.parent / "outside.txt").write_text("not this crate's license", encoding="utf-8")
            with self.assertRaises(ValueError):
                packaged_texts(root, {"name": "fixture", "license_file": "../outside.txt"})


class ArchiveValidation(unittest.TestCase):
    def test_archive_and_license_tampering_are_rejected(self):
        version, target, commit = "0.1.1", "x86_64-unknown-linux-gnu", "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            staging = output / f"termius-mcp-rs-{version}-{target}"
            staging.mkdir()
            for filename in (*BINARIES, "README.md", "README.zh-CN.md", "LICENSE", "NOTICE", "CHANGELOG.md"):
                (staging / filename).write_text("synthetic test fixture\n", encoding="utf-8")
            licenses = staging / "THIRD_PARTY_LICENSES"
            (licenses / "fixture-1.0.0").mkdir(parents=True)
            material = licenses / "fixture-1.0.0" / "LICENSE"
            material.write_text("synthetic license material\n", encoding="utf-8")
            (licenses / "README.md").write_text("fixture index\n", encoding="utf-8")
            index = {"target": target, "packages": [{"name": "fixture", "license": "MIT", "license_files": [{"path": "fixture-1.0.0/LICENSE", "sha256": sha256(material)}]}]}
            (licenses / "index.json").write_text(json.dumps(index), encoding="utf-8")
            build = {"version": version, "commit": commit, "target": target, "binaries": list(BINARIES), "cargo_lock_sha256": "b" * 64, "dependency_count": 1}
            (staging / "BUILD_INFO.json").write_text(json.dumps(build), encoding="utf-8")
            archive = output / archive_name(version, target)
            create_archive(staging, archive, 1700000000)
            build.update({"archive": archive.name, "sha256": sha256(archive), "size": archive.stat().st_size})
            (output / f"{target}.build.json").write_text(json.dumps(build), encoding="utf-8")
            self.assertEqual(verify_platform(output, version, commit, target)["commit"], commit)
            with self.assertRaises(ValueError):
                verify_platform(output, version, "c" * 40, target)
            with archive.open("ab") as stream:
                stream.write(b"tampered")
            with self.assertRaises(ValueError):
                verify_platform(output, version, commit, target)
            material.write_text("changed license without changing its index hash\n", encoding="utf-8")
            create_archive(staging, archive, 1700000000)
            with self.assertRaises(ValueError):
                verify_archive(archive, build)


class DraftReleaseRecovery(unittest.TestCase):
    repository = "owner/repository"
    tag = "v0.1.1"
    commit = "a" * 40
    marker = f"<!-- termius-mcp-rs-release:{commit}:0.1.1 -->"
    release_id = 451143230

    def draft(self, **changes):
        return {"id": self.release_id, "tag_name": self.tag, "draft": True,
                "body": self.marker, "assets": [], **changes}

    def api_response(self, command, pages, detail):
        listing = f"repos/{self.repository}/releases?per_page=100"
        if command == ["gh", "api", "--paginate", "--slurp", listing]:
            return subprocess.CompletedProcess(command, 0, json.dumps(pages), "")
        if command == ["gh", "api", f"repos/{self.repository}/releases/{self.release_id}"]:
            if detail is None:
                return subprocess.CompletedProcess(command, 1, "", "HTTP 404: Not Found")
            return subprocess.CompletedProcess(command, 0, json.dumps(detail), "")
        if command == ["gh", "api", f"repos/{self.repository}/releases/tags/{self.tag}"]:
            # GitHub's tag lookup is for published releases, even when the
            # authenticated listing and ID endpoint can see this draft.
            return subprocess.CompletedProcess(command, 1, "", "HTTP 404: Not Found")
        self.fail(f"Unexpected GitHub command in contract fixture: {command}")

    def test_tag_404_still_finds_draft_on_later_page_and_refreshes_by_id(self):
        first_page = [self.draft(id=index + 1, tag_name=f"v0.0.{index}") for index in range(100)]
        listed = self.draft()
        refreshed = self.draft(assets=[{"name": "archive.zip", "size": 42}])
        with patch.object(publish_release.subprocess, "run", side_effect=lambda command, **kwargs:
                          self.api_response(command, [first_page, [listed]], refreshed)) as process:
            self.assertIsNone(publish_release.read_api(f"repos/{self.repository}/releases/tags/{self.tag}"))
            self.assertEqual(publish_release.existing_release(self.repository, self.tag, self.marker), refreshed)
        self.assertEqual(process.call_count, 3)

    def test_interrupted_empty_draft_resumes_upload_and_checksum_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            asset = Path(temporary) / "archive.zip"
            asset.write_bytes(b"verified build artifact")
            writes = []

            def command_result(command, **kwargs):
                if command[:3] == ["gh", "release", "upload"]:
                    writes.append(command)
                    self.assertEqual(command, ["gh", "release", "upload", self.tag, str(asset), "--repo", self.repository])
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[:3] == ["gh", "release", "download"]:
                    destination = Path(command[command.index("--dir") + 1])
                    (destination / asset.name).write_bytes(asset.read_bytes())
                    return subprocess.CompletedProcess(command, 0, "", "")
                return self.api_response(command, [[self.draft()]], self.draft())

            with patch.object(publish_release.subprocess, "run", side_effect=command_result):
                publish_release.upload_missing(self.repository, self.tag, [asset], self.marker)
            self.assertEqual(len(writes), 1)

    def test_public_unrelated_retagged_or_missing_release_is_never_written(self):
        cases = [
            (self.draft(draft=False), self.draft(draft=False)),
            (self.draft(), self.draft(draft=False)),
            (self.draft(body="someone else's draft"), self.draft(body="someone else's draft")),
            (self.draft(), self.draft(body="changed ownership marker")),
            (self.draft(), self.draft(tag_name="v9.9.9")),
            (self.draft(), self.draft(id=self.release_id + 1)),
            (self.draft(), None),
        ]
        for listed, detail in cases:
            with self.subTest(listed=listed, detail=detail), patch.object(
                    publish_release.subprocess, "run", side_effect=lambda command, **kwargs:
                    self.api_response(command, [[listed]], detail)) as process:
                with self.assertRaises(ValueError):
                    publish_release.upload_missing(self.repository, self.tag, [], self.marker)
                self.assertTrue(all(call.args[0][:2] == ["gh", "api"] for call in process.call_args_list))

    def test_duplicate_matching_releases_are_rejected(self):
        with patch.object(publish_release.subprocess, "run", side_effect=lambda command, **kwargs:
                          self.api_response(command, [[self.draft()], [self.draft(id=123)]], self.draft())) as process:
            with self.assertRaisesRegex(ValueError, "Multiple releases"):
                publish_release.existing_release(self.repository, self.tag, self.marker)
        self.assertEqual(process.call_count, 1)

    def test_wrong_git_tag_commit_stops_recovery_before_any_write(self):
        def command_result(command, **kwargs):
            if command == ["gh", "api", f"repos/{self.repository}/git/ref/tags/{self.tag}"]:
                return subprocess.CompletedProcess(command, 0, json.dumps({"object": {"type": "commit", "sha": "b" * 40}}), "")
            return self.api_response(command, [[self.draft()]], self.draft())

        environment = {"GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
                       "GH_TOKEN": "synthetic-test-token", "GITHUB_REPOSITORY": self.repository,
                       "RELEASE_OUTPUT": "dist/release-assets"}
        with patch.dict(os.environ, environment), patch.object(publish_release, "requested_version", return_value="0.1.1"), \
                patch.object(publish_release, "source_commit", return_value=self.commit), \
                patch.object(publish_release, "assemble", return_value={"platforms": []}), \
                patch.object(publish_release.subprocess, "run", side_effect=command_result) as process:
            with self.assertRaisesRegex(ValueError, "Existing tag does not point"):
                publish_release.main()
        self.assertTrue(all(call.args[0][:2] == ["gh", "api"] for call in process.call_args_list))


if __name__ == "__main__":
    unittest.main()
