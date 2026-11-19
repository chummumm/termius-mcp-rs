"""Release boundary regressions: validation, license completeness, and tampering."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from assemble_release import verify_archive, verify_platform
from collect_licenses import override_texts, packaged_texts, validate_license_declaration
from package_release import create_archive
from prepare_release import prepare
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


if __name__ == "__main__":
    unittest.main()
