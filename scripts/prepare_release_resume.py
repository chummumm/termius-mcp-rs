"""Authorize reuse of one completed, tested build without rebuilding or moving tags.

The recovery automation runs from the current main commit. Its manifest identifies
the original source and Actions run; the publication job separately checks out that
source and verifies the existing archive contracts before uploading anything.
This preparation script only performs GET requests with a read-only job token.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

from release_common import COMMIT_PATTERN, ROOT, TARGETS, validate_commit, validate_version


SOURCE_WORKFLOW = ".github/workflows/release.yml"
REQUIRED_JOBS = {"Validate release request", *(f"Build {target}" for target in TARGETS)}
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Release recovery JSON contains a duplicate key")
        result[key] = value
    return result


def positive_integer(value: object, label: str) -> int:
    # bool is a subclass of int; it is never a valid GitHub identifier.
    if type(value) is not int or not 0 < value <= 2**63 - 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def load_manifest(path: Path) -> tuple[str, str, int]:
    manifest = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(manifest, dict) or set(manifest) != {"version", "source_commit", "source_run_id"}:
        raise ValueError("Release recovery manifest must contain only version, source_commit, and source_run_id")
    if not isinstance(manifest["version"], str):
        raise ValueError("Release recovery version must be a string")
    version = validate_version(manifest["version"])
    commit = manifest["source_commit"]
    if not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit):
        raise ValueError("Release recovery requires a full lowercase source commit SHA")
    run_id = positive_integer(manifest["source_run_id"], "Source run ID")
    return version, commit, run_id


def read_api(endpoint: str, *, paginate: bool = False) -> object:
    arguments = ["gh", "api", "--hostname", "github.com", "--method", "GET",
                 "-H", "Accept: application/vnd.github+json",
                 "-H", "X-GitHub-Api-Version: 2022-11-28"]
    if paginate:
        arguments.extend(["--paginate", "--slurp"])
    arguments.append(endpoint)
    result = subprocess.run(arguments, text=True, encoding="utf-8",
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        # Tokens and potentially sensitive response bodies never enter the log.
        raise RuntimeError("Could not read the source release run or tag from GitHub")
    try:
        return json.loads(result.stdout, object_pairs_hook=unique_object)
    except (ValueError, TypeError) as error:
        raise ValueError("GitHub returned invalid release recovery metadata") from error


def verify_run(run: object, repository: str, commit: str, run_id: int) -> int:
    if not isinstance(run, dict) or type(run.get("id")) is not int or run["id"] != run_id:
        raise ValueError("Source workflow run identity does not match the recovery manifest")
    for field in ("repository", "head_repository"):
        if not isinstance(run.get(field), dict) or run[field].get("full_name") != repository:
            raise ValueError("Source workflow run must belong to this same repository")
    if run.get("head_sha") != commit or run.get("head_branch") != "main":
        raise ValueError("Source workflow run must build the exact main-branch release commit")
    if run.get("event") not in {"push", "workflow_dispatch"}:
        raise ValueError("Source workflow run has an unsupported trigger")
    if run.get("path") != SOURCE_WORKFLOW or run.get("status") != "completed":
        raise ValueError("Source release workflow must be completed before recovery")
    # Overall conclusion may be failure because only publication failed. The
    # individual validation and all native build jobs are checked below.
    return positive_integer(run.get("run_attempt"), "Source run attempt")


def verify_jobs(pages: object, commit: str, run_id: int) -> None:
    if not isinstance(pages, list) or not pages:
        raise ValueError("Source release job listing is incomplete")
    jobs = []
    totals = set()
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("jobs"), list):
            raise ValueError("Unexpected source release job listing")
        totals.add(positive_integer(page.get("total_count"), "Source job count"))
        jobs.extend(page["jobs"])
    if len(totals) != 1 or len(jobs) != next(iter(totals)):
        raise ValueError("Source release job listing is incomplete or changed during pagination")
    seen_ids = set()
    required = {}
    for job in jobs:
        if not isinstance(job, dict):
            raise ValueError("Unexpected source release job metadata")
        job_id = positive_integer(job.get("id"), "Source job ID")
        if job_id in seen_ids:
            raise ValueError("Duplicate job in the source release run")
        seen_ids.add(job_id)
        if type(job.get("run_id")) is not int or job["run_id"] != run_id:
            raise ValueError("Source release job belongs to a different run")
        if job.get("head_sha") != commit:
            raise ValueError("Source release job was built from a different commit")
        name = job.get("name")
        if name not in REQUIRED_JOBS | {"Verify and publish release"}:
            raise ValueError("Unexpected job in the source release workflow")
        if name in REQUIRED_JOBS:
            if name in required:
                raise ValueError("Multiple source release jobs have the same required name")
            if job.get("status") != "completed" or job.get("conclusion") != "success":
                raise ValueError("Release validation and all three native builds must have succeeded")
            required[name] = job
    if set(required) != REQUIRED_JOBS:
        raise ValueError("Source release run is missing validation or a required native build")


def verify_tag(reference: object, version: str, commit: str) -> None:
    if not isinstance(reference, dict) or reference.get("ref") != f"refs/tags/v{version}":
        raise ValueError("The original release tag must already exist")
    target = reference.get("object")
    if not isinstance(target, dict) or target.get("type") != "commit" or target.get("sha") != commit:
        raise ValueError("The existing release tag must point directly to the exact original source commit")


def prepare() -> None:
    if os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get("GITHUB_EVENT_NAME") not in {"push", "workflow_dispatch"}:
        raise ValueError("Release recovery must start from main")
    if not os.environ.get("GH_TOKEN"):
        raise ValueError("Release recovery requires the read-only job token")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise ValueError("Invalid GitHub repository identifier")
    validate_commit(os.environ.get("GITHUB_SHA", ""))
    version, commit, run_id = load_manifest(ROOT / ".github" / "release-resume.json")
    endpoint = f"repos/{repository}/actions/runs/{run_id}"
    attempt = verify_run(read_api(endpoint), repository, commit, run_id)
    jobs = read_api(f"{endpoint}/attempts/{attempt}/jobs?per_page=100", paginate=True)
    verify_jobs(jobs, commit, run_id)
    verify_tag(read_api(f"repos/{repository}/git/ref/tags/v{version}"), version, commit)
    if verify_run(read_api(endpoint), repository, commit, run_id) != attempt:
        raise ValueError("Source release workflow was rerun during recovery validation")
    output = Path(os.environ["GITHUB_OUTPUT"])
    with output.open("a", encoding="utf-8") as stream:
        stream.write(f"version={version}\ncommit={commit}\nrun_id={run_id}\n")
    print(f"Validated reuse of run {run_id} for v{version} at {commit}; no rebuild or tag change")


if __name__ == "__main__":
    prepare()
