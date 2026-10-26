"""Proof bundles: a vulnerability report that carries its own, re-runnable proof.

A bundle pins the project commit and sandbox image, and holds the build command, the PoC files and one check
command that exits 0 only while the bug is present. Anyone can verify it: build that commit in a fresh sandbox,
run the check, compare. No model is involved, so the answer does not depend on anyone's judgement.

Verifying against a later commit (for example the fix) shows the other half: the same check stops passing.
"""

import hashlib
import json
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from . import codecheck
from .sandbox import IMAGE, Sandbox

SCHEMA = "slopproof.bundle/v1"


def image_id() -> str | None:
    out = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], capture_output=True, text=True)
    return out.stdout.strip() or None


def digest(bundle: dict) -> str:
    body = {k: v for k, v in bundle.items() if k != "sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def make_bundle(repo: str, commit: str, build: str, files: dict[str, str], check: str, claim: str,
                expect_output: str | None = None, setup: str = "") -> dict:
    bundle = {
        "schema": SCHEMA,
        "claim": claim,
        "repo": repo,
        "commit": commit,
        "sandbox_image": image_id(),
        "build": build,
        "files": files,
        "setup": setup,
        "check": check,
        "expect_output": expect_output,  # optional regex the check's output must also match
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    bundle["sha256"] = digest(bundle)
    return bundle


def _run_at(bundle: dict, ref: str, emit: Callable[[str], None]) -> dict:
    """Build the project at ref in a fresh sandbox, install the PoC files, run the check once."""
    bare = codecheck.ensure_repo(bundle["repo"])
    sha = codecheck.git(bare, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()
    sb = Sandbox(codecheck.export_tree(bare, sha))
    t0 = time.time()
    try:
        emit(f"building {sha[:12]} ...")
        built = sb.run(bundle["build"], timeout=1500)
        if built["exit_code"] != 0:
            return {"commit": sha, "built": False, "output": built["output"][-2000:], "seconds": round(time.time() - t0)}
        for path, content in bundle["files"].items():
            sb.write(path, content)
        if bundle.get("setup"):
            sb.run(bundle["setup"], timeout=600)
        emit("running the check ...")
        res = sb.run(bundle["check"], timeout=300)
        matched = bool(re.search(bundle["expect_output"], res["output"], re.M)) if bundle.get("expect_output") else True
        return {"commit": sha, "built": True, "exit_code": res["exit_code"], "output": res["output"][-3000:],
                "bug_present": res["exit_code"] == 0 and matched, "seconds": round(time.time() - t0)}
    finally:
        sb.close()


def verify(bundle: dict, against: str | None = None, emit: Callable[[str], None] = lambda m: None) -> dict:
    """VERIFIED when the check shows the bug at the bundle's commit; FIXED_AT_AGAINST when it is also gone there."""
    problems = []
    if bundle.get("schema") != SCHEMA:
        problems.append(f"unknown schema {bundle.get('schema')!r}")
    if bundle.get("sha256") and bundle["sha256"] != digest(bundle):
        problems.append("sha256 does not match the bundle contents (edited after it was made)")
    if bundle.get("sandbox_image") and bundle["sandbox_image"] != image_id():
        problems.append("built with a different sandbox image; results may differ")
    if any(not p.startswith("/work/") for p in bundle.get("files", {})):
        return {"verdict": "INVALID", "problems": problems + ["files must live under /work/"]}
    report = _run_at(bundle, bundle["commit"], emit)
    out = {"bundle": bundle.get("sha256"), "claim": bundle.get("claim"), "problems": problems, "at_commit": report}
    if not report["built"]:
        out["verdict"] = "BUILD_FAILED"
        return out
    out["verdict"] = "VERIFIED" if report["bug_present"] else "NOT_VERIFIED"
    if against and report["bug_present"]:
        later = _run_at(bundle, against, emit)
        out["at_against"] = later
        if later.get("built") and not later["bug_present"]:
            out["verdict"] = "VERIFIED_AND_FIXED"
    return out


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())
