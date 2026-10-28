"""Docker sandbox: no network, capped CPU, memory and processes."""

import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

from .codecheck import CACHE

# SLOPPROOF_IMAGE lets a benchmark use a separate sandbox image without rebuilding the one the live demo runs.
IMAGE = os.environ.get("SLOPPROOF_IMAGE", "slopproof-sandbox:latest")
OUTPUT_LIMIT = 6000


def _ccache_mount() -> list[str]:
    """Docker args for a shared ccache, when SLOPPROOF_CCACHE names a directory. Empty otherwise (the default)."""
    d = os.environ.get("SLOPPROOF_CCACHE")
    if not d:
        return []
    p = Path(d).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, 0o777)  # the container's unprivileged runner (uid 1000) must be able to write it
    # Route clang/gcc through ccache transparently (via /usr/lib/ccache on PATH), so build commands and proof
    # bundles stay plain and portable; ccache only ever runs when this shared cache is mounted.
    path = "/usr/lib/ccache:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return ["-v", f"{p}:/ccache", "-e", "CCACHE_DIR=/ccache", "-e", "CCACHE_MAXSIZE=5G", "-e", f"PATH={path}"]


class Sandbox:
    def __init__(self, tree: Path, memory: str = "3g", cpus: str = "6"):
        self.name = f"slopproof-{uuid.uuid4().hex[:10]}"
        # Each run gets a writable copy, so a build in one run never leaks into another.
        self.workdir = CACHE / "runs" / self.name
        self.workdir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(tree, self.workdir / "repo", symlinks=True)
        # SLOPPROOF_RUNTIME=runsc runs the container under gVisor, which gives it its own kernel.
        runtime = os.environ.get("SLOPPROOF_RUNTIME")
        # SLOPPROOF_CCACHE=<dir> mounts a shared ccache so repeated builds of the same project are fast. It is a
        # writable bind mount, so it is opt-in (off in the live deployment) and only ever holds compiler cache.
        cache = _ccache_mount()
        subprocess.run([
            "docker", "run", "-d", "--rm", "--name", self.name, *(["--runtime", runtime] if runtime else []),
            "--network", "none", "--memory", memory, "--cpus", cpus, "--pids-limit", "1024",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--read-only", "--tmpfs", "/tmp:rw,exec,size=1g", *cache,
            "-v", f"{self.workdir}:/work", "-w", "/work/repo", IMAGE, "sleep", "infinity",
        ], check=True, capture_output=True)

    def run(self, cmd: str, timeout: int = 300, pipefail: bool = True) -> dict:
        try:
            # pipefail: "make | tail" must report make's failure, not tail's success. Proof-bundle checks run
            # without it, so "poc | grep -q" keeps meaning "grep found it".
            p = subprocess.run(["docker", "exec", self.name, "timeout", "-k", "5", str(timeout), "bash", "-lc",
                                f"set -o pipefail; {cmd}" if pipefail else cmd],
                               capture_output=True, text=True, timeout=timeout + 30)
            out = (p.stdout + p.stderr)
            code = p.returncode
        except subprocess.TimeoutExpired:
            out, code = "host timeout", 124
        if code == 124:
            out += f"\n[command timed out after {timeout}s]"
        elif code == 141 and pipefail:
            out += "\n[exit 141: a later command in the pipe (head, grep -q) stopped reading early; not a failure]"
        if len(out) > OUTPUT_LIMIT:
            # Keep a sanitizer report intact from its header: it is the evidence that matters.
            m = re.search(r"==\d+==\s*(ERROR|WARNING): \w+Sanitizer|runtime error:|SUMMARY: \w+Sanitizer", out)
            if m and m.start() > 1500:
                start = max(0, m.start() - 300)
                out = out[:800] + "\n... [cut] ...\n" + out[start:start + OUTPUT_LIMIT - 800]
            else:
                out = (out[:1500] + f"\n... [{len(out) - OUTPUT_LIMIT} chars cut: read specific lines with "
                       "grep -n or sed -n 'A,Bp' instead of whole files] ...\n" + out[-(OUTPUT_LIMIT - 1500):])
        return {"exit_code": code, "output": out}

    def background(self, cmd: str, tag: str = "build") -> None:
        """Start a long command (a build) detached; output goes to /work/{tag}.log, exit code to /work/{tag}.done."""
        script = f"cd /work/repo && ( {cmd} ) > /work/{tag}.log 2>&1; echo $? > /work/{tag}.done"
        subprocess.run(["docker", "exec", "-d", self.name, "bash", "-lc", script], check=True)

    def write(self, path: str, content: str) -> str:
        target = (self.workdir / path.removeprefix("/work/")).resolve()
        if not str(target).startswith(str(self.workdir.resolve())):
            return "refused: path outside /work"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return f"wrote {len(content)} bytes to /work/{target.relative_to(self.workdir.resolve())}"

    def close(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        # Build artefacts are owned by the container user; remove them from inside first.
        subprocess.run(["docker", "run", "--rm", "-v", f"{self.workdir}:/work", IMAGE, "bash", "-c", "rm -rf /work/* /work/.[!.]*"],
                       capture_output=True)
        shutil.rmtree(self.workdir, ignore_errors=True)
