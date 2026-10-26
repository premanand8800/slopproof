"""Docker sandbox: no network, capped CPU, memory and processes."""

import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

from .codecheck import CACHE

IMAGE = "slopproof-sandbox:latest"
OUTPUT_LIMIT = 6000


class Sandbox:
    def __init__(self, tree: Path, memory: str = "3g", cpus: str = "6"):
        self.name = f"slopproof-{uuid.uuid4().hex[:10]}"
        # Each run gets a writable copy, so a build in one run never leaks into another.
        self.workdir = CACHE / "runs" / self.name
        self.workdir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(tree, self.workdir / "repo", symlinks=True)
        # SLOPPROOF_RUNTIME=runsc runs the container under gVisor, which gives it its own kernel.
        runtime = os.environ.get("SLOPPROOF_RUNTIME")
        subprocess.run([
            "docker", "run", "-d", "--rm", "--name", self.name, *(["--runtime", runtime] if runtime else []),
            "--network", "none", "--memory", memory, "--cpus", cpus, "--pids-limit", "1024",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--read-only", "--tmpfs", "/tmp:rw,exec,size=1g",
            "-v", f"{self.workdir}:/work", "-w", "/work/repo", IMAGE, "sleep", "infinity",
        ], check=True, capture_output=True)

    def run(self, cmd: str, timeout: int = 300) -> dict:
        try:
            p = subprocess.run(["docker", "exec", self.name, "timeout", "-k", "5", str(timeout), "bash", "-lc", cmd],
                               capture_output=True, text=True, timeout=timeout + 30)
            out = (p.stdout + p.stderr)
            code = p.returncode
        except subprocess.TimeoutExpired:
            out, code = "host timeout", 124
        if code == 124:
            out += f"\n[command timed out after {timeout}s]"
        if len(out) > OUTPUT_LIMIT:
            # Keep a sanitizer report intact from its header: it is the evidence that matters.
            m = re.search(r"==\d+==\s*(ERROR|WARNING): \w+Sanitizer|runtime error:|SUMMARY: \w+Sanitizer", out)
            if m and m.start() > 1500:
                start = max(0, m.start() - 300)
                out = out[:800] + "\n... [cut] ...\n" + out[start:start + OUTPUT_LIMIT - 800]
            else:
                out = out[:1500] + f"\n... [{len(out) - OUTPUT_LIMIT} chars cut] ...\n" + out[-(OUTPUT_LIMIT - 1500):]
        return {"exit_code": code, "output": out}

    def background(self, cmd: str) -> None:
        """Start a long command (a build) detached; exit code lands in /work/build.done."""
        script = f"cd /work/repo && ( {cmd} ) > /work/build.log 2>&1; echo $? > /work/build.done"
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
