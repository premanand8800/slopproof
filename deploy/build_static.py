"""Build the static demo: the web UI plus the benchmark and every recorded run as JSON. No server, no keys.

  uv run python deploy/build_static.py [--out site] [--from-head]

--from-head reads the benchmark files from the last git commit, so a benchmark that is still writing
results is never published half-done.
"""

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from slopproof.benchscore import score
from slopproof.server import BENCH_FILES, bench_rows, report_bodies, stored_run

ROOT = Path(__file__).resolve().parents[1]
FILES = ("dataset.jsonl", *(n for names in BENCH_FILES.values() for n in names),
         "baseline_factcheck.json", "search_eval.json")


def bench_dir(from_head: bool) -> Path:
    if not from_head:
        return ROOT / "bench"
    tmp = Path(tempfile.mkdtemp())
    for name in FILES:
        out = subprocess.run(["git", "-C", str(ROOT), "show", f"HEAD:bench/{name}"], capture_output=True)
        if out.returncode == 0:
            (tmp / name).write_bytes(out.stdout)
    return tmp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="site")
    ap.add_argument("--from-head", action="store_true")
    a = ap.parse_args()
    src, out = bench_dir(a.from_head), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for child in out.iterdir():  # keep .git when building into a checked-out Space
        if child.name != ".git":
            shutil.rmtree(child) if child.is_dir() else child.unlink()
    shutil.copytree(ROOT / "web", out / "static", ignore=shutil.ignore_patterns("index.html"))
    html = (ROOT / "web" / "index.html").read_text()
    html = html.replace('<script src="static/js/core.js">', '<script>window.SLOPPROOF_STATIC = true;</script>\n'
                                                            '<script src="static/js/core.js">')
    (out / "index.html").write_text(html)

    bodies = report_bodies(src)
    bench = {}
    for mode in ("static", "sandbox", "baseline"):
        light = [{k: v for k, v in r.items() if k != "full"} for r in bench_rows(mode, src)]
        bench[mode] = {"score": score(light) if light else None, "rows": light}
        if mode != "baseline":
            (out / "data" / "runs" / mode).mkdir(parents=True, exist_ok=True)
            for r in bench_rows(mode, src, headline_only=False):
                (out / "data" / "runs" / mode / f"{r['id']}.json").write_text(json.dumps(stored_run(r, bodies), default=str))
    (out / "data" / "examples").mkdir(parents=True, exist_ok=True)
    for f in (ROOT / "examples" / "bundles").glob("*.json"):
        shutil.copy(f, out / "data" / "examples" / f.name)
    fc = src / "baseline_factcheck.json"
    bench["baseline"]["factcheck"] = json.loads(fc.read_text()) if fc.exists() else None
    (out / "data" / "bench.json").write_text(json.dumps(bench, default=str))
    n = sum(1 for _ in out.rglob("*") if _.is_file())
    print(f"built {out} with {n} files")


if __name__ == "__main__":
    main()
