"""Check a report's claims against the real source tree at the time of the report."""

import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

from rapidfuzz import fuzz

CACHE = Path(__file__).resolve().parents[2] / ".cache"
SOURCE_EXT = (".c", ".h", ".cc", ".cpp", ".hpp", ".py", ".go", ".rs", ".js", ".ts", ".java", ".rb", ".pl", ".sh")


def git(bare: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(bare), *args], capture_output=True, text=True, check=True).stdout


def repo_slug(repo_url: str) -> str:
    m = re.search(r"github\.com[/:]([^/]+)/([^/.]+)", repo_url)
    if not m:
        raise ValueError(f"not a GitHub repo URL: {repo_url}")
    return f"{m.group(1)}__{m.group(2)}"


def ensure_repo(repo_url: str) -> Path:
    bare = CACHE / "repos" / f"{repo_slug(repo_url)}.git"
    if not bare.exists():
        bare.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--bare", "-q", repo_url, str(bare)], check=True)
    return bare


def resolve_ref(bare: Path, claims: dict, created_at: str | None) -> dict:
    """Pick the commit the reporter was most likely looking at."""
    commit = claims.get("claimed_commit")
    if commit:
        try:
            sha = git(bare, "rev-parse", "--verify", f"{commit}^{{commit}}").strip()
            return {"sha": sha, "why": f"commit linked in the report ({commit[:12]})"}
        except subprocess.CalledProcessError:
            pass
    if created_at:
        sha = git(bare, "rev-list", "-1", f"--before={created_at}", "HEAD").strip()
        if sha:
            return {"sha": sha, "why": f"default branch as of report date {created_at[:10]}"}
    sha = git(bare, "rev-parse", "HEAD").strip()
    return {"sha": sha, "why": "default branch HEAD (no date or commit in report)"}


def version_tag(bare: Path, version: str | None) -> str | None:
    if not version:
        return None
    nums = re.findall(r"\d+", version)
    if len(nums) < 2:
        return None
    want = "_".join(nums[:3])
    for tag in git(bare, "tag", "--list").split():
        if "_".join(re.findall(r"\d+", tag)[:3]) == want:
            return tag
    return None


def export_tree(bare: Path, sha: str) -> Path:
    dest = CACHE / "trees" / bare.stem / sha[:12]
    if not dest.exists():
        tmp = dest.with_name(f"{dest.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.mkdir(parents=True, exist_ok=True)
        archive = subprocess.run(["git", "-C", str(bare), "archive", sha], capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", str(tmp)], input=archive, check=True)
        try:
            tmp.rename(dest)
        except OSError:  # another thread exported the same commit first
            shutil.rmtree(tmp, ignore_errors=True)
    return dest


def _source_files(tree: Path) -> list[Path]:
    return [p for p in tree.rglob("*") if p.is_file() and p.suffix in SOURCE_EXT]


def _norm(code: str) -> str:
    return re.sub(r"\s+", " ", code).strip()


PARTIAL_CANDIDATES = 25


def best_match(quote: str, files: list[Path], tree: Path, texts: dict[Path, str] | None = None) -> dict:
    """Find where a quoted snippet best matches real code, sliding a window over each file.

    Only windows that share an identifier with the quote are scored. Every candidate gets the fast
    fuzz.ratio; the slower partial_ratio (which matters when the quote is a fragment of a longer window)
    runs only on the best candidates, which keeps long quotes over many files from taking tens of seconds.
    """
    q = _norm(quote)
    n_lines = max(1, quote.strip().count("\n") + 1)
    idents = set(re.findall(r"[A-Za-z_]\w{2,}", quote))
    best = {"score": 0.0, "file": None, "line": None}
    scored = []
    for f in files:
        text = texts[f] if texts and f in texts else f.read_text(errors="replace")
        lines = text.splitlines()
        hits = [i for i, line in enumerate(lines) if any(t in line for t in idents)] if idents else range(len(lines))
        for i in sorted({max(0, h - k) for h in hits for k in range(n_lines)}):
            window = _norm("\n".join(lines[i:i + n_lines]))
            if window:
                scored.append((fuzz.ratio(q, window), f, i, window))
                if scored[-1][0] > best["score"]:
                    best = {"score": round(scored[-1][0], 1), "file": str(f.relative_to(tree)), "line": i + 1}
    scored.sort(key=lambda x: -x[0])
    for _, f, i, window in scored[:PARTIAL_CANDIDATES]:
        if len(q) <= len(window):
            score = fuzz.partial_ratio(q, window)
            if score > best["score"]:
                best = {"score": round(score, 1), "file": str(f.relative_to(tree)), "line": i + 1}
    return best


def _excerpt(tree: Path, rel: str, start: int, end: int) -> str:
    lines = (tree / rel).read_text(errors="replace").splitlines()
    start, end = max(1, start), min(len(lines), end)
    return "\n".join(f"{i:5d}  {lines[i - 1]}" for i in range(start, end + 1))


def _function_span(tree: Path, rel: str, line: int, cap: int = 220) -> tuple[int, int]:
    """From a definition line, follow braces to the end of a C-style function body."""
    lines = (tree / rel).read_text(errors="replace").splitlines()
    depth, opened = 0, False
    for i in range(line - 1, min(len(lines), line - 1 + cap)):
        depth += lines[i].count("{") - lines[i].count("}")
        opened = opened or "{" in lines[i]
        if opened and depth <= 0:
            return line, i + 1
    return line, min(len(lines), line + 120)


def code_context(tree: Path, code: dict, found: list[dict] | None = None, budget: int = 40000) -> str:
    """Source excerpts the reasoning model needs: cited lines, definitions of cited functions, then the
    functions code search ranked highest (these fill whatever budget the cited code leaves)."""
    parts, seen = [], set()
    for ref in code["line_refs"]:
        f, n = str(ref.get("file") or "").lstrip("/"), ref.get("line")
        if isinstance(n, int) and n > 0 and (tree / f).is_file() and (f, n) not in seen:
            seen.add((f, n))
            parts.append(f"=== {f} around line {n} (cited by report)\n{_excerpt(tree, f, n - 30, n + 30)}")
    for fn in code["functions"]:
        for d in fn["definitions"][:2]:
            f, n = d.rsplit(":", 1)
            if not f.endswith((".h", ".hpp")) and (f, int(n)) not in seen:
                seen.add((f, int(n)))
                s, e = _function_span(tree, f, int(n))
                parts.append(f"=== {f}:{s}-{e} definition of {fn['name']}\n{_excerpt(tree, f, s, e)}")
    for h in found or []:
        if (h["file"], h["start"]) not in seen and (tree / h["file"]).is_file():
            seen.add((h["file"], h["start"]))
            parts.append(f"=== {h['file']}:{h['start']}-{h['end']} {h['name']} (found by code search: {h['why']})\n"
                         f"{_excerpt(tree, h['file'], h['start'], min(h['end'], h['start'] + 200))}")
    out, total = [], 0
    for p in parts:
        if total + len(p) > budget:
            continue  # a smaller excerpt further down may still fit
        out.append(p)
        total += len(p)
    return "\n\n".join(out)


def check_code(tree: Path, claims: dict) -> dict:
    results = {"files": [], "functions": [], "line_refs": [], "code_quotes": []}
    all_files = _source_files(tree)
    texts = {f: f.read_text(errors="replace") for f in all_files}

    for path in claims["files"]:
        path = path.strip().lstrip("/")
        exists = (tree / path).is_file()
        moved = None
        if not exists:
            base = Path(path).name
            hits = [str(f.relative_to(tree)) for f in all_files if f.name == base]
            moved = hits[:3] or None
        results["files"].append({"path": path, "exists": exists, "found_elsewhere": moved})

    for fn in claims["functions"]:
        name = re.sub(r"[^\w]", "", fn.split("(")[0])
        if not name:
            continue
        pat = re.compile(rf"\b{re.escape(name)}\s*\(")
        defs, uses = [], 0
        for f in all_files:
            text = texts[f]
            if not pat.search(text):
                continue
            uses += 1
            rel = str(f.relative_to(tree))
            for i, line in enumerate(text.splitlines(), 1):
                # A definition starts at column 0 in C style and is not a call statement.
                if pat.search(line) and not line.startswith((" ", "\t")) and not line.rstrip().endswith(";"):
                    defs.append(f"{rel}:{i}")
        test_only = bool(defs) and all(d.startswith(("tests/", "test/")) for d in defs)
        results["functions"].append({"name": name, "exists": uses > 0, "definitions": defs[:5],
                                     "files_using": uses, "test_code_only": test_only})

    for ref in claims["line_refs"]:
        f = tree / str(ref.get("file", "")).lstrip("/")
        line = ref.get("line")
        text = None
        if f.is_file() and isinstance(line, int):
            lines = f.read_text(errors="replace").splitlines()
            if 0 < line <= len(lines):
                text = lines[line - 1].strip()
        results["line_refs"].append({"file": ref.get("file"), "line": line, "actual": text})

    for q in claims["code_quotes"]:
        code = (q.get("code") or "").strip()
        # Only quotes presented as the project's own code must exist in the tree.
        if len(code) < 12 or q.get("role", "project_code") != "project_code":
            continue
        # Prose the extractor mislabelled as code has no code punctuation; skip it.
        if not re.search(r"[(){};=\[\]<>*]", code):
            continue
        cited = tree / str(q.get("file") or "").lstrip("/")
        candidates = [cited] if cited.is_file() else []
        m = best_match(code, candidates, tree, texts) if candidates else {"score": 0.0}
        if m["score"] < 90:
            # Narrow the global search to files that mention the longest identifier in the quote.
            idents = sorted(set(re.findall(r"[A-Za-z_]\w{4,}", code)), key=len, reverse=True)[:2]
            pool = [f for f in all_files if idents and any(i in texts[f] for i in idents)]
            g = best_match(code, pool[:200], tree, texts)
            if g["score"] > m["score"]:
                m = g
        verdict = "verbatim" if m["score"] >= 90 else "paraphrased" if m["score"] >= 70 else "not_in_codebase"
        results["code_quotes"].append({"quote": code[:400], "cited_file": q.get("file"), "match": m, "verdict": verdict})
    return results
