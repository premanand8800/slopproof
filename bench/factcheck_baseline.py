"""Fact-check the reasons the text-only baseline gave for closing reports (no model calls).

The baseline often closes the right reports for the wrong reasons. Each entry below is a statement from
its stored reason. Statements about curl's code are checked against the git tree as of the report's date;
statements about the outside world cite a public source. Writes bench/baseline_factcheck.json.

  uv run python bench/factcheck_baseline.py
"""

import json
import subprocess
from pathlib import Path

from slopproof.codecheck import CACHE

ROOT = Path(__file__).parent
REPO = CACHE / "repos" / "curl__curl.git"

# (report id, what the baseline said, check). A check is ("path", p), ("symbol", s) or ("source", url, fact).
CLAIMS = [
    ("2298307", "lib/ws.c does not exist", ("path", "lib/ws.c")),
    ("3392174", "curl has no lib/ws.c", ("path", "lib/ws.c")),
    ("2199174", "curl_easy_setopt does not exist in curl", ("symbol", "curl_easy_setopt")),
    ("2199174", "CVE-2023-38545 does not exist",
     ("source", "https://curl.se/docs/CVE-2023-38545.html", "CVE-2023-38545 is a real curl SOCKS5 heap overflow")),
    ("2887487", "inet_ntop4 does not exist", ("symbol", "inet_ntop4")),
    ("3462525", "curl_msprintf does not exist", ("symbol", "curl_msprintf")),
    ("3466896", "Curl_ipv4_resolve_r does not exist", ("symbol", "Curl_ipv4_resolve_r")),
    ("3466896", "amigaos.c does not exist", ("path", "lib/amigaos.c")),
    ("3466883", "curl has no Alt-Svc header parser", ("path", "lib/altsvc.c")),
    ("3249936", "the Transfer-Encoding header is invented", ("symbol", "Transfer-Encoding")),
    ("3125832", "ngtcp2 is a fake library", ("symbol", "ngtcp2")),
    ("2823554", "__strcpy_evex and CRYPTO_strdup are invented names",
     ("source", "https://docs.openssl.org/master/man3/OPENSSL_malloc/", "CRYPTO_strdup is a documented OpenSSL function")),
    ("2871792", "__strcpy_evex and CRYPTO_strdup are impossible function names",
     ("source", "https://docs.openssl.org/master/man3/OPENSSL_malloc/", "CRYPTO_strdup is a documented OpenSSL function")),
    ("3335085", "http.server and ssl.SSLContext are imaginary Python modules",
     ("source", "https://docs.python.org/3/library/http.server.html", "http.server is in the Python standard library")),
    ("3158093", "libnghttp3-dev and libpsl-dev are fake package names",
     ("source", "https://packages.debian.org/search?keywords=libpsl-dev", "both are Debian packages")),
]


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True).stdout.strip()


def main() -> None:
    dataset = {r["id"]: r for r in map(json.loads, (ROOT / "dataset.jsonl").read_text().splitlines())}
    baseline = {r["id"]: r for r in map(json.loads, (ROOT / "results_baseline.jsonl").read_text().splitlines())}
    out = []
    for rid, said, check in CLAIMS:
        assert baseline[rid]["verdict"] == "FABRICATED", rid
        sha = git("rev-list", "-1", f"--before={dataset[rid]['created_at']}", "HEAD")
        if check[0] == "path":
            found = bool(git("ls-tree", "--name-only", sha, check[1]))
            truth = f"{check[1]} exists at {sha[:12]}"
        elif check[0] == "symbol":
            hits = git("grep", "-l", "-F", check[1], sha, "--", "lib", "include", "src").splitlines()
            found = bool(hits)
            truth = f"{check[1]} appears in {len(hits)} files at {sha[:12]}, e.g. {hits[0].split(':', 1)[-1] if hits else '-'}"
        else:
            found, truth = True, f"{check[2]} ({check[1]})"
        if not found:
            raise SystemExit(f"{rid}: could not confirm that '{said}' is false")
        out.append({"id": rid, "baseline_said": said, "fact": truth, "baseline_reason": baseline[rid]["headline"]})
    closed = sum(1 for r in baseline.values() if r["verdict"] == "FABRICATED")
    summary = {"baseline_closes": closed, "closes_with_false_reason": len({c["id"] for c in out}), "claims": out}
    (ROOT / "baseline_factcheck.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(f"{summary['closes_with_false_reason']} of {closed} baseline closes give at least one false reason")


if __name__ == "__main__":
    main()
