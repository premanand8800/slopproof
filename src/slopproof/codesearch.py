"""Find the code a report is about, even when it names no file or function.

Code is split into functions with tree-sitter and ranked with BM25 over code-aware tokens (identifiers split
on case and underscores, no stemming). Parsed functions are cached by git blob hash, so trees from different
dates share almost all of the work. bench/eval_search.py measures it against the functions each CVE fix changed.
We also tried adding callees of the best hits (call-graph expansion); it found the fixed function slightly
less often, so it is not used.

This answers "where is the code this report is about?". Whether quoted code is real stays a lexical check
in codecheck.py: a semantic match would let invented code pass as "similar".
"""

import json
import math
import re
import subprocess
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_c
from tree_sitter import Language, Parser

from .codecheck import CACHE

C_LANG = Language(tree_sitter_c.language())
SEARCH_DIRS = ("lib/", "src/", "include/")
STOP = set("""if else for while do switch case break continue return goto sizeof struct union enum typedef static const
void int char long short unsigned signed bool size_t ssize_t null true false the a an of to in is it and or be this that
with for on as by not are was from at can if we when then data result""".split())


@dataclass
class Func:
    file: str
    name: str
    start: int
    end: int
    calls: list[str]
    text: str


def tokens(text: str) -> list[str]:
    """Split code and prose into search tokens: CURLOPT_NETRC -> curlopt, netrc; parseNetrc -> parse, netrc."""
    out = []
    for word in re.findall(r"[A-Za-z][A-Za-z0-9_]*", text):
        for part in re.split(r"_+", word):
            for piece in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", part):
                p = piece.lower()
                if len(p) > 1 and p not in STOP:
                    out.append(p)
        if "_" in word or re.search(r"[a-z][A-Z]", word):
            out.append(word.lower())  # keep the whole identifier too, so exact names score highest
    return out


def _name_of(node) -> str | None:
    """Walk a function_definition's declarator chain down to its identifier."""
    d = node.child_by_field_name("declarator")
    while d is not None:
        if d.type in ("identifier", "field_identifier"):
            return d.text.decode(errors="replace")
        nxt = d.child_by_field_name("declarator")
        if nxt is None:
            ids = [c for c in d.children if c.type == "identifier"]
            return ids[0].text.decode(errors="replace") if ids else None
        d = nxt
    return None


def parse_functions(path: str, source: bytes) -> list[dict]:
    tree = Parser(C_LANG).parse(source)
    out, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            name = _name_of(node)
            if name:
                start = node.start_point[0]
                prev = node.prev_sibling
                while prev is not None and prev.type == "comment" and prev.end_point[0] >= start - 1:
                    start = prev.start_point[0]  # keep the comment above the function: it is good prose to match
                    prev = prev.prev_sibling
                calls, cstack = set(), [node]
                while cstack:
                    n = cstack.pop()
                    if n.type == "call_expression":
                        f = n.child_by_field_name("function")
                        if f is not None and f.type == "identifier":
                            calls.add(f.text.decode(errors="replace"))
                    cstack.extend(n.children)
                lines = source.decode(errors="replace").splitlines()[start:node.end_point[0] + 1]
                out.append({"file": path, "name": name, "start": start + 1, "end": node.end_point[0] + 1,
                            "calls": sorted(calls), "text": "\n".join(lines)})
            continue
        stack.extend(node.children)
    return out


def _blobs(bare: Path, sha: str) -> list[tuple[str, str]]:
    out = subprocess.run(["git", "-C", str(bare), "ls-tree", "-r", sha], capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        meta, path = line.split("\t", 1)
        if path.endswith((".c", ".h")):
            rows.append((path, meta.split()[2]))
    # curl-style layouts keep product code in lib/, src/ and include/. Use them only if they hold C sources;
    # otherwise (libevent keeps .c files at the top level) take everything except tests and samples.
    main = [r for r in rows if r[0].startswith(SEARCH_DIRS)]
    if any(path.endswith(".c") for path, _ in main):
        return main
    return [r for r in rows if not re.match(r"(tests?|testing|test-export|sample|examples?|fuzz)/", r[0])]


def load_functions(bare: Path, sha: str) -> list[Func]:
    cache = CACHE / "funcs"
    cache.mkdir(parents=True, exist_ok=True)
    funcs = []
    for path, blob in _blobs(bare, sha):
        f = cache / f"{blob}.json"
        if f.exists():
            items = json.loads(f.read_text())
        else:
            src = subprocess.run(["git", "-C", str(bare), "cat-file", "blob", blob], capture_output=True, check=True).stdout
            items = parse_functions(path, src)
            f.write_text(json.dumps(items))
        funcs += [Func(**{**i, "file": path}) for i in items]
    return funcs


class Index:
    """BM25 over functions."""

    def __init__(self, funcs: list[Func], k1: float = 1.2, b: float = 0.75):
        self.funcs, self.k1, self.b = funcs, k1, b
        self.docs = []
        for f in funcs:
            # Name and path count extra: they are the strongest hint of what a function is about.
            toks = tokens(f.text) + tokens(f.name) * 3 + tokens(f.file) * 2
            self.docs.append(Counter(toks))
        self.lens = [sum(d.values()) for d in self.docs]
        self.avg = sum(self.lens) / max(1, len(self.lens))
        df = Counter(t for d in self.docs for t in d)
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}
        self.postings = defaultdict(list)
        for i, d in enumerate(self.docs):
            for t in d:
                self.postings[t].append(i)

    def bm25(self, query_tokens: list[str]) -> dict[int, float]:
        scores: dict[int, float] = defaultdict(float)
        for t, qtf in Counter(query_tokens).items():
            idf = self.idf.get(t)
            if idf is None:
                continue
            for i in self.postings[t]:
                tf = self.docs[i][t]
                denom = tf + self.k1 * (1 - self.b + self.b * self.lens[i] / self.avg)
                scores[i] += idf * tf * (self.k1 + 1) / denom * (1 + math.log(qtf))
        return scores

    def search(self, query_tokens: list[str], k: int = 10) -> list[tuple[Func, float, list[str]]]:
        """Top functions, each with the query terms that matched it best (rarest first)."""
        top = sorted(self.bm25(query_tokens).items(), key=lambda x: -x[1])[:k]
        qset = set(query_tokens)
        out = []
        for i, s in top:
            terms = sorted((t for t in qset if t in self.docs[i]), key=lambda t: -self.idf[t])[:5]
            out.append((self.funcs[i], round(s, 2), terms))
        return out


_indexes: dict[str, Index] = {}
_lock = threading.Lock()


def index_for(bare: Path, sha: str) -> Index:
    with _lock:
        if sha not in _indexes:
            if len(_indexes) >= 4:
                _indexes.pop(next(iter(_indexes)))  # keep a few trees; each index is about 4 s to build
            _indexes[sha] = Index(load_functions(bare, sha))
        return _indexes[sha]


def report_query(title: str, body: str, claims: dict) -> list[str]:
    """Query tokens from the report: the claim in its own words, plus every identifier and option it mentions."""
    parts = [title, claims.get("summary") or "", claims.get("vuln_class") or "", claims.get("attack_surface") or "",
             " ".join(claims.get("functions") or []), " ".join(claims.get("files") or []),
             " ".join(claims.get("repro_steps") or [])]
    ids = re.findall(r"\b(?:CURL[A-Z]*_[A-Z0-9_]+|Curl_\w+|curl_\w+|curlx_\w+)\b|--[a-z][a-z0-9-]+", body)
    return tokens(" ".join(parts + ids))


def find_code(bare: Path, sha: str, title: str, body: str, claims: dict, k: int = 8) -> list[dict]:
    hits = index_for(bare, sha).search(report_query(title, body, claims), k=k)
    return [{"file": f.file, "name": f.name, "start": f.start, "end": f.end, "score": s,
             "why": "matches " + ", ".join(terms)} for f, s, terms in hits]
