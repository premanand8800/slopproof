"""Static reasoning: does the real code allow the condition the report claims?"""

from collections.abc import Callable

from .llm import Ledger, chat_json

SYSTEM = """You are a senior C and systems security engineer. You get a vulnerability report and the REAL source
code it refers to, taken from the project at the commit the reporter was looking at.

Decide whether the specific condition the report claims (overflow, use-after-free, double free, injection, leak...)
can actually happen in this code. Trace sizes, bounds, ownership and control flow. Quote the exact lines
(file:line) that make the claim possible or impossible. Ignore the report's rhetoric; only the code matters.
If your conclusion depends on how a function or macro you were NOT shown behaves, do not guess ("if implemented
naively"): list it in read_next, and it will be fetched from the real tree for a second look.

Reply with one JSON object only:
{
  "claim_holds": "yes | no | unclear",
  "reasoning": "step by step, citing file:line",
  "key_lines": ["file:line - why it matters"],
  "test_plan": "the most direct runtime test that would prove or disprove the claim through the public API, CLI or network input",
  "read_next": ["exact names of functions or macros whose code you need and were not shown; empty if none"]
}"""


def analyze(title: str, body: str, claims: dict, context: str, ledger: Ledger) -> dict:
    user = (f"REPORT TITLE: {title}\n\nREPORT:\n{body[:12000]}\n\n"
            f"SUMMARY OF CLAIM: {claims.get('summary')}\n\nREAL SOURCE CODE:\n{context or '(no matching code found)'}")
    return chat_json("big", SYSTEM, user, ledger, "static analysis", max_tokens=16000, think=True)


def analyze_deep(title: str, body: str, claims: dict, context: str, ledger: Ledger,
                 fetch: "Callable[[list[str]], str]") -> dict:
    """Analyze, and if the model names code it needed but did not get, fetch it and look once more."""
    first = analyze(title, body, claims, context, ledger)
    names = [n for n in (first.get("read_next") or []) if isinstance(n, str) and n.strip()][:6]
    if not names:
        return first
    extra = fetch(names)
    if not extra:
        return {**first, "read_next_missing": names}
    second = analyze(title, body, claims, f"{context}\n\n=== Fetched on request: {', '.join(names)}\n{extra}", ledger)
    second["second_look"] = {"asked_for": names, "first_conclusion": first.get("claim_holds")}
    return second
