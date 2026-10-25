"""Static reasoning: does the real code allow the condition the report claims?"""

from .llm import Ledger, chat_json

SYSTEM = """You are a senior C and systems security engineer. You get a vulnerability report and the REAL source
code it refers to, taken from the project at the commit the reporter was looking at.

Decide whether the specific condition the report claims (overflow, use-after-free, double free, injection, leak...)
can actually happen in this code. Trace sizes, bounds, ownership and control flow. Quote the exact lines
(file:line) that make the claim possible or impossible. Ignore the report's rhetoric; only the code matters.
If the code you were given is not enough to decide, say so and name what to read next.

Reply with one JSON object only:
{
  "claim_holds": "yes | no | unclear",
  "reasoning": "step by step, citing file:line",
  "key_lines": ["file:line - why it matters"],
  "test_plan": "the most direct runtime test that would prove or disprove the claim through the public API, CLI or network input"
}"""


def analyze(title: str, body: str, claims: dict, context: str, ledger: Ledger) -> dict:
    user = (f"REPORT TITLE: {title}\n\nREPORT:\n{body[:12000]}\n\n"
            f"SUMMARY OF CLAIM: {claims.get('summary')}\n\nREAL SOURCE CODE:\n{context or '(no matching code found)'}")
    return chat_json("big", SYSTEM, user, ledger, "static analysis", max_tokens=16000, think=True)
