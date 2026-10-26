"""Text-only screen: one model call that judges a report from its wording alone.

This is how AI slop is spotted today, and it is often right about the outcome. Its reasons are not:
in our benchmark many of them cite facts that are themselves false (for example, that lib/ws.c does not
exist). So the screen is only a vote. It can lower a report's priority, and it can let a close go through
when the evidence-based verdict also wants to close, but its reasons are never shown as evidence.
"""

from .llm import Ledger, chat_json

SYSTEM = """You review vulnerability reports sent to the {project} project.
Many reports are AI-generated slop: invented code, impossible bugs, or generic text that does not apply to {project}.
Decide from the report text whether it should be closed as slop or kept for a maintainer to investigate.
Reply with one JSON object only: {{"close": true or false, "confidence": 0.0 to 1.0, "reason": "one sentence"}}"""


def screen(title: str, body: str, project: str, ledger: Ledger) -> dict:
    """project is the short name, for example "curl"."""
    out = chat_json("big", SYSTEM.format(project=project), f"TITLE: {title}\n\nREPORT:\n{body[:6000]}", ledger,
                    "screen", max_tokens=300)
    return {"close": bool(out.get("close")), "confidence": out.get("confidence"), "reason": out.get("reason", "")}
