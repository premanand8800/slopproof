"""Nebius Token Factory client with model routing and a cost ledger."""

import contextvars
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv
from openai import NotFoundError, OpenAI, RateLimitError

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

BASE_URL = os.environ.get("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")

# Nebius Token Factory is the default and what the hosted demo uses. SLOPPROOF_PROVIDER=openrouter serves the same
# Nemotron models through OpenRouter, for development when Token Factory credit runs out. Every result records
# which provider produced it.
PROVIDER = os.environ.get("SLOPPROOF_PROVIDER", "nebius")
OPENROUTER_IDS = {
    "nvidia/Nemotron-3_5-Lightning": "nvidia/nemotron-3.5-lightning",
    "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B": "nvidia/nemotron-3-nano-30b-a3b",
    "nvidia/nemotron-3-super-120b-a12b": "nvidia/nemotron-3-super-120b-a12b",
    "nvidia/Nemotron-3.5-Super-VL": "nvidia/nemotron-3.5-super-vl",
    "nvidia/Nemotron-3-Ultra-550b-a55b": "nvidia/nemotron-3-ultra-550b-a55b",
}

# Three tiers. Fast model reads and extracts, the mid model audits, the big model reasons and reproduces.
MODELS = {
    "fast": os.environ.get("SLOPPROOF_FAST_MODEL", "nvidia/Nemotron-3_5-Lightning"),
    "mid": os.environ.get("SLOPPROOF_MID_MODEL", "nvidia/nemotron-3-super-120b-a12b"),
    "big": os.environ.get("SLOPPROOF_BIG_MODEL", "nvidia/Nemotron-3-Ultra-550b-a55b"),
}

# USD per 1M tokens (input, output), from the Token Factory catalog.
PRICES = {
    "nvidia/Nemotron-3_5-Lightning": (0.06, 0.24),
    "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B": (0.06, 0.24),
    "nvidia/nemotron-3-super-120b-a12b": (0.30, 0.90),
    "nvidia/Nemotron-3.5-Super-VL": (0.30, 0.90),
    "nvidia/Nemotron-3-Ultra-550b-a55b": (1.00, 3.00),
}


@dataclass
class Ledger:
    calls: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, model: str, purpose: str, usage, seconds: float) -> None:
        pin, pout = PRICES.get(model, (1.0, 3.0))
        tin = getattr(usage, "prompt_tokens", 0) or 0
        tout = getattr(usage, "completion_tokens", 0) or 0
        with self._lock:
            self.calls.append({
                "model": model, "purpose": purpose, "in": tin, "out": tout,
                "usd": (tin * pin + tout * pout) / 1e6, "seconds": round(seconds, 2),
            })

    def add_tool(self, tool: str, purpose: str, credits: float, usd: float, seconds: float,
                 extra: dict | None = None) -> None:
        """A paid non-model call (Tavily), counted in the same ledger so the cost of a run is complete.
        extra keeps what is needed later, such as a search's request id and result URLs for Tavily feedback."""
        with self._lock:
            self.calls.append({"model": tool, "purpose": purpose, "in": 0, "out": 0, "credits": credits,
                               "usd": usd, "seconds": round(seconds, 2), **(extra or {})})

    def summary(self) -> dict:
        by_model: dict[str, dict] = {}
        for c in self.calls:
            m = by_model.setdefault(c["model"], {"calls": 0, "in": 0, "out": 0, "usd": 0.0})
            m["calls"] += 1
            m["in"] += c["in"]
            m["out"] += c["out"]
            m["usd"] += c["usd"]
            if "credits" in c:
                m["credits"] = m.get("credits", 0) + (c["credits"] or 0)
        # USD is always estimated at Token Factory list prices, so runs on either provider compare directly.
        return {"total_usd": round(sum(c["usd"] for c in self.calls), 5), "by_model": by_model, "provider": PROVIDER,
                "tavily_credits": sum(c.get("credits") or 0 for c in self.calls)}


_client: OpenAI | None = None

# A visitor's own Token Factory key for one run (the hosted demo's credit can run out). It lives only in this
# context variable and the in-memory client cache: never in events, results, logs or on disk.
_run_key: contextvars.ContextVar[str | None] = contextvars.ContextVar("slopproof_run_key", default=None)
_keyed: dict[str, OpenAI] = {}


def use_key(key: str | None) -> None:
    """Send this thread's model calls (and threads started with its copied context) with the given key."""
    _run_key.set(key or None)


def client() -> OpenAI:
    global _client
    key = _run_key.get()
    if key:
        if key not in _keyed:
            _keyed[key] = OpenAI(api_key=key, base_url=BASE_URL, timeout=180, max_retries=3)
        return _keyed[key]
    if _client is None:
        if PROVIDER == "openrouter":
            _client = OpenAI(api_key=os.environ["OPENROUTER_API_KEY"], base_url="https://openrouter.ai/api/v1",
                             timeout=300, max_retries=5)
        else:
            _client = OpenAI(api_key=os.environ["NEBIUS_API_KEY"], base_url=BASE_URL, timeout=180, max_retries=3)
    return _client


def _route(model: str, kw: dict) -> tuple[str, dict]:
    """Translate a Token Factory request for OpenRouter: model id, and thinking on/off as its reasoning flag."""
    if PROVIDER != "openrouter":
        return model, kw
    rid = OPENROUTER_IDS.get(model, model.lower())
    if os.environ.get("SLOPPROOF_OPENROUTER_FREE", "1") == "1":
        rid += ":free"
    extra = dict(kw.pop("extra_body", None) or {})
    thinking = (extra.pop("chat_template_kwargs", None) or {}).get("enable_thinking", True)
    extra["reasoning"] = {"enabled": bool(thinking)}
    return rid, {**kw, "extra_body": extra}


def _create(model: str, messages: list[dict], kw: dict):
    """One completion, waiting out per-minute rate limits (free endpoints allow about 20 requests a minute)."""
    for attempt in range(12):
        try:
            return client().chat.completions.create(model=model, messages=messages, **kw)
        except RateLimitError as e:
            if attempt == 11 or "per-day" in str(e):  # a daily quota does not come back in a minute
                raise
            time.sleep(10 + 5 * attempt)


def chat(tier: str, messages: list[dict], ledger: Ledger, purpose: str, **kw):
    """One chat completion on the given tier. Returns the message object."""
    model, kw = _route(MODELS[tier], kw)
    t0 = time.time()
    try:
        resp = _create(model, messages, kw)
    except NotFoundError:
        if not model.endswith(":free"):
            raise
        # A free OpenRouter endpoint can be missing for a model; the paid one serves the same weights.
        model = model.removesuffix(":free")
        resp = _create(model, messages, kw)
    ledger.add(MODELS[tier], purpose, resp.usage, time.time() - t0)
    if not resp.choices:
        raise ValueError(f"{purpose}: empty response from {model}")
    return resp.choices[0].message


def chat_json(tier: str, system: str, user: str, ledger: Ledger, purpose: str,
              max_tokens: int = 4000, think: bool = False) -> dict:
    """Ask for a JSON object and parse it, retrying once with the parse error.

    Thinking is off by default: Lightning writes its thinking into the content field.
    """
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    extra = {} if think else {"chat_template_kwargs": {"enable_thinking": False}}
    for attempt in range(2):
        if attempt:
            # A long thinking pass can use up the token budget before any JSON; retry without it.
            extra = {"chat_template_kwargs": {"enable_thinking": False}}
        msg = chat(tier, messages, ledger, purpose, max_tokens=max_tokens, temperature=0.2, extra_body=extra)
        text = msg.content or ""
        try:
            return parse_json(text)
        except ValueError as e:
            messages += [{"role": "assistant", "content": text},
                         {"role": "user", "content": f"That was not valid JSON ({e}). Reply with only the JSON object."}]
    raise ValueError(f"{purpose}: model did not return JSON")


def parse_json(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, flags=re.S)
    if m:
        text = m.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("no JSON object found")
    try:
        # strict=False: models often put raw newlines or tabs inside strings (quoted code).
        return json.loads(text[start:end + 1], strict=False)
    except json.JSONDecodeError as e:
        raise ValueError(str(e)) from e
