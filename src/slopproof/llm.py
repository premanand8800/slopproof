"""Nebius Token Factory client with model routing and a cost ledger."""

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

BASE_URL = os.environ.get("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")

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

    def summary(self) -> dict:
        by_model: dict[str, dict] = {}
        for c in self.calls:
            m = by_model.setdefault(c["model"], {"calls": 0, "in": 0, "out": 0, "usd": 0.0})
            m["calls"] += 1
            m["in"] += c["in"]
            m["out"] += c["out"]
            m["usd"] += c["usd"]
        return {"total_usd": round(sum(c["usd"] for c in self.calls), 5), "by_model": by_model}


_client: OpenAI | None = None


def client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(api_key=os.environ["NEBIUS_API_KEY"], base_url=BASE_URL, timeout=180, max_retries=3)
    return _client


def chat(tier: str, messages: list[dict], ledger: Ledger, purpose: str, **kw):
    """One chat completion on the given tier. Returns the message object."""
    model = MODELS[tier]
    t0 = time.time()
    resp = client().chat.completions.create(model=model, messages=messages, **kw)
    ledger.add(model, purpose, resp.usage, time.time() - t0)
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
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as e:
        raise ValueError(str(e)) from e
