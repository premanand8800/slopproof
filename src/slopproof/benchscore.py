"""Benchmark scoring: how much slop is auto-closed, and whether any real report is."""

CLOSE = {"NOT_REPRODUCED", "FABRICATED"}


def score(rows: list[dict]) -> dict:
    # "invalid" (held-out reports curl closed as not applicable) is scored like slop: it should not stay on top.
    slop = [r for r in rows if r["label"] in ("slop", "invalid")]
    real = [r for r in rows if r["label"] == "real"]
    caught = [r for r in slop if r["verdict"] in CLOSE]
    wrongly_closed = [r for r in real if r["verdict"] in CLOSE]
    # Closed or marked low priority: what a maintainer can leave until the rest of the queue is done.
    slop_down = [r for r in slop if r["verdict"] in CLOSE or r.get("priority") == "low"]
    real_down = [r for r in real if r["verdict"] in CLOSE or r.get("priority") == "low"]
    counts: dict[str, dict[str, int]] = {}
    for r in rows:
        counts.setdefault(r["label"], {}).setdefault(r["verdict"], 0)
        counts[r["label"]][r["verdict"]] += 1
    return {
        "reports": len(rows),
        "slop_auto_closed": f"{len(caught)}/{len(slop)}",
        "slop_auto_closed_pct": round(100 * len(caught) / max(1, len(slop)), 1),
        "real_wrongly_closed": f"{len(wrongly_closed)}/{len(real)}",
        "real_kept_pct": round(100 * (len(real) - len(wrongly_closed)) / max(1, len(real)), 1),
        "slop_closed_or_low": f"{len(slop_down)}/{len(slop)}",
        "real_closed_or_low": f"{len(real_down)}/{len(real)}",
        "verdicts": counts,
        "avg_usd": round(sum(r["usd"] for r in rows) / max(1, len(rows)), 4),
        "avg_seconds": round(sum(r["seconds"] for r in rows) / max(1, len(rows)), 1),
        "wrongly_closed_ids": [r["id"] for r in wrongly_closed],
        "missed_slop_ids": [r["id"] for r in slop if r["verdict"] not in CLOSE],
    }
