import threading

from fastapi.testclient import TestClient

from slopproof import bundle, server


def test_example_rerun_needs_no_passcode_and_is_shared(monkeypatch):
    gate = threading.Event()

    def fake_verify(b, against, emit):
        gate.wait(5)
        return {"bug_present": True}

    monkeypatch.setattr(server, "SANDBOX_ENABLED", True)
    monkeypatch.setattr(server, "SANDBOX_KEY", "secret")
    monkeypatch.setattr(bundle, "verify", fake_verify)
    monkeypatch.setattr(server, "_verify", {"job": None, "name": None, "at": 0.0})
    c = TestClient(server.app)

    first = c.post("/api/examples/curl-3735184-netrc/verify")
    assert first.status_code == 200 and not first.json().get("joined")
    again = c.post("/api/examples/curl-3735184-netrc/verify")
    assert again.json() == {"job": first.json()["job"], "joined": True}
    other = c.post("/api/examples/curl-4041053-effective-url/verify")
    assert other.status_code == 429
    gate.set()


def test_daily_budget_does_not_limit_passcode_holders(monkeypatch):
    monkeypatch.setattr(server, "DAILY_RUNS", 1)
    monkeypatch.setattr(server, "_runs_today", {"day": "", "n": 0})
    server._count_run()
    import pytest
    with pytest.raises(server.HTTPException):
        server._count_run()
    server._count_run(exempt=True)


def test_visitor_key_reaches_pool_threads_and_is_never_recorded(monkeypatch, tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from slopproof import llm, pipeline

    seen = {}

    def run():
        llm.use_key("visitor-key-123")
        with ThreadPoolExecutor(max_workers=2) as ex:
            seen["pool"] = pipeline._CtxPool(ex).submit(lambda: llm.client().api_key).result()
        seen["thread"] = llm.client().api_key

    t = threading.Thread(target=run)
    t.start()
    t.join()
    assert seen == {"pool": "visitor-key-123", "thread": "visitor-key-123"}
    assert llm._run_key.get() is None  # other threads keep the demo's own key

    monkeypatch.setattr(server, "JOBS_DIR", tmp_path)
    monkeypatch.setattr(server, "triage", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("402 budget")))
    job = server.launch({"title": "t", "body": "b"}, "https://github.com/x/y", False, None, api_key="visitor-key-123")
    for _ in range(50):
        if any(e["stage"] == "error" for e in server.jobs[job]["events"]):
            break
        threading.Event().wait(0.05)
    assert "visitor-key-123" not in (tmp_path / f"{job}.jsonl").read_text()


def test_empty_model_answer_is_retried(monkeypatch):
    from types import SimpleNamespace

    from slopproof import llm

    answers = [SimpleNamespace(choices=[], usage=None),
               SimpleNamespace(choices=[SimpleNamespace(message="ok")], usage=None)]
    monkeypatch.setattr(llm, "_create", lambda model, messages, kw: answers.pop(0))
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    assert llm.chat("fast", [], llm.Ledger(), "test") == "ok"
