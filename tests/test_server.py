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
