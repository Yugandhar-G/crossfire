"""Tests for the FastAPI dashboard server (server/main.py)."""

import pytest
from fastapi.testclient import TestClient

from server.main import _rate_windows, app, guardian, manager, store


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset server state between tests."""
    store.events.clear()
    store.server_stats.clear()
    guardian.set_mode("monitor")
    manager.connections.clear()
    _rate_windows.clear()
    yield


client = TestClient(app)


def _make_event(
    event_id: str = "test-1",
    server: str = "demo",
    severity: str = "clean",
    threats: list | None = None,
) -> dict:
    return {
        "id": event_id,
        "timestamp": "2025-01-01T00:00:00Z",
        "protocol": "mcp",
        "direction": "request",
        "server": server,
        "method": "tools/call",
        "params": {},
        "threats": threats or [],
        "severity": severity,
    }


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_post_and_get_events():
    event = _make_event()
    resp = client.post("/api/events", json=event)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["guardian_mode"] == "monitor"

    events = client.get("/api/events").json()
    assert len(events) >= 1
    assert events[0]["id"] == "test-1"


def test_events_filter_by_server():
    client.post("/api/events", json=_make_event("e1", server="alpha"))
    client.post("/api/events", json=_make_event("e2", server="beta"))

    alpha = client.get("/api/events?server=alpha").json()
    assert all(e["server"] == "alpha" for e in alpha)


def test_guardian_get_and_set():
    resp = client.get("/api/guardian")
    assert resp.json()["mode"] == "monitor"

    resp = client.post("/api/guardian", json={"mode": "block"})
    assert resp.status_code == 200
    assert resp.json()["mode"] == "block"

    resp = client.get("/api/guardian")
    assert resp.json()["mode"] == "block"


def test_guardian_rejects_invalid_mode():
    resp = client.post("/api/guardian", json={"mode": "destroy"})
    assert resp.status_code == 422


def test_servers_stats():
    client.post("/api/events", json=_make_event("e1", server="srv-a"))
    client.post("/api/events", json=_make_event("e2", server="srv-b"))

    stats = client.get("/api/servers").json()
    assert stats["total_events"] == 2
    assert "srv-a" in stats["servers"]
    assert "srv-b" in stats["servers"]


def test_health_check_endpoint():
    client.post("/api/events", json=_make_event())
    resp = client.get("/api/health")
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["total_events"] >= 1
    assert body["guardian_mode"] == "monitor"


def test_rate_limit():
    from server.main import _rate_windows, RATE_LIMIT_PER_SECOND

    _rate_windows.clear()

    event = _make_event()
    for i in range(RATE_LIMIT_PER_SECOND):
        event["id"] = f"rate-{i}"
        resp = client.post("/api/events", json=event)
        assert resp.status_code == 200, f"Event {i} should succeed"

    event["id"] = "rate-overflow"
    resp = client.post("/api/events", json=event)
    assert resp.status_code == 429


def test_post_event_with_threats():
    event = _make_event(
        severity="critical",
        threats=[
            {
                "type": "shell_injection",
                "severity": "critical",
                "detail": "curl piped to bash",
                "pattern": "SHELL-INJECT",
            }
        ],
    )
    resp = client.post("/api/events", json=event)
    assert resp.status_code == 200

    stats = client.get("/api/servers").json()
    assert stats["total_threats"] >= 1
