"""GUI tests: homepage + the live attack endpoints (real read-only MCP server)."""

from __future__ import annotations

from starlette.testclient import TestClient

from protocol_siftpp.gui import app


def test_homepage():
    c = TestClient(app)
    r = c.get("/")
    assert r.status_code == 200
    assert "Protocol SIFT++" in r.text
    assert "Attack it live" in r.text


def test_tamper_endpoint_detects_edit():
    c = TestClient(app)
    r = c.post("/api/tamper")
    assert r.status_code == 200
    assert r.json()["passed"] is True


def test_spoliation_endpoint_refuses_all():
    # Spawns the real read-only MCP server in-process against synthetic evidence.
    c = TestClient(app)
    r = c.post("/api/spoliation")
    assert r.status_code == 200
    assert r.json()["passed"] is True
