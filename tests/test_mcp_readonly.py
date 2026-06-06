"""Tests for the read-only MCP layer: the architectural guardrail.

These mock the Volatility subprocess, so they verify the *enforcement* (safe
argv, allowlist, evidence integrity, output hashing, audit) without needing a
real memory image.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from protocol_siftpp.audit import AuditLogger, verify_chain
from protocol_siftpp.mcp_server import volatility as V
from protocol_siftpp.schema import sha256_hex


def _make_runner(tmp_path, monkeypatch, stdout=b"[]", returncode=0, stderr=b""):
    evidence = tmp_path / "mem.raw"
    evidence.write_bytes(b"FAKEMEMORY" * 100)
    audit = AuditLogger(tmp_path / "audit.jsonl")
    guard = V.EvidenceGuard.open(evidence)
    runner = V.VolatilityRunner(guard=guard, audit=audit, agent="investigator")
    monkeypatch.setattr(V, "vol_executable", lambda: "vol")
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    monkeypatch.setattr(
        V.subprocess, "run",
        fake_run,
    )
    return runner, evidence, audit, calls


def test_registry_is_read_only_only():
    dumpers = ("dump", "procdump", "memmap", "dumpfiles", "write", "config")
    for spec in V.READ_ONLY_PLUGINS:
        assert spec.plugin.startswith("windows.")
        assert not any(d in spec.plugin.lower() for d in dumpers), spec.plugin
    names = [s.tool for s in V.READ_ONLY_PLUGINS]
    assert len(names) == len(set(names))  # no duplicate tool names


def test_run_builds_safe_argv_and_hashes_full_output(tmp_path, monkeypatch):
    runner, evidence, _, calls = _make_runner(tmp_path, monkeypatch, stdout=b'[{"PID": 4}]')
    res = runner.run("vol_pslist")
    argv = res["command"]
    assert argv[0] == "vol"
    assert "-r" in argv and "json" in argv
    assert "-f" in argv and str(evidence) in argv
    assert "windows.pslist" in argv
    assert "-o" not in argv  # never an output dir -> no disk writes
    assert res["output_sha256"] == sha256_hex(b'[{"PID": 4}]')
    assert res["result"] == [{"PID": 4}]
    assert res["evidence_sha256"] == sha256_hex(b"FAKEMEMORY" * 100)
    assert calls[0][1]["stdin"] is subprocess.DEVNULL

    ok, _ = verify_chain(tmp_path / "audit.jsonl")
    assert ok
    events = [json.loads(line) for line in
              (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    tool_calls = [e for e in events if e["event"] == "tool_call"]
    assert tool_calls and tool_calls[0]["output_sha256"] == sha256_hex(b'[{"PID": 4}]')


def test_non_allowed_tools_are_refused(tmp_path, monkeypatch):
    runner, *_ = _make_runner(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        runner.run("vol_dumpfiles")       # not registered
    with pytest.raises(ValueError):
        runner.run("windows.dumpfiles")   # raw plugin id is not a tool name


def test_pid_validation(tmp_path, monkeypatch):
    runner, *_ = _make_runner(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        runner.run("vol_pslist", pid=5)        # pslist takes no pid
    res = runner.run("vol_dlllist", pid=1234)
    assert "--pid" in res["command"] and "1234" in res["command"]


def test_evidence_integrity_guard_trips_on_tamper(tmp_path, monkeypatch):
    runner, evidence, _, _ = _make_runner(tmp_path, monkeypatch)
    evidence.write_bytes(b"TAMPERED")  # change the image after acquisition
    with pytest.raises(V.IntegrityError):
        runner.run("vol_pslist")


def test_verify_integrity_roundtrip(tmp_path, monkeypatch):
    runner, *_ = _make_runner(tmp_path, monkeypatch)
    out = runner.verify_integrity()
    assert out["unchanged"] is True
    assert out["sha256_before"] == out["sha256_after"]
