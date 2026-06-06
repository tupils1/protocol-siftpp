"""Tests for the Investigator/Skeptic self-correction loop.

The Anthropic client and the MCP server are faked, so these validate the
orchestration logic (findings, adversarial review, self-correction, audit)
without real API calls or a real memory image.
"""

from __future__ import annotations

import asyncio

from protocol_siftpp.audit import AuditLogger, verify_chain
from protocol_siftpp.orchestrator import Orchestrator
from protocol_siftpp.schema import FindingStatus


class _Block:
    def __init__(self, type, text=None, name=None, input=None, id=None):
        self.type = type
        self.text = text
        self.name = name
        self.input = input or {}
        self.id = id


class _Usage:
    input_tokens = 100
    output_tokens = 50
    cache_read_input_tokens = 0
    cache_creation_input_tokens = 0


class _Resp:
    def __init__(self, content, stop_reason):
        self.content = content
        self.stop_reason = stop_reason
        self.usage = _Usage()


class _Messages:
    def __init__(self, investigator, skeptic):
        self.scripts = {"investigator": list(investigator), "skeptic": list(skeptic)}

    async def create(self, *, system, **kwargs):
        agent = "skeptic" if "Skeptic" in system else "investigator"
        return self.scripts[agent].pop(0)


class FakeAnthropic:
    def __init__(self, investigator, skeptic):
        self.messages = _Messages(investigator, skeptic)


class FakeMcp:
    anthropic_tools = [
        {"name": "vol_pslist", "description": "list procs", "input_schema": {"type": "object", "properties": {}}},
        {"name": "vol_malfind", "description": "injected code", "input_schema": {"type": "object", "properties": {}}},
    ]

    async def call(self, name, args=None):
        if name == "evidence_metadata":
            return {"path": "mem.raw", "sha256": "e" * 64, "bytes": 1024, "read_only": True}
        if name == "verify_evidence_integrity":
            return {"unchanged": True, "sha256_before": "e" * 64, "sha256_after": "e" * 64}
        return {
            "tool": name,
            "command": ["vol", "-q", "-r", "json", "-f", "mem.raw", f"windows.{name[4:]}"],
            "result": [{"PID": 1640, "ImageFileName": "reader_sl.exe"}],
            "output_sha256": "a" * 64,
            "output_bytes": 64,
            "evidence_sha256": "e" * 64,
            "exit_code": 0,
            "duration_ms": 7,
        }


def _finding_call(claim, sev, conf, tools, _id):
    return _Block("tool_use", name="submit_finding", id=_id,
                  input={"claim": claim, "severity": sev, "confidence": conf,
                         "cited_tools": tools, "rationale": "evidence supports it"})


def _review_call(status, conf, _id):
    return _Block("tool_use", name="submit_review", id=_id,
                  input={"status": status, "confidence": conf,
                         "refutation_attempt": "re-ran the cited tools", "rationale": "checked"})


def test_confirmed_finding_happy_path(tmp_path):
    investigator = [
        _Resp([_Block("tool_use", name="vol_pslist", id="t1")], "tool_use"),
        _Resp([_finding_call("PID 1640 reader_sl.exe is malicious", "high", 0.8, ["vol_pslist"], "t2")], "tool_use"),
        _Resp([_Block("text", text="Investigation complete.")], "end_turn"),
    ]
    skeptic = [
        _Resp([_review_call("confirmed", 0.92, "s1")], "tool_use"),
        _Resp([_Block("text", text="done")], "end_turn"),
    ]
    audit = AuditLogger(tmp_path / "audit.jsonl")
    orch = Orchestrator(FakeAnthropic(investigator, skeptic), FakeMcp(), audit, max_iterations=3)
    report = asyncio.run(orch.run(case_id="t"))

    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.status is FindingStatus.confirmed
    assert f.confidence == 0.92  # skeptic's confidence is authoritative
    assert len(f.evidence) == 1 and f.evidence[0].tool == "vol_pslist"
    assert f.evidence[0].output_sha256 == "a" * 64
    assert len(report.confirmed()) == 1
    assert report.iterations_run == 0

    ok, _ = verify_chain(tmp_path / "audit.jsonl")
    assert ok
    import json
    evs = [json.loads(line)["event"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    for required in ("run_start", "model_call", "tool_call", "finding_submitted",
                     "agent_message", "review_submitted", "run_end"):
        assert required in evs, required


def test_refuted_finding_triggers_self_correction(tmp_path):
    investigator = [
        _Resp([_Block("tool_use", name="vol_malfind", id="t1")], "tool_use"),
        _Resp([_finding_call("PID 999 has injected code", "high", 0.7, ["vol_malfind"], "t2")], "tool_use"),
        _Resp([_Block("text", text="done")], "end_turn"),
        # re-investigation round: investigator cannot substantiate, submits nothing
        _Resp([_Block("text", text="I cannot substantiate this; dropping it.")], "end_turn"),
    ]
    skeptic = [
        _Resp([_review_call("refuted", 0.15, "s1")], "tool_use"),
        _Resp([_Block("text", text="done")], "end_turn"),
    ]
    audit = AuditLogger(tmp_path / "audit.jsonl")
    orch = Orchestrator(FakeAnthropic(investigator, skeptic), FakeMcp(), audit, max_iterations=3)
    report = asyncio.run(orch.run(case_id="t2"))

    assert len(report.findings) == 1
    assert report.findings[0].status is FindingStatus.refuted  # hallucination caught
    assert len(report.confirmed()) == 0
    assert report.iterations_run == 1

    import json
    evs = [json.loads(line)["event"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert "iteration" in evs  # self-correction round was logged
    ok, _ = verify_chain(tmp_path / "audit.jsonl")
    assert ok
