"""Tests for the spoliation-resistance assessment (no subprocess / no key)."""

from __future__ import annotations

import asyncio

from protocol_siftpp.spoliation_test import assess_spoliation


class ReadOnlyMcp:
    """Mimics the real server: only read-only tools, unknown tools raise."""

    anthropic_tools = [
        {"name": "vol_pslist", "description": "", "input_schema": {}},
        {"name": "vol_malfind", "description": "", "input_schema": {}},
        {"name": "evidence_metadata", "description": "", "input_schema": {}},
        {"name": "verify_evidence_integrity", "description": "", "input_schema": {}},
    ]

    async def call(self, name, args=None):
        if name == "verify_evidence_integrity":
            return {"unchanged": True, "sha256_before": "a" * 64, "sha256_after": "a" * 64}
        if name in {"vol_pslist", "vol_malfind", "evidence_metadata"}:
            return {"exit_code": 0, "result": []}
        raise ValueError(f"Tool {name!r} is not an allowed read-only tool")


class LeakyMcp(ReadOnlyMcp):
    """A broken server that exposes a dump tool and lets it run -> must FAIL."""

    anthropic_tools = ReadOnlyMcp.anthropic_tools + [
        {"name": "dump_evidence", "description": "", "input_schema": {}},
    ]

    async def call(self, name, args=None):
        if name in {"windows.dumpfiles", "vol_dumpfiles", "dump_evidence"}:
            return {"exit_code": 0, "result": "dumped!"}  # pretends to succeed
        return await super().call(name, args)


def test_read_only_server_passes_spoliation():
    report = asyncio.run(assess_spoliation(ReadOnlyMcp()))
    assert report["passed"] is True
    assert report["exposed_destructive_tools"] == []
    assert report["attempts_refused"] == report["attempts_total"]
    assert report["evidence_unchanged"] is True


def test_leaky_server_fails_spoliation():
    report = asyncio.run(assess_spoliation(LeakyMcp()))
    assert report["passed"] is False
    # the exposed dump tool is flagged AND some destructive attempts "succeed"
    assert "dump_evidence" in report["exposed_destructive_tools"]
    assert report["attempts_refused"] < report["attempts_total"]
