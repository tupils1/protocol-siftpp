"""Tests for the deterministic local demo runner."""

from __future__ import annotations

import asyncio
import json

from protocol_siftpp.audit import verify_chain
from protocol_siftpp.demo import run_demo
from protocol_siftpp.schema import FindingStatus


def test_demo_run_shows_self_correction(tmp_path):
    result = asyncio.run(run_demo(out=tmp_path / "demo"))
    report = result.report

    assert report.iterations_run == 1
    assert report.by_status(FindingStatus.refuted)
    assert report.by_status(FindingStatus.confirmed)
    assert "evidence integrity verified" in report.summary

    assert result.audit_ok
    ok, n = verify_chain(tmp_path / "demo" / "audit.jsonl")
    assert ok and n == result.audit_records

    report_json = json.loads((tmp_path / "demo" / "report.json").read_text(encoding="utf-8"))
    assert report_json["case_id"] == "demo-self-correction"
    assert (tmp_path / "demo" / "report.md").is_file()
