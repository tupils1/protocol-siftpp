"""Test the audit tamper-evidence demo on a real (small) hash-chained log."""

from __future__ import annotations

from protocol_siftpp.audit import AuditLogger
from protocol_siftpp.tamper_test import run_tamper_test


def test_tamper_is_detected(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    log = AuditLogger(audit_path)
    log.log("run_start", evidence_path="mem.raw")
    log.tool_call(agent="investigator", tool="vol_pslist", command=["vol"],
                  output_sha256="a" * 64, output_bytes=10, duration_ms=1)
    log.log("finding_submitted", agent="investigator", finding_id="f1",
            claim="x", confidence=0.8)
    log.log("review_submitted", agent="skeptic", finding_id="f1",
            status="confirmed", confidence=0.9)
    log.log("run_end", findings=1, confirmed=1)

    result = run_tamper_test(audit_path, tmp_path / "out")
    assert result["original_ok"] is True
    assert result["passed"] is True
    assert result["detected"] is True
    assert result["tampered_ok"] is False
    # the break is reported at the tampered record (or earlier-but-not-after)
    assert result["break_detected_at_record"] == result["tampered_record"]
