"""Smoke tests for the foundation: finding schema + tamper-evident audit log."""

from __future__ import annotations

import json

from protocol_siftpp.audit import AuditLogger, verify_chain
from protocol_siftpp.schema import (
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    SkepticReview,
    sha256_hex,
)


def test_finding_roundtrips_with_evidence():
    output = b"PID  PPID  ImageFileName\n4    0     System\n"
    f = Finding(
        claim="Process 'System' (PID 4) is the expected kernel process.",
        severity=Severity.info,
        mitre_attack=[" t1055 "],
        evidence=[
            Evidence(
                tool="vol3.pslist",
                command=["vol", "-f", "mem.raw", "windows.pslist"],
                output_excerpt=output.decode(),
                output_sha256=sha256_hex(output),
                output_bytes=len(output),
            )
        ],
    )
    assert f.mitre_attack == ["T1055"]  # normalized
    assert f.status is FindingStatus.draft
    # pydantic round-trip
    again = Finding.model_validate(json.loads(f.model_dump_json()))
    assert again.evidence[0].output_sha256 == sha256_hex(output)


def test_needs_reinvestigation_on_refute_or_low_confidence():
    f = Finding(claim="x", confidence=0.9, status=FindingStatus.confirmed)
    assert not f.needs_reinvestigation()
    f.status = FindingStatus.refuted
    assert f.needs_reinvestigation()
    f.status = FindingStatus.inferred
    f.confidence = 0.69
    assert f.needs_reinvestigation()
    f.confidence = 0.70
    assert not f.needs_reinvestigation()


def test_skeptic_review_confidence_bounds():
    r = SkepticReview(
        status=FindingStatus.confirmed,
        confidence=1.0,
        refutation_attempt="cross-checked pslist against psscan; no discrepancy",
        rationale="process appears in both views with consistent PPID",
    )
    assert r.confidence == 1.0


def test_audit_chain_is_tamper_evident(tmp_path):
    log = AuditLogger(tmp_path / "audit.jsonl")
    log.iteration(n=1, reason="initial investigation")
    log.tool_call(agent="investigator", tool="vol3.pslist",
                  command=["vol", "-f", "mem.raw", "windows.pslist"],
                  output_sha256="a" * 64, output_bytes=128, duration_ms=42)
    log.evidence_integrity(path="mem.raw", sha256_before="b" * 64,
                           sha256_after="b" * 64)
    ok, n = verify_chain(tmp_path / "audit.jsonl")
    assert ok and n == 3

    # Tamper with a past record -> chain must break.
    p = tmp_path / "audit.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["tool"] = "vol3.malfind"  # falsify what tool was run
    lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok2, _ = verify_chain(p)
    assert not ok2


def test_audit_resumes_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLogger(path).log("a")
    AuditLogger(path).log("b")  # reopen; should continue the chain, not reset
    ok, n = verify_chain(path)
    assert ok and n == 2
