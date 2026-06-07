"""Test the self-contained HTML report renderer."""

from __future__ import annotations

from protocol_siftpp.report_html import render_html


def _report():
    return {
        "case_id": "t-case",
        "evidence_path": "mem.raw",
        "evidence_sha256": "a" * 64,
        "summary": "2 confirmed of 3 findings; integrity verified.",
        "iterations_run": 1,
        "findings": [
            {
                "id": "f1",
                "claim": "PID 4 <script>System</script> is the kernel process",
                "severity": "high",
                "confidence": 0.9,
                "status": "confirmed",
                "mitre_attack": ["T1055"],
                "evidence": [
                    {"tool": "vol_pslist", "output_sha256": "b" * 64, "output_bytes": 10,
                     "command": ["vol"], "output_excerpt": "..."}
                ],
                "review": {"status": "confirmed", "confidence": 0.9,
                           "refutation_attempt": "x", "rationale": "cross-checked psscan"},
                "iteration": 0,
            },
            {
                "id": "f2", "claim": "DKOM rootkit", "severity": "critical", "confidence": 0.2,
                "status": "refuted", "mitre_attack": [], "evidence": [],
                "review": {"status": "refuted", "confidence": 0.2,
                           "refutation_attempt": "re-ran", "rationale": "symbol artifact"},
                "iteration": 1,
            },
        ],
    }


def test_render_html_has_sections_and_escapes():
    html = render_html(_report(), {"ok": True, "records": 9, "kinds": {"model_call": 3, "tool_call": 5}})
    assert "t-case" in html
    assert "Confirmed (1)" in html and "Refuted (1)" in html
    assert "vol_pslist" in html
    assert "audit hash chain OK" in html
    # user-controlled text must be HTML-escaped (no raw injection)
    assert "<script>System</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_html_without_audit():
    html = render_html(_report(), None)
    assert "<html" in html and "Summary" in html
