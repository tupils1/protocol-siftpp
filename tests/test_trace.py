"""siftpp-trace: chain verification + readable timeline of an audit log."""

import sys

import pytest

from protocol_siftpp.audit import AuditLogger
from protocol_siftpp.trace import main


def _write_log(path):
    log = AuditLogger(path)
    log.log("run_start", evidence_sha256="ab" * 32)
    log.tool_call(agent="investigator", tool="vol3.pslist",
                  command=["vol", "windows.pslist"],
                  output_sha256="a" * 64, output_bytes=10, duration_ms=3)
    log.log("finding_submitted", agent="investigator", finding_id="f1",
            claim="Suspicious process", severity="high", confidence=0.9)
    log.log("review_submitted", agent="skeptic", finding_id="f1",
            status="refuted", confidence=0.2)


def test_trace_story_hides_tool_calls(tmp_path, capsys, monkeypatch):
    path = tmp_path / "audit.jsonl"
    _write_log(path)
    monkeypatch.setattr(sys, "argv", ["siftpp-trace", str(path)])
    main()
    out = capsys.readouterr().out
    assert "hash chain OK (4 records)" in out
    assert "Suspicious process" in out and "REFUTED" in out
    assert "vol3.pslist" not in out  # story view skips tool calls


def test_trace_all_shows_tool_calls_and_broken_chain_exits(tmp_path, capsys, monkeypatch):
    path = tmp_path / "audit.jsonl"
    _write_log(path)
    monkeypatch.setattr(sys, "argv", ["siftpp-trace", "--all", str(path)])
    main()
    assert "vol3.pslist" in capsys.readouterr().out

    # Corrupt one record -> trace must report BROKEN and exit non-zero.
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("vol3.pslist", "vol3.malfind")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["siftpp-trace", str(path)])
    with pytest.raises(SystemExit):
        main()
    assert "BROKEN" in capsys.readouterr().out
