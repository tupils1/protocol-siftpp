"""Append-only, tamper-evident audit log (DESIGN.md section 5; deliverable #8).

Every tool call, inter-agent message, and self-correction iteration is written
as one JSON object per line (JSONL). Each record carries a `seq`, a UTC `ts`,
and a `prev_hash` -> `hash` chain, so the log is tamper-evident: editing any
past record breaks the chain for every record after it. `verify_chain()`
re-derives the chain and is used by the tests and the integrity report.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schema import sha256_hex

_GENESIS = "0" * 64

# ANSI styles for --echo live progress (only used when stderr is a tty).
_RESET = "\x1b[0m"
_DIM = "\x1b[2m"
_BOLD = "\x1b[1m"
_CYAN = "\x1b[36m"
_YELLOW = "\x1b[33m"
_GREEN = "\x1b[32m"
_RED = "\x1b[31m"
_MAGENTA = "\x1b[35m"


def _short(text: str, limit: int = 72) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _canonical(record: dict[str, Any]) -> str:
    """Deterministic JSON used as the hashed body (key order independent)."""
    return json.dumps(record, sort_keys=True, default=str, ensure_ascii=False)


class AuditLogger:
    """Thread-safe append-only JSONL writer with a hash chain."""

    def __init__(self, path: str | Path, echo: bool | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = _GENESIS
        if echo is None:
            echo = os.environ.get("SIFTPP_ECHO", "") not in ("", "0")
        self._echo = echo
        self._color = echo and sys.stderr.isatty()
        if self.path.exists():
            self._resume()

    def _resume(self) -> None:
        """Continue an existing log's chain instead of restarting it."""
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if last:
            rec = json.loads(last)
            self._seq = int(rec.get("seq", 0))
            self._prev_hash = rec.get("hash", _GENESIS)

    def log(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            record: dict[str, Any] = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **fields,
                "prev_hash": self._prev_hash,
            }
            record["hash"] = sha256_hex(self._prev_hash + _canonical(record))
            self._prev_hash = record["hash"]
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")
            if self._echo:
                self._echo_line(record)
            return record

    def _echo_line(self, rec: dict[str, Any]) -> None:
        """One compact line per audit event, streamed to stderr (--echo)."""
        print(format_event(rec, color=self._color), file=sys.stderr, flush=True)

    # --- typed convenience helpers -------------------------------------------

    def tool_call(self, *, agent: str, tool: str, command: list[str],
                  output_sha256: str, output_bytes: int, duration_ms: int,
                  exit_code: int = 0, tokens: int | None = None,
                  evidence_sha256: str | None = None) -> dict[str, Any]:
        return self.log("tool_call", agent=agent, tool=tool, command=command,
                        output_sha256=output_sha256, output_bytes=output_bytes,
                        duration_ms=duration_ms, exit_code=exit_code, tokens=tokens,
                        evidence_sha256=evidence_sha256)

    def agent_message(self, *, sender: str, recipient: str, summary: str,
                      tokens: int | None = None) -> dict[str, Any]:
        return self.log("agent_message", sender=sender, recipient=recipient,
                        summary=summary, tokens=tokens)

    def iteration(self, *, n: int, reason: str) -> dict[str, Any]:
        return self.log("iteration", n=n, reason=reason)

    def evidence_integrity(self, *, path: str | Path, sha256_before: str,
                           sha256_after: str) -> dict[str, Any]:
        return self.log("evidence_integrity", path=str(path),
                        sha256_before=sha256_before, sha256_after=sha256_after,
                        unchanged=(sha256_before == sha256_after))


def format_event(rec: dict[str, Any], color: bool = False) -> str:
    """One compact human-readable line for an audit record (--echo, siftpp-trace)."""
    event = rec.get("event", "?")
    style = _DIM
    if event == "tool_call":
        style = _CYAN
        text = (
            f"tool      {rec.get('agent', '?'):<12} {rec.get('tool', '?'):<28} "
            f"{rec.get('duration_ms', 0):>6} ms  sha256 {str(rec.get('output_sha256', ''))[:12]}"
        )
    elif event == "model_call":
        text = (
            f"model     {rec.get('agent', '?'):<12} stop={rec.get('stop_reason')}  "
            f"tokens in/out {rec.get('input_tokens')}/{rec.get('output_tokens')}"
        )
    elif event == "finding_submitted":
        style = _YELLOW
        text = (
            f"finding   {str(rec.get('finding_id', ''))[:8]:<9} [{rec.get('severity', '?')}] "
            f"conf {rec.get('confidence', 0.0):.2f}  {_short(str(rec.get('claim', '')))}"
        )
    elif event == "review_submitted":
        status = str(rec.get("status", "?"))
        style = {"confirmed": _GREEN, "refuted": _BOLD + _RED}.get(status, _YELLOW)
        text = (
            f"review    {str(rec.get('finding_id', ''))[:8]:<9} {status.upper():<10} "
            f"conf {rec.get('confidence', 0.0):.2f}  by skeptic"
        )
    elif event == "agent_message":
        text = (
            f"message   {rec.get('sender', '?')} -> {rec.get('recipient', '?')}  "
            f"{_short(str(rec.get('summary', '')))}"
        )
    elif event == "iteration":
        style = _BOLD + _MAGENTA
        text = f"iteration #{rec.get('n')}  {rec.get('reason', '')}"
    elif event == "run_start":
        style = _GREEN
        text = f"run_start evidence sha256 {str(rec.get('evidence_sha256', ''))[:16]}"
    elif event == "evidence_integrity":
        style = _GREEN
        text = f"integrity evidence unchanged = {rec.get('unchanged')}"
    elif event == "run_end":
        style = _BOLD + _GREEN
        text = (
            f"run_end   {rec.get('confirmed')} confirmed / {rec.get('findings')} findings  "
            f"evidence_unchanged={rec.get('evidence_unchanged')}"
        )
    else:
        text = event
    line = f"[{rec.get('seq', 0):04d}] {text}"
    if color:
        line = f"{style}{line}{_RESET}"
    return line


def verify_chain(path: str | Path) -> tuple[bool, int]:
    """Re-derive the hash chain. Returns (ok, n_records). Proves the audit log
    was not tampered with: any edit to a past record breaks the chain."""
    prev = _GENESIS
    n = 0
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            n += 1
            rec = json.loads(line)
            stored = rec.pop("hash", None)
            if stored != sha256_hex(prev + _canonical(rec)):
                return False, n
            prev = stored
    return True, n
