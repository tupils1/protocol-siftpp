"""Append-only, tamper-evident audit log (DESIGN.md section 5; deliverable #8).

Every tool call, inter-agent message, and self-correction iteration is written
as one JSON object per line (JSONL). Each record carries a `seq`, a UTC `ts`,
and a `prev_hash` -> `hash` chain, so the log is tamper-evident: editing any
past record breaks the chain for every record after it. `verify_chain()`
re-derives the chain and is used by the tests and the integrity report.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schema import sha256_hex

_GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> str:
    """Deterministic JSON used as the hashed body (key order independent)."""
    return json.dumps(record, sort_keys=True, default=str, ensure_ascii=False)


class AuditLogger:
    """Thread-safe append-only JSONL writer with a hash chain."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = _GENESIS
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
            return record

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
