"""`siftpp-trace` - human-readable timeline of a tamper-evident audit log.

Verifies the hash chain, then prints one line per audit event. By default it
shows the investigation story (findings, Skeptic reviews, self-correction
iterations, run start/end); `--all` adds every tool and model call.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .audit import format_event, verify_chain

STORY_EVENTS = {
    "run_start",
    "finding_submitted",
    "review_submitted",
    "iteration",
    "evidence_integrity",
    "run_end",
}


def main() -> None:
    p = argparse.ArgumentParser(
        prog="siftpp-trace",
        description="Verify and pretty-print a Protocol SIFT++ audit log.",
    )
    p.add_argument("audit_log", help="Path to audit.jsonl")
    p.add_argument(
        "--all",
        action="store_true",
        help="Show every event (tool calls, model calls), not just the investigation story",
    )
    p.add_argument(
        "--replay",
        action="store_true",
        help="Pause briefly between events, replaying the investigation as a timeline",
    )
    args = p.parse_args()

    path = Path(args.audit_log)
    if not path.is_file():
        raise SystemExit(f"Audit log not found: {path}")

    ok, n = verify_chain(path)
    status = "OK" if ok else "BROKEN"
    print(f"hash chain {status} ({n} records) - {path}")
    if not ok:
        raise SystemExit(2)

    color = sys.stdout.isatty()
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if args.all or rec.get("event") in STORY_EVENTS:
                print(format_event(rec, color=color), flush=args.replay)
                if args.replay:
                    time.sleep(0.12)


if __name__ == "__main__":
    main()
