"""Audit tamper-evidence test: editing any past record breaks the hash chain.

The audit log is the chain of custody. Each record's hash covers the previous
hash, so changing any historical record invalidates every record after it. This
test verifies the real log, then alters one record in a COPY and shows
verify_chain detects it immediately.

Run:  uv run siftpp-tamper-test            (uses the real run's audit if present)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .audit import verify_chain

REAL_AUDIT = Path("analysis/srl-2018-base-file-memory/audit.jsonl")
DEMO_AUDIT = Path("analysis/demo/audit.jsonl")


def _default_audit() -> Path:
    if REAL_AUDIT.is_file():
        return REAL_AUDIT
    return DEMO_AUDIT


def run_tamper_test(audit: Path, out: Path) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    ok, n = verify_chain(audit)
    if not ok:
        return {"original_ok": False, "records": n, "error": "original chain already broken"}

    lines = audit.read_text(encoding="utf-8").splitlines()
    target = max(1, len(lines) // 2)  # a record in the middle of history
    rec = json.loads(lines[target])
    before = {k: rec.get(k) for k in ("event", "confidence", "status", "tool") if k in rec}
    rec["_tampered_by_test"] = True
    if "confidence" in rec:
        rec["confidence"] = 0.999
    elif "output_sha256" in rec:
        rec["output_sha256"] = "0" * 64
    else:
        rec["event"] = f"{rec.get('event', '')}_altered"
    lines[target] = json.dumps(rec)

    tampered = out / "audit_tampered.jsonl"
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok2, k = verify_chain(tampered)
    return {
        "original_audit": str(audit),
        "original_ok": ok,
        "records": n,
        "tampered_record": target + 1,
        "tampered_field_before": before,
        "tampered_path": str(tampered),
        "tampered_ok": ok2,
        "break_detected_at_record": k,
        "detected": not ok2,
        "passed": ok and not ok2,
    }


def main() -> None:
    p = argparse.ArgumentParser(
        prog="siftpp-tamper-test",
        description="Prove the audit log hash chain is tamper-evident.",
    )
    p.add_argument("--audit", help="Audit JSONL (default: real run if present, else demo)")
    p.add_argument("--out", default="analysis/tamper", help="Output dir for the tampered copy")
    args = p.parse_args()
    audit = Path(args.audit) if args.audit else _default_audit()
    if not audit.is_file():
        raise SystemExit(f"audit log not found: {audit} (run siftpp-demo or the real case first)")

    result = run_tamper_test(audit, Path(args.out))
    print("=== Audit tamper-evidence test ===")
    print(f"original audit: {result.get('original_audit')}")
    print(f"  verify_chain -> ({result.get('original_ok')}, {result.get('records')})")
    if "error" in result:
        raise SystemExit(result["error"])
    print(f"tampered record #{result['tampered_record']} of {result['records']} "
          f"(was {result['tampered_field_before']}) -> {result['tampered_path']}")
    print(f"  verify_chain -> ({result['tampered_ok']}, {result['break_detected_at_record']})")
    if result["passed"]:
        print(f"RESULT: PASS — tampering detected at record {result['break_detected_at_record']}")
    else:
        print("RESULT: FAIL — tampering NOT detected")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
