"""Render a run's report.json (+ audit.jsonl) into a self-contained HTML report.

No web server, no JS framework, no external assets — one portable .html file you
can open, screenshot, or embed. Also the page the GUI serves.

    uv run siftpp-report --run analysis/srl-2018-base-file-memory
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

from .audit import verify_chain

_STATUS_COLOR = {"confirmed": "#1a7f37", "inferred": "#9a6700", "refuted": "#cf222e", "draft": "#57606a"}
_SEV_COLOR = {"critical": "#cf222e", "high": "#bc4c00", "medium": "#9a6700", "low": "#0969da", "info": "#57606a"}


def audit_summary(audit_path: Path) -> dict[str, Any]:
    if not audit_path.is_file():
        return {}
    ok, n = verify_chain(audit_path)
    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    kinds: dict[str, int] = {}
    for e in events:
        kinds[e.get("event", "?")] = kinds.get(e.get("event", "?"), 0) + 1
    return {"ok": ok, "records": n, "kinds": kinds}


def _esc(x: Any) -> str:
    return html.escape(str(x), quote=True)


def _bar(conf: float) -> str:
    pct = max(0, min(100, round(float(conf) * 100)))
    color = "#1a7f37" if pct >= 80 else "#9a6700" if pct >= 50 else "#cf222e"
    return (
        f'<div class="bar"><div class="fill" style="width:{pct}%;background:{color}"></div>'
        f'<span class="barlbl">{conf:.2f}</span></div>'
    )


def _finding_card(f: dict[str, Any]) -> str:
    status = f.get("status", "draft")
    sev = f.get("severity", "medium")
    atk = "".join(f'<span class="chip">{_esc(t)}</span>' for t in f.get("mitre_attack", []))
    ev = "".join(
        f'<li><code>{_esc(e.get("tool"))}</code> '
        f'<span class="hash">sha256 {_esc(str(e.get("output_sha256", ""))[:16])}…</span></li>'
        for e in f.get("evidence", [])
    )
    review = f.get("review") or {}
    skeptic = (
        f'<div class="skeptic"><b>Skeptic ({_esc(review.get("status", "?"))}, '
        f'{float(review.get("confidence", 0)):.2f}):</b> {_esc(review.get("rationale", ""))}</div>'
        if review else ""
    )
    return f"""
    <div class="card" style="border-left-color:{_SEV_COLOR.get(sev, '#57606a')}">
      <div class="cardtop">
        <span class="badge" style="background:{_STATUS_COLOR.get(status, '#57606a')}">{_esc(status.upper())}</span>
        <span class="sev">{_esc(sev)}</span>
        {_bar(f.get("confidence", 0))}
      </div>
      <div class="claim">{_esc(f.get("claim", ""))}</div>
      <div class="atk">{atk}</div>
      {skeptic}
      <ul class="ev">{ev}</ul>
    </div>"""


def render_html(report: dict[str, Any], audit: dict[str, Any] | None = None) -> str:
    findings = report.get("findings", [])
    by = {s: [f for f in findings if f.get("status") == s] for s in ("confirmed", "inferred", "refuted", "draft")}
    audit = audit or {}
    integrity = ""
    if audit:
        ok = audit.get("ok")
        integrity = (
            f'<span class="pill {"ok" if ok else "bad"}">audit hash chain '
            f'{"OK" if ok else "BROKEN"} · {audit.get("records", 0)} records</span>'
        )
    kinds = audit.get("kinds", {})
    stats = "".join(
        f'<div class="stat"><div class="num">{v}</div><div class="lbl">{_esc(k)}</div></div>'
        for k, v in (
            ("confirmed", len(by["confirmed"])),
            ("inferred", len(by["inferred"])),
            ("refuted", len(by["refuted"])),
            ("iterations", report.get("iterations_run", 0)),
            ("model_calls", kinds.get("model_call", 0)),
            ("tool_calls", kinds.get("tool_call", 0)),
        )
    )
    sections = ""
    for s in ("confirmed", "inferred", "refuted", "draft"):
        if not by[s]:
            continue
        cards = "".join(_finding_card(f) for f in by[s])
        sections += f'<h2 style="color:{_STATUS_COLOR[s]}">{s.capitalize()} ({len(by[s])})</h2>{cards}'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Protocol SIFT++ — {_esc(report.get("case_id", "report"))}</title>
<style>
:root {{ color-scheme: light; }}
* {{ box-sizing: border-box; }}
body {{ font: 15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; margin: 0; background:#f6f8fa; color:#1f2328; }}
.wrap {{ max-width: 980px; margin: 0 auto; padding: 28px 20px 60px; }}
header h1 {{ margin:0 0 4px; font-size: 24px; }}
.sub {{ color:#57606a; font-size: 13px; }}
.meta {{ margin:14px 0; padding:12px 14px; background:#fff; border:1px solid #d0d7de; border-radius:10px; font-size:13px; }}
.meta code {{ word-break: break-all; }}
.pill {{ display:inline-block; padding:2px 10px; border-radius:999px; font-weight:600; font-size:12px; color:#fff; }}
.pill.ok {{ background:#1a7f37; }} .pill.bad {{ background:#cf222e; }}
.stats {{ display:flex; flex-wrap:wrap; gap:10px; margin:14px 0 24px; }}
.stat {{ flex:1 1 120px; background:#fff; border:1px solid #d0d7de; border-radius:10px; padding:12px; text-align:center; }}
.stat .num {{ font-size:24px; font-weight:700; }} .stat .lbl {{ font-size:11px; color:#57606a; text-transform:uppercase; letter-spacing:.04em; }}
.summary {{ background:#fff; border:1px solid #d0d7de; border-radius:10px; padding:12px 14px; margin-bottom:20px; }}
h2 {{ font-size:16px; margin:24px 0 10px; }}
.card {{ background:#fff; border:1px solid #d0d7de; border-left:5px solid #57606a; border-radius:10px; padding:14px 16px; margin:10px 0; }}
.cardtop {{ display:flex; align-items:center; gap:10px; margin-bottom:8px; flex-wrap:wrap; }}
.badge {{ color:#fff; font-weight:700; font-size:11px; padding:2px 8px; border-radius:6px; }}
.sev {{ font-size:12px; color:#57606a; text-transform:uppercase; }}
.bar {{ position:relative; flex:1 1 140px; height:16px; background:#eaeef2; border-radius:8px; min-width:120px; overflow:hidden; }}
.bar .fill {{ height:100%; }}
.bar .barlbl {{ position:absolute; right:6px; top:0; font-size:11px; line-height:16px; color:#1f2328; }}
.claim {{ font-weight:600; margin-bottom:6px; }}
.chip {{ display:inline-block; background:#ddf4ff; color:#0969da; border-radius:6px; padding:1px 7px; font-size:11px; margin:2px 4px 2px 0; }}
.skeptic {{ background:#fff8c5; border:1px solid #eac54f; border-radius:8px; padding:8px 10px; font-size:13px; margin:8px 0; }}
.ev {{ margin:8px 0 0; padding-left:18px; font-size:12px; }}
.hash {{ color:#57606a; font-family:ui-monospace,Menlo,Consolas,monospace; }}
code {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; }}
footer {{ margin-top:30px; color:#57606a; font-size:12px; text-align:center; }}
</style></head>
<body><div class="wrap">
<header>
  <h1>Protocol SIFT++ — Incident Report</h1>
  <div class="sub">Self-verifying autonomous DFIR · case <b>{_esc(report.get("case_id", ""))}</b></div>
</header>
<div class="meta">
  Evidence: <code>{_esc(report.get("evidence_path", ""))}</code><br>
  Evidence SHA-256: <code>{_esc(report.get("evidence_sha256", ""))}</code><br>
  {integrity}
</div>
<div class="stats">{stats}</div>
<div class="summary"><b>Summary.</b> {_esc(report.get("summary", ""))}</div>
{sections}
<footer>Generated from report.json + audit.jsonl · findings are confirmed/inferred/refuted by an adversarial Skeptic; every finding cites a tool command + output SHA-256.</footer>
</div></body></html>"""


def main() -> None:
    p = argparse.ArgumentParser(prog="siftpp-report", description="Render a run to a self-contained HTML report.")
    p.add_argument("--run", required=True, help="Run directory containing report.json (+ audit.jsonl)")
    p.add_argument("--out", help="Output HTML path (default: <run>/report.html)")
    args = p.parse_args()
    run = Path(args.run)
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    audit = audit_summary(run / "audit.jsonl")
    out = Path(args.out) if args.out else run / "report.html"
    out.write_text(render_html(report, audit), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
