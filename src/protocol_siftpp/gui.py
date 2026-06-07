"""Local web GUI for Protocol SIFT++ (no build step, no external assets).

Its hero feature is the *live attack panel*: a reviewer clicks a button and the
real read-only MCP server refuses every destructive attempt (evidence unchanged),
and editing the audit log is detected by the hash chain. It also serves the
rendered HTML report for each run.

    uv run siftpp-gui        # then open http://127.0.0.1:8732
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from .mcp_client import McpForensics
from .report_html import audit_summary, render_html
from .spoliation_test import _server_params, assess_spoliation
from .tamper_test import run_tamper_test


def discover_runs() -> dict[str, Path]:
    runs: dict[str, Path] = {}
    for base in (Path("docs/examples"), Path("analysis")):
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            if d.is_dir() and (d / "report.json").is_file():
                runs[d.name] = d
    return runs


def _pick_audit() -> Path | None:
    for p in (Path("analysis/srl-2018-base-file-memory/audit.jsonl"),
              Path("docs/examples/srl-2018-base-file-memory/audit.jsonl"),
              Path("analysis/demo/audit.jsonl")):
        if p.is_file():
            return p
    return None


HOME_CSS = """
body{font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0d1117;color:#e6edf3}
.wrap{max-width:900px;margin:0 auto;padding:32px 20px 60px}
h1{margin:0 0 4px;font-size:26px}.sub{color:#8b949e}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:18px;margin:16px 0}
.guar{display:flex;gap:8px;align-items:flex-start;margin:6px 0}.guar b{color:#fff}
button{font:600 15px inherit;color:#fff;background:#1f6feb;border:0;border-radius:8px;padding:11px 16px;cursor:pointer;margin:6px 8px 6px 0}
button.danger{background:#cf222e}button.warn{background:#9a6700}
.out{white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:12px;margin-top:8px;min-height:22px}
.ok{color:#3fb950;font-weight:700}.bad{color:#f85149;font-weight:700}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
.runs li{margin:6px 0}
.tag{display:inline-block;background:#21262d;border:1px solid #30363d;border-radius:999px;padding:1px 10px;font-size:12px;color:#8b949e}
"""

HOME_JS = """
async function attack(ep, el){
  el.textContent = 'running real attack against the live read-only server…';
  try{
    const r = await fetch(ep, {method:'POST'});
    const j = await r.json();
    el.innerHTML = j.html;
  }catch(e){ el.textContent = 'error: ' + e; }
}
"""


def home_html() -> str:
    runs = discover_runs()
    run_items = "".join(
        f'<li><a href="/run/{r}">{r}</a> <span class="tag">report</span></li>' for r in runs
    ) or "<li>(no runs found — run an investigation or open docs/examples)</li>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Protocol SIFT++ — control room</title><style>{HOME_CSS}</style></head>
<body><div class="wrap">
<h1>Protocol SIFT++</h1>
<div class="sub">Self-verifying, forensically-defensible autonomous DFIR — verify the claims yourself, no API key.</div>

<div class="card">
  <div class="guar"><span>🛡️</span><div><b>It cannot alter evidence.</b> Destructive actions don't exist in the tool server.</div></div>
  <div class="guar"><span>🔗</span><div><b>Tamper-evident chain of custody.</b> Editing any audit record breaks the hash chain.</div></div>
  <div class="guar"><span>🤖</span><div><b>It argues with itself.</b> An adversarial Skeptic refutes every finding (see reports below).</div></div>
</div>

<div class="card">
  <h3>Attack it live</h3>
  <p class="sub">These run the real read-only MCP server in-process — not canned output.</p>
  <button class="danger" onclick="attack('/api/spoliation', document.getElementById('o1'))">🔪 Try to dump / delete / exfiltrate the evidence</button>
  <div id="o1" class="out"></div>
  <button class="warn" onclick="attack('/api/tamper', document.getElementById('o2'))">✎ Tamper with the audit log</button>
  <div id="o2" class="out"></div>
</div>

<div class="card">
  <h3>Investigation reports</h3>
  <ul class="runs">{run_items}</ul>
</div>
</div><script>{HOME_JS}</script></body></html>"""


async def homepage(request: Any) -> HTMLResponse:
    return HTMLResponse(home_html())


async def run_report(request: Any) -> HTMLResponse:
    name = request.path_params["name"]
    runs = discover_runs()
    if name not in runs:
        return HTMLResponse("<p>unknown run</p>", status_code=404)
    d = runs[name]
    report = json.loads((d / "report.json").read_text(encoding="utf-8"))
    return HTMLResponse(render_html(report, audit_summary(d / "audit.jsonl")))


async def api_spoliation(request: Any) -> JSONResponse:
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        evidence = out / "synthetic-evidence.bin"
        evidence.write_bytes(b"SYNTHETIC EVIDENCE\n" * 64)
        params = _server_params(evidence, out / "mcp.jsonl")
        async with McpForensics(params) as mcp:
            report = await assess_spoliation(mcp)
    integ = report["server_integrity"]
    cls = "ok" if report["passed"] else "bad"
    html = (
        f'tools exposed: {len(report["tool_surface"])} · '
        f'destructive tools exposed: {len(report["exposed_destructive_tools"])}\n'
        f'destructive attempts refused: <b>{report["attempts_refused"]}/{report["attempts_total"]}</b>\n'
        f'evidence sha256 before: {integ.get("sha256_before","")[:24]}…\n'
        f'evidence sha256 after:  {integ.get("sha256_after","")[:24]}…\n'
        f'evidence unchanged: {report["evidence_unchanged"]}\n'
        f'<span class="{cls}">RESULT: {"PASS — evidence cannot be altered/dumped/exfiltrated by construction" if report["passed"] else "FAIL"}</span>'
    )
    return JSONResponse({"html": html, "passed": report["passed"]})


async def api_tamper(request: Any) -> JSONResponse:
    audit = _pick_audit()
    if audit is None:
        return JSONResponse({"html": '<span class="bad">no audit log found — run a case or the demo first</span>'})
    with tempfile.TemporaryDirectory() as td:
        result = run_tamper_test(audit, Path(td))
    cls = "ok" if result.get("passed") else "bad"
    html = (
        f'original audit: {result.get("original_audit")}\n'
        f'  verify_chain -> ({result.get("original_ok")}, {result.get("records")})\n'
        f'edited record #{result.get("tampered_record")} of {result.get("records")} '
        f'(was {result.get("tampered_field_before")})\n'
        f'  verify_chain -> ({result.get("tampered_ok")}, {result.get("break_detected_at_record")})\n'
        f'<span class="{cls}">RESULT: {"PASS — tampering detected" if result.get("passed") else "FAIL"}</span>'
    )
    return JSONResponse({"html": html, "passed": bool(result.get("passed"))})


app = Starlette(routes=[
    Route("/", homepage),
    Route("/run/{name}", run_report),
    Route("/api/spoliation", api_spoliation, methods=["POST"]),
    Route("/api/tamper", api_tamper, methods=["POST"]),
])


def main() -> None:
    p = argparse.ArgumentParser(prog="siftpp-gui", description="Local web GUI for Protocol SIFT++.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8732)
    args = p.parse_args()
    print(f"Protocol SIFT++ GUI -> http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
