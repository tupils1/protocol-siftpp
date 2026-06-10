# Agent Execution Logs

Runs write append-only JSONL logs (audit + mcp-server). Live runs land under the
gitignored `analysis/`; curated copies for review are committed under
`docs/examples/` and pass `verify_chain` on a fresh clone:

- `docs/examples/srl-2018-base-file-memory/audit.jsonl` - SANS, Windows (302 records)
- `docs/examples/srl-2018-linux/audit.jsonl` - SANS, Linux reproduction (256 records)
- `docs/examples/m57-pat-2009-12-05/audit.jsonl` - DigitalCorpora M57 (265 records)
- `docs/examples/srl-2018-live/audit.jsonl` - SANS, the on-camera demo-video run,
  Linux (230 records)

Verify all four at once: `uv run siftpp-verify`. Pretty-print any of them:
`uv run siftpp-trace <audit.jsonl> [--replay] [--all]`.

## Final Run Summary

```text
case_id: srl-2018-base-file-memory
run_generated_at: 2026-06-06T19:52:29.803172Z
evidence_sha256: 4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
summary: 4 confirmed of 10 findings; 2 self-correction iteration(s); evidence integrity verified.
audit_records: 302
audit_hash_chain: OK
model_calls: 99
tool_calls: 159
input_tokens: 415886
output_tokens: 89065
total_tokens: 504951
```

## Important Audit Events

The audit log contains:

- `run_start`
- `model_call`
- `tool_call`
- `finding_submitted`
- `review_submitted`
- `agent_message`
- `iteration`
- `run_end`

The final run's visible correction sequence:

```text
review_submitted: ngentask.exe claim -> inferred, confidence 0.65
iteration 1: 1 finding(s) refuted/low-confidence -> re-investigate
review_submitted: revised ngentask.exe claim -> inferred, confidence 0.55
iteration 2: 1 finding(s) refuted/low-confidence -> re-investigate
review_submitted: narrowed ngentask.exe behavior claim -> confirmed, confidence 0.85
```

## Additional Runs

```text
Linux reproduction (same image, sha256-identical):
  2 confirmed of 8 findings; 2 self-correction iterations; audit (True, 256).
  The Linux Skeptic refuted the Windows "DKOM rootkit" confirmation as a
  Volatility symbol/KDBG artifact (KeNumberProcessors=0).
M57 Pat (DigitalCorpora, public answer key):
  4 confirmed of 9 findings; 2 self-correction iterations; audit (True, 265).
  Confirmed findings match the documented Advanced Keylogger -> P/R/F1 = 1.00.
Demo-video run (srl-2018-live, recorded on camera, Linux/WSL2 Ubuntu 22.04):
  4 confirmed of 8 findings; 1 self-correction iteration; audit (True, 230).
  22.3 minutes unattended; 79 model calls (358,745 tokens), 116 tool calls.
  The Skeptic downgraded three over-broad claims (one 0.70 -> 0.30) and the
  re-investigated, narrower claims were confirmed (0.82, 0.90).
```

## Verify The Hash Chain

```powershell
uv run python -c `
  "from protocol_siftpp.audit import verify_chain; print(verify_chain('analysis/srl-2018-base-file-memory/audit.jsonl'))"
```

Expected:

```text
(True, 302)
```

## Verify Evidence Integrity

The MCP server log contains the final `evidence_integrity` event:

```text
sha256_before: 4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
sha256_after:  4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
unchanged: true
```

## Replay The Investigation Story

```bash
uv run siftpp-trace docs/examples/srl-2018-live/audit.jsonl --replay
```

Verifies the chain, then prints one line per story event (findings, Skeptic
reviews, iterations, run start/end) — the same view the demo video shows.
Add `--all` to include every tool and model call. During a live run,
`siftpp-investigate --echo` streams the identical lines as they are written.
