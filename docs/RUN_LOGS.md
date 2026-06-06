# Agent Execution Logs

The final real SANS case run writes two JSONL logs:

- `analysis/srl-2018-base-file-memory/audit.jsonl`
- `analysis/srl-2018-base-file-memory/mcp-server.jsonl`

These logs are generated artifacts and are not committed to git because the
`analysis/` directory is ignored. They should be included with the Devpost
submission package or shown in the demo video.

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

## Verify The Hash Chain

```powershell
C:\Users\Administrator\.local\bin\uv.exe run python -c `
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

## Extract A Short Demo View

```powershell
C:\Users\Administrator\.local\bin\uv.exe run python -c `
  "import json; p='analysis/srl-2018-base-file-memory/audit.jsonl'; [print(e['seq'], e['event'], e.get('n'), e.get('reason'), e.get('finding_id'), e.get('status'), e.get('confidence')) for e in map(json.loads, open(p, encoding='utf-8')) if e['event'] in ('finding_submitted','review_submitted','iteration')]"
```

Use this in the video to show inter-agent review and self-correction without
scrolling through the full 302-record log.
