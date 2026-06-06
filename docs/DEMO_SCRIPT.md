# 5-Minute Demo Script

Target: show autonomous execution, two visible self-correction iterations,
evidence citations, and evidence-integrity proof on real SANS case data.

## 0:00-0:30 Setup

Show the repository and state the case:

```text
Protocol SIFT++ is a self-verifying autonomous DFIR analyst.
It adds an Investigator/Skeptic correction loop and a read-only MCP forensic
tool boundary to the Protocol SIFT idea.
```

Show these files:

- `src/protocol_siftpp/orchestrator.py`
- `src/protocol_siftpp/mcp_server/volatility.py`
- `docs/ARCHITECTURE.md`

## 0:30-1:15 Start Or Show The Real Run

Run the real SANS sample command, or show the completed output if preserving
time for the video:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-investigate `
  --provider deepseek `
  --evidence evidence\srl-2018-base-file-memory\extracted\base-file-memory.img `
  --out analysis\srl-2018-base-file-memory `
  --case-id srl-2018-base-file-memory `
  --offline `
  --max-iterations 3
```

Expected final output:

```text
4 confirmed of 10 findings; 2 self-correction iteration(s); evidence integrity verified.
audit log: 302 records, hash chain OK
outputs written to analysis\srl-2018-base-file-memory/
```

Do not show API keys in the terminal.

For local rehearsals only:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-demo --out analysis\demo
```

## 1:15-2:30 Show The Self-Correction

Use the audit log:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run python -c `
  "import json; p='analysis/srl-2018-base-file-memory/audit.jsonl'; [print(e['seq'], e['event'], e.get('n'), e.get('reason'), e.get('finding_id'), e.get('status'), e.get('confidence')) for e in map(json.loads, open(p, encoding='utf-8')) if e['event'] in ('finding_submitted','review_submitted','iteration')]"
```

Point out:

- `review_submitted` for `ngentask.exe` with `status=inferred`,
  confidence `0.65`.
- `iteration` event 202: `1 finding(s) refuted/low-confidence -> re-investigate`.
- revised `ngentask.exe` finding, then another `status=inferred`, confidence
  `0.55`.
- `iteration` event 253.
- final narrower `ngentask.exe` finding with `status=confirmed`, confidence
  `0.85`.

Narration:

```text
The first claim was not accepted because it sounded plausible.
The Skeptic reran the tools, separated confirmed network/process facts from
unsupported malware attribution, and forced two reinvestigation rounds.
```

## 2:30-3:45 Show The Report

Open `analysis/srl-2018-base-file-memory/report.md`.

Show:

- 4 confirmed findings.
- 6 inferred findings.
- The corrected `ngentask.exe` finding.
- Tool-output SHA-256 citations.
- ATT&CK mappings.

Key finding to narrate:

```text
The strongest corrected finding is not "ngentask.exe is definitely malware."
It is the narrower confirmed behavior: ngentask.exe lived for one second and
made two connections to the same 172.16.4.10:8080 destination contacted by the
PowerShell chain.
```

## 3:45-4:30 Show The Guardrail

Open `src/protocol_siftpp/mcp_server/volatility.py`.

Show:

- `READ_ONLY_PLUGINS`
- no generic command runner
- no dump/write plugins
- fixed argv list
- `stdin=subprocess.DEVNULL`
- evidence integrity checks before and after tool calls

Narration:

```text
The agent cannot be prompted into dumping, editing, deleting, or uploading
evidence because those capabilities are absent from the MCP server.
```

## 4:30-5:00 Close

Show audit verification:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run python -c `
  "from protocol_siftpp.audit import verify_chain; print(verify_chain('analysis/srl-2018-base-file-memory/audit.jsonl'))"
```

Expected:

```text
(True, 302)
```

Close with:

```text
Protocol SIFT++ does not rely on a prompt saying "be careful".
It makes destructive actions unavailable, verifies every finding adversarially,
and writes a tamper-evident evidence trail.
```
