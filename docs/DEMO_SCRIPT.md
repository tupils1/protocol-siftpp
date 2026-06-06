# 5-Minute Demo Script

Target: show autonomous execution, one visible self-correction, evidence
citations, and evidence-integrity proof.

## 0:00-0:30 Setup

Show the repository and state the case:

```text
Protocol SIFT++ is a self-verifying autonomous DFIR analyst.
The key difference is the Investigator/Skeptic loop plus a read-only MCP
forensic tool boundary.
```

## 0:30-1:15 Start The Run

For the final submission, run the real SANS sample command:

```powershell
$env:DEEPSEEK_API_KEY = "<your key>"
C:\Users\Administrator\.local\bin\uv.exe run siftpp-investigate `
  --provider deepseek `
  --evidence evidence\srl-2018-base-file-memory\extracted\base-file-memory.img `
  --out analysis\final-demo `
  --case-id srl-2018-base-file-memory `
  --offline
```

For local rehearsals only:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-demo --out analysis\demo
```

## 1:15-2:30 Show The Self-Correction

Open `analysis/<case>/audit.jsonl` and point out:

- `finding_submitted`
- `review_submitted` with `status=refuted`
- `iteration`
- replacement `finding_submitted`
- final `review_submitted` with `status=confirmed`

Narration:

```text
The first claim is not accepted just because the Investigator said it.
The Skeptic reruns the evidence, refutes the unsupported part, and the
Investigator is forced to re-investigate.
```

## 2:30-3:45 Show The Report

Open `analysis/<case>/report.md`.

Show:

- Confirmed findings.
- Refuted findings.
- Confidence scores.
- Tool-output SHA-256 citations.
- ATT&CK mappings when present.

## 3:45-4:30 Show The Guardrail

Open `src/protocol_siftpp/mcp_server/volatility.py`.

Show:

- `READ_ONLY_PLUGINS`
- no generic command runner
- no dump/write plugins
- fixed argv list
- evidence integrity checks before and after tool calls

## 4:30-5:00 Close

Show the audit verification result:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run python -c `
  "from protocol_siftpp.audit import verify_chain; print(verify_chain('analysis/final-demo/audit.jsonl'))"
```

Close with:

```text
Protocol SIFT++ does not rely on a prompt saying "be careful".
It makes destructive actions unavailable, verifies every finding adversarially,
and writes a tamper-evident evidence trail.
```
