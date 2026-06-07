# 5-Minute Demo Script

Target: show autonomous execution, two visible self-correction iterations,
evidence citations, and evidence-integrity proof on real SANS case data.

## 0:00-0:30 Setup

Show the repository and state the case:

```text
This is the autonomous DFIR agent you can defend in court: it physically cannot
alter evidence, it catches its own hallucinations, and it shows you its accuracy,
including its misses. Watch me prove all three.
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

## 3:45-4:30 Attack It Live (strongest segment)

Don't just describe the guardrail — try to break it on camera.

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-spoliation-test
```

Expected:

```text
tools exposed: 11; destructive tools exposed: 0
destructive attempts refused: 14/14
evidence sha256 before/after identical
RESULT: PASS - evidence cannot be altered/dumped/exfiltrated by construction
```

Then prove the chain of custody is tamper-evident:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-tamper-test
```

Expected:

```text
verify_chain -> (True, 302)
... tamper one record ...
verify_chain -> (False, 152)
RESULT: PASS - tampering detected at record 152
```

Optionally show `READ_ONLY_PLUGINS` and `stdin=subprocess.DEVNULL` in
`src/protocol_siftpp/mcp_server/volatility.py`.

Narration:

```text
I just tried to make the agent dump, delete, and exfiltrate the evidence - all
fourteen attempts failed, because those capabilities do not exist in the server.
Then I edited one line of the audit log and the hash chain caught it instantly.
This is forensic defensibility you can verify, not a prompt that says be careful.
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
