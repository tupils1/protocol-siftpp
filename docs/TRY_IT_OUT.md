# Try It Out

Protocol SIFT++ has two run paths:

1. A deterministic local replay demo that needs no API key and no forensic image.
2. The real investigation path for a Windows memory image using Volatility 3 and
   the Anthropic API.

## Local replay demo

Run this first to verify the self-correction loop, report writer, and
tamper-evident audit log:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-demo
```

Expected result:

```text
1 confirmed of 2 findings; 1 self-correction iteration(s); evidence integrity verified.
audit log: ... records, hash chain OK
outputs written to analysis\demo/
```

Generated files:

- `analysis/demo/report.md`
- `analysis/demo/report.json`
- `analysis/demo/audit.jsonl`
- `analysis/demo/demo-memory.raw`

The replay demo intentionally starts with an over-claimed injected-code finding.
The Skeptic refutes it, the Investigator re-investigates, and the final report
contains a narrower confirmed finding. This proves the autonomous
self-correction loop, but it is not the final SANS case-data run.

## Real memory-image run

Prerequisites:

- Python 3.11+ with `uv`.
- Volatility 3 installed through this project environment.
- `DEEPSEEK_API_KEY` or `ANTHROPIC_API_KEY` set in the environment.
- A Windows memory image from the SANS sample set.

Download the selected SANS case:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-download-case
```

Use one of the printed `candidate evidence:` paths as `--evidence`.
For the selected case, the expected path is:

```text
evidence\srl-2018-base-file-memory\extracted\base-file-memory.img
```

Run:

```powershell
$env:DEEPSEEK_API_KEY = "<your key>"
C:\Users\Administrator\.local\bin\uv.exe run siftpp-investigate `
  --provider deepseek `
  --evidence evidence\srl-2018-base-file-memory\extracted\base-file-memory.img `
  --out analysis\srl-2018-base-file-memory `
  --case-id srl-2018-base-file-memory `
  --offline `
  --max-iterations 3
```

Outputs:

- `analysis/srl-2018-base-file-memory/report.md`
- `analysis/srl-2018-base-file-memory/report.json`
- `analysis/srl-2018-base-file-memory/audit.jsonl`
- `analysis/srl-2018-base-file-memory/mcp-server.jsonl`

Verify the audit hash chain:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run python -c `
  "from protocol_siftpp.audit import verify_chain; print(verify_chain('analysis/srl-2018-base-file-memory/audit.jsonl'))"
```

The final Devpost demo video should use the real SANS case data, not the replay
demo.
