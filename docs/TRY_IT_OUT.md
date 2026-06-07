# Try It Out

Protocol SIFT++ has two run paths:

1. A deterministic replay demo that needs no API key and no forensic image.
2. The real investigation path for the selected SANS memory image.

## Prerequisites

- Python 3.11+.
- `uv`.
- Network access for the first dependency install and case download.
- `DEEPSEEK_API_KEY` or `ANTHROPIC_API_KEY` for the real agent run.

On Windows, this project was verified with:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run pytest
C:\Users\Administrator\.local\bin\uv.exe run ruff check .
```

## Docker Quick Check (no API key)

Judges can verify the no-key path with one container command. It runs the replay
demo, then attacks the read-only MCP server, then tampers with the audit log:

```bash
docker build -t siftpp .
docker run --rm siftpp
```

Expected high-level result:

```text
1 confirmed of 2 findings; 1 self-correction iteration(s); evidence integrity verified.
RESULT: PASS - evidence cannot be altered/dumped/exfiltrated by construction
RESULT: PASS - tampering detected
```

For a real DeepSeek run in Docker, mount the evidence read-only, mount an output
directory, and pass the key as an environment variable:

```bash
docker run --rm \
  -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  -v "$PWD/evidence/srl-2018-base-file-memory/extracted/base-file-memory.img:/evidence/base-file-memory.img:ro" \
  -v "$PWD/analysis-docker:/app/analysis" \
  siftpp \
  sh -lc '.venv/bin/siftpp-investigate \
    --provider deepseek \
    --evidence /evidence/base-file-memory.img \
    --out analysis/srl-2018-base-file-memory \
    --case-id srl-2018-base-file-memory \
    --offline \
    --max-iterations 3'
```

Do not bake `.env` or evidence files into the image; `.dockerignore` excludes
them from the build context.

On Linux or SANS SIFT Workstation, install `uv` and replace the Windows `uv`
path with:

```bash
uv run <command>
```

Linux / SANS SIFT portability is verified by `tools/linux_smoke.sh`, run on
Ubuntu 22.04 (WSL2) in a separate Linux virtual environment (so it does not
collide with the Windows `.venv`):

```bash
bash tools/linux_smoke.sh
```

Verified result on Ubuntu 22.04, uv-managed CPython 3.12.13
(captured in `docs/examples/linux-smoke.txt`):

```text
pytest: 25 passed     ruff: All checks passed
demo:   1 confirmed of 2 findings; 1 self-correction; integrity verified
spoliation: 14/14 destructive attempts refused; evidence unchanged; PASS
```

The real case run itself was performed on Windows; this smoke confirms the code
path (Python + Volatility 3 + MCP) runs unchanged on Linux/SIFT.

## Local Replay Demo

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
The Skeptic refutes it (a caught-and-dropped false positive), the Investigator
re-investigates, and the final report contains a narrower confirmed finding. This
proves the self-correction loop without a paid model or real evidence.

## Forensic-Defensibility Proofs (no key)

Two reproducible tests prove the safety properties by attacking them:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-spoliation-test
C:\Users\Administrator\.local\bin\uv.exe run siftpp-tamper-test
```

- `siftpp-spoliation-test` throws 14 destructive operations (dump, write, delete,
  shell, exfiltrate) at the live MCP server; all are refused and the evidence
  SHA-256 is identical before and after.
- `siftpp-tamper-test` edits one record in the audit log and shows `verify_chain`
  detects the break at that exact record.

Both run on the real SANS artifacts when present, otherwise on a synthetic file.

## Real Memory-Image Run

Download the selected SANS case:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-download-case
```

Expected evidence path:

```text
evidence\srl-2018-base-file-memory\extracted\base-file-memory.img
```

Set credentials. Either export an environment variable:

```powershell
$env:DEEPSEEK_API_KEY = "<your key>"
```

or create a local `.env` file that is not committed:

```text
DEEPSEEK_API_KEY=<your key>
SIFTPP_LLM_PROVIDER=deepseek
```

Run:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-investigate `
  --provider deepseek `
  --evidence evidence\srl-2018-base-file-memory\extracted\base-file-memory.img `
  --out analysis\srl-2018-base-file-memory `
  --case-id srl-2018-base-file-memory `
  --offline `
  --max-iterations 3
```

Expected final result from the submitted run:

```text
4 confirmed of 10 findings; 2 self-correction iteration(s); evidence integrity verified.
audit log: 302 records, hash chain OK
outputs written to analysis\srl-2018-base-file-memory/
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

Expected:

```text
(True, 302)
```

## Linux / SIFT Workstation Notes

The quickest no-key check on Linux/SIFT is `bash tools/linux_smoke.sh` (runs
pytest + the demo + the spoliation test). For the individual commands, the code
path is Python and Volatility 3 based. On Linux/SIFT:

```bash
export UV_PROJECT_ENVIRONMENT=.venv-linux
uv sync
uv run pytest
uv run ruff check .
uv run siftpp-demo
uv run siftpp-download-case
uv run siftpp-investigate \
  --provider deepseek \
  --evidence evidence/srl-2018-base-file-memory/extracted/base-file-memory.img \
  --out analysis/srl-2018-base-file-memory \
  --case-id srl-2018-base-file-memory \
  --offline \
  --max-iterations 3
```

The final Devpost demo video should use the real SANS case data, not only the
replay demo.
