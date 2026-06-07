# Example Artifacts (real run)

These are the **actual outputs** of the final autonomous run on the real SANS
sample (`SRL-2018 / base-file-memory.img`, sha256 `4c192e5d…`), committed so
reviewers can inspect real results without downloading the 318 MB image or
spending API tokens. The live `analysis/` directory is gitignored (generated,
large), so these curated copies are the in-repo evidence.

## Files

- `srl-2018-base-file-memory/report.md` — human-readable incident report
  (4 confirmed, 6 inferred findings).
- `srl-2018-base-file-memory/report.json` — structured findings
  (schema: `src/protocol_siftpp/schema.py`).
- `srl-2018-base-file-memory/audit.jsonl` — tamper-evident agent execution log,
  302 records (this is required deliverable #8).
- `spoliation_report.json` — result of `siftpp-spoliation-test` on the real
  image: 14/14 destructive attempts refused, evidence SHA-256 unchanged.
- `srl-2018-linux/` — independent **Linux** re-run (Ubuntu 22.04), same image
  (sha256-identical). 2 confirmed of 8; audit `(True, 256)`. Its report
  **refutes** the DKOM claim the Windows run confirmed — a real caught over-claim.
- `m57-pat-2009-12-05/` - second independent public **Windows** memory case
  (DigitalCorpora M57 Pat). 4 confirmed of 9; 2 self-correction iterations;
  audit `(True, 265)`. Its report downgrades over-strong exfiltration and
  persistence claims, then confirms narrower facts.
- `linux-volcheck.txt`, `linux-smoke.txt`, `linux-realrun.log` — Linux
  Volatility/portability verification + run logs.

## Verify the audit hash chain (no key needed)

```bash
uv run python -c "from protocol_siftpp.audit import verify_chain; print(verify_chain('docs/examples/srl-2018-base-file-memory/audit.jsonl'))"
# -> (True, 302)

uv run python -c "from protocol_siftpp.audit import verify_chain; print(verify_chain('docs/examples/m57-pat-2009-12-05/audit.jsonl'))"
# -> (True, 265)
```

## Note on secrets

No secrets are present. The audit log records tool commands, output SHA-256
hashes, token counts, and inter-agent message summaries — never API keys, and
never the contents of the evidence image.
