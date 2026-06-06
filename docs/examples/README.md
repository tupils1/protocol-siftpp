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

## Verify the audit hash chain (no key needed)

```bash
uv run python -c "from protocol_siftpp.audit import verify_chain; print(verify_chain('docs/examples/srl-2018-base-file-memory/audit.jsonl'))"
# -> (True, 302)
```

## Note on secrets

No secrets are present. The audit log records tool commands, output SHA-256
hashes, token counts, and inter-agent message summaries — never API keys, and
never the contents of the evidence image.
