# Submission Checklist

Use this before submitting on Devpost.

## Required Deliverables

- [x] Public GitHub repository:
  `https://github.com/tupils1/protocol-siftpp`
- [x] MIT license: `LICENSE`
- [ ] Demo video, five minutes max, showing real SANS case data and at least
  one self-correction.
- [x] Architecture diagram: `docs/ARCHITECTURE.md`
- [x] Written description draft: `docs/DEVPOST_STORY.md`
- [x] Dataset documentation: `docs/DATASET.md`
- [x] Accuracy and integrity report: `docs/ACCURACY_REPORT.md`
- [x] Try-it-out instructions: `docs/TRY_IT_OUT.md`
- [x] Agent execution logs generated locally:
  `analysis/srl-2018-base-file-memory/audit.jsonl`
- [x] Agent execution log summary: `docs/RUN_LOGS.md`

## Demo Video Shot List

- [ ] Show GitHub repo and project name.
- [ ] Show the real SANS case command.
- [ ] Show final run summary:
  `4 confirmed of 10 findings; 2 self-correction iteration(s); evidence integrity verified.`
- [ ] Show audit events for the two `ngentask.exe` correction iterations.
- [ ] Show `report.md` with confirmed and inferred findings.
- [ ] Run `siftpp-spoliation-test` live: 14/14 destructive attempts refused, evidence sha256 unchanged.
- [ ] Run `siftpp-tamper-test` live: edit one record -> `verify_chain` -> `(False, 152)`.
- [ ] Show `READ_ONLY_PLUGINS` and evidence-integrity checks.
- [ ] Show audit hash-chain verification result: `(True, 302)`.

## Final Local Checks

```powershell
C:\Users\Administrator\.local\bin\uv.exe run pytest
C:\Users\Administrator\.local\bin\uv.exe run ruff check .
C:\Users\Administrator\.local\bin\uv.exe run siftpp-spoliation-test
C:\Users\Administrator\.local\bin\uv.exe run siftpp-tamper-test
C:\Users\Administrator\.local\bin\uv.exe run python -c `
  "from protocol_siftpp.audit import verify_chain; print(verify_chain('analysis/srl-2018-base-file-memory/audit.jsonl'))"
```

## Do Not Submit

- API keys.
- `.env`.
- Raw evidence image unless Devpost explicitly requests it.
- Large generated analysis directories in git.
