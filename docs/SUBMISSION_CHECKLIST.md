# Submission Checklist

Use this before submitting on Devpost.

## Required Deliverables

- [x] Public GitHub repository:
  `https://github.com/tupils1/protocol-siftpp`
- [x] MIT license: `LICENSE`
- [ ] Demo video, five minutes max, showing real SANS case data and at least
  one self-correction.
- [x] Architecture diagram: `docs/architecture.png` (source: `docs/ARCHITECTURE.md`)
- [x] Written description draft: `docs/DEVPOST_STORY.md` (+ field packet `docs/DEVPOST_SUBMISSION.md`)
- [x] Dataset documentation: `docs/DATASET.md` (SANS SRL-2018 + DigitalCorpora M57)
- [x] Accuracy and integrity report: `docs/ACCURACY_REPORT.md` (SANS proxy F1 0.86; M57 public answer key P/R/F1 1.00)
- [x] Try-it-out instructions: `docs/TRY_IT_OUT.md` (one command: `uv run siftpp-verify`)
- [x] Agent execution logs: committed in `docs/examples/` (audit.jsonl for SANS Windows/Linux + M57; live runs under gitignored `analysis/`)
- [x] Agent execution log summary: `docs/RUN_LOGS.md`

## Demo Video Shot List

- [ ] Show GitHub repo and project name.
- [ ] Run `uv run siftpp-verify`: one command, every check `[PASS]`, `ALL CHECKS PASSED`.
- [ ] Show the real SANS case command.
- [ ] Show final run summary:
  `4 confirmed of 10 findings; 2 self-correction iteration(s); evidence integrity verified.`
- [ ] Show audit events for the two `ngentask.exe` correction iterations.
- [ ] Show `report.md` with confirmed and inferred findings.
- [ ] Run `siftpp-spoliation-test` live: 14/14 destructive attempts refused, evidence sha256 unchanged.
- [ ] Run `siftpp-tamper-test` live: edit one record -> `verify_chain` -> `(False, 152)`.
- [ ] Show `READ_ONLY_PLUGINS` and evidence-integrity checks.
- [ ] Show audit hash-chain verification result: `(True, 302)`.
- [ ] Show the second public case (M57): confirmed findings match the documented keylogger (precision/recall 1.00).
- [ ] (Optional) `uv run siftpp-gui` -> click the live attack button, watch 14/14 refused.

## Final Local Checks

One command runs the whole proof suite (tests + all three audit chains + live
spoliation + tamper):

```powershell
uv run siftpp-verify
```

Granular equivalents, if needed:

```powershell
uv run pytest
uv run ruff check .
uv run siftpp-spoliation-test
uv run siftpp-tamper-test
```

## Do Not Submit

- API keys.
- `.env`.
- Raw evidence image unless Devpost explicitly requests it.
- Large generated analysis directories in git.
