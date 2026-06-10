# Submission Checklist

Use this before submitting on Devpost.

## Required Deliverables

- [x] Public GitHub repository:
  `https://github.com/tupils1/protocol-siftpp`
- [x] MIT license: `LICENSE`
- [x] Demo video, five minutes max, showing real SANS case data and at least
  one self-correction: `video/PROTOCOL_SIFTPP_DEMO.mp4` (4:06, 1080p screencast
  of live terminal execution on Linux; per-beat breakdown in
  `docs/DEMO_SCRIPT.md`). **Still needs: upload to YouTube/Vimeo/Youku + link
  in the Devpost form.**
- [x] Architecture diagram: `docs/architecture.png` (source: `docs/ARCHITECTURE.md`)
- [x] Written description draft: `docs/DEVPOST_STORY.md` (+ field packet `docs/DEVPOST_SUBMISSION.md`)
- [x] Dataset documentation: `docs/DATASET.md` (SANS SRL-2018 + DigitalCorpora M57)
- [x] Accuracy and integrity report: `docs/ACCURACY_REPORT.md` (SANS proxy F1 0.86; M57 public answer key P/R/F1 1.00)
- [x] Try-it-out instructions: `docs/TRY_IT_OUT.md` (one command: `uv run siftpp-verify`)
- [x] Agent execution logs: committed in `docs/examples/` (audit.jsonl for SANS Windows/Linux + M57; live runs under gitignored `analysis/`)
- [x] Agent execution log summary: `docs/RUN_LOGS.md`

## Demo Video Shot List (all present in the recorded video)

- [x] Linux terminal on screen (`uname -a`), per "built on Linux terminal / SIFT".
- [x] `uv run siftpp-verify`: every check `[PASS]`, `ALL CHECKS PASSED`, no API key.
- [x] Live start of the real SANS investigation (`siftpp-investigate --echo`),
  audit events streaming as they are hash-chained.
- [x] Final run verdict on camera: `4 confirmed of 8 findings; 1 self-correction
  iteration(s); evidence integrity verified.` + `hash chain OK (230 records)`.
- [x] Self-correction sequence replayed from the audit log (`siftpp-trace --replay`):
  downgrades (0.70 -> 0.30), iteration #1, narrower claims confirmed.
- [x] Cross-run hallucination catch: the refuted "DKOM rootkit" section.
- [x] `siftpp-spoliation-test` live: 14/14 refused, evidence sha256 unchanged.
- [x] `siftpp-tamper-test` live: edited record detected.
- [x] M57 public-answer-key case: confirmed keylogger findings (P/R 1.00).
- [x] Close: one-line chain verification of the documented run (302 records).

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
