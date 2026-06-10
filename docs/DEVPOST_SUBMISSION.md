# Devpost Submission Packet

Copy-paste these into the Devpost project form. Fill `[VIDEO URL]` after recording
the demo. Do **not** upload `.env` or any API key.

## Project name

Protocol SIFT++

## Tagline (one line)

A forensically-defensible autonomous DFIR analyst: read-only by construction,
adversarially self-correcting, with a tamper-evident chain of custody.

## Built With

`python`, `volatility3`, `model-context-protocol (mcp)`, `deepseek` (Anthropic-
compatible API), `anthropic` SDK, `pydantic`, `starlette`, `uvicorn`, `uv`

## Links

- GitHub repo: https://github.com/tupils1/protocol-siftpp
- Demo video: `[VIDEO URL]`
- Try it out: https://github.com/tupils1/protocol-siftpp/blob/main/docs/TRY_IT_OUT.md

## Story

Paste the full contents of `docs/DEVPOST_STORY.md` (Inspiration → What It Does →
Why It Is Defensible → How We Built It → What We Learned → Challenges →
Accomplishments → What Is Next).

## Required-deliverables map (so a judge can tick every box)

| # | Deliverable | Where |
|---|---|---|
| 1 | Public repo (MIT) | repo link above |
| 2 | Demo video (<=5 min, live terminal screencast, real case, >=1 self-correction) | `[VIDEO URL]` — beat-by-beat breakdown: `docs/DEMO_SCRIPT.md`; the on-camera run is committed at `docs/examples/srl-2018-live/` |
| 3 | Architecture diagram | `docs/architecture.png` (source: `docs/ARCHITECTURE.md`) |
| 4 | Written description | the Story above |
| 5 | Dataset documentation | `docs/DATASET.md` |
| 6 | Accuracy + integrity report | `docs/ACCURACY_REPORT.md` |
| 7 | Try-it-out instructions | `docs/TRY_IT_OUT.md` |
| 8 | Agent execution logs | `docs/examples/` — four hash-chain-verified audit logs (302 / 256 / 265 / 230 records), incl. the on-camera demo run; summary in `docs/RUN_LOGS.md` |

## Differentiators to emphasize on the page

1. Read-only by construction — `siftpp-spoliation-test`: 14/14 destructive attempts
   refused, evidence hash unchanged.
2. Tamper-evident chain of custody — `siftpp-tamper-test`: editing one audit record
   is detected by `verify_chain`.
3. Adversarial self-correction — Skeptic refutes/downgrades the Investigator; real
   run forced two `ngentask.exe` revisions; the no-key demo drops a false positive.
4. Quantified accuracy without pretending to have an official answer key: manual
   Volatility-review proxy, cross-run corrected precision 1.00 / recall 0.75 /
   F1 0.86, with DKOM counted as a caught false positive.

## Final pre-submit checklist

See `docs/SUBMISSION_CHECKLIST.md`.
