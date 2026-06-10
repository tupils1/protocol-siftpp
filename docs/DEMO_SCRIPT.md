# Demo Video — What It Shows, and How to Reproduce Every Beat

The demo is a **screencast of live terminal execution** (per the FIND EVIL!
rules: not slides, not a marketing video). It was recorded in a Linux terminal
(Ubuntu 22.04 / WSL2 — the SANS SIFT Workstation base OS) running the repo
exactly as documented. Keystrokes were auto-typed for pacing, but **every
command executes for real, on the real SANS evidence image**, in one
continuous session per act. There is a single time-cut while the autonomous
run finishes (~22 minutes, marked on screen and in the narration). Narration
is a Microsoft neural TTS voice.

The on-camera investigation (`--case-id srl-2018-live`) is committed in full
at `docs/examples/srl-2018-live/` (report + 230-record audit log), so every
number in the video can be re-verified offline.

## Beat-by-beat

| # | On-screen command | What it proves |
|---|---|---|
| A1 | `uname -a` | Linux terminal, as the rules require |
| A2 | `uv run siftpp-verify` | whole proof suite green in one command, no API key |
| A3 | `uv run siftpp-investigate --provider deepseek --echo --evidence ~/ev/base-file-memory.img --out analysis/srl-2018-live --case-id srl-2018-live` | live autonomous run on the SANS image; `--echo` streams every audit event (tool calls + output SHA-256, model calls + tokens) as it is hash-chained to disk |
| — | *time cut: “the run finished unattended” (22 min)* | |
| B1 | `head -n 6 analysis/srl-2018-live/report.md` | verdict: 4 confirmed of 8 findings, 1 self-correction iteration, evidence integrity verified |
| B2 | `uv run siftpp-trace analysis/srl-2018-live/audit.jsonl --replay` | the self-correction sequence, replayed from the tamper-evident log: Skeptic downgrades (0.7 → 0.3), iteration #1 re-investigates, narrower claims survive |
| B3 | `sed -n '/^## Refuted/,$p' docs/examples/srl-2018-linux/report.md \| head -7` | the flagship catch: an earlier run confirmed a “DKOM rootkit” at 0.92 — an independent Linux re-run **refuted its own confirmation** as a Volatility symbol artifact |
| B4 | `uv run siftpp-spoliation-test` | 14/14 destructive attempts refused live; evidence SHA-256 unchanged |
| B5 | `uv run siftpp-tamper-test` | edit one audit record → hash chain breaks at exactly that record |
| B6 | `sed -n '/^## Confirmed/,/^## Inferred/p' docs/examples/m57-pat-2009-12-05/report.md \| grep -E '^##\|^###' \| head -3` | second, public-answer-key case (M57): confirmed exactly the documented keylogger — precision/recall 1.00 |
| B7 | `uv run siftpp-trace docs/examples/srl-2018-base-file-memory/audit.jsonl \| head -1` | close: any log verifies in one line — `hash chain OK (302 records)` |

## Reproduce it yourself

Everything in the video is a repo command. The no-key path:

```bash
uv run siftpp-verify          # A2: tests + 3 audit chains + spoliation + tamper
uv run siftpp-trace docs/examples/srl-2018-live/audit.jsonl --replay   # B2 on the committed copy
uv run siftpp-spoliation-test # B4
uv run siftpp-tamper-test     # B5
```

The live run (A3/B1) needs a `DEEPSEEK_API_KEY` (or `--provider anthropic`)
and the SANS image from `uv run siftpp-download-case` — see
`docs/TRY_IT_OUT.md`.

## Production notes (transparency)

- Recorded with ffmpeg (gdigrab) from a real WezTerm window running WSL2
  Ubuntu 22.04; 1080p output downscaled from a 2432×1368 capture.
- The auto-typing harness (`video/demo_*.sh`) prints a prompt, types the
  command with human-ish jitter, then `eval`s it — the outputs on screen are
  genuine, unedited tool output.
- One cut joins the start of the autonomous run to its finish; the run kept
  executing unattended in the same terminal between the two takes
  (`video/markers_*.log` carries the wall-clock timestamps).
- Narration: edge-tts `en-US-ChristopherNeural`; subtitles burned from the
  same synthesis pass (`video/captions.srt`).
- After recording, the on-camera run's audit chain was added to
  `siftpp-verify` as a fourth committed chain — so a fresh clone now shows
  four `audit chain` PASS lines where the video shows three.
