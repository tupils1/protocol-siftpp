# 5-Minute Demo Script (read-aloud)

Read each **SAY** line aloud; perform each **DO** action on screen. Times are
cumulative; target ~5:00. Every command is **no-API-key** and copy-pastes from
the README.

**Pre-stage (before recording):** run `uv sync`; in a second terminal start the
GUI with `uv run siftpp-gui` (so it's instant when you switch to it); use a large
terminal font; make sure no API key is visible on screen.

---

## 0:00-0:25 - Hook
**DO:** Show the GitHub repo (the README scorecard at the top).
**SAY:**
> "This is Protocol SIFT++, an autonomous memory-forensics agent built for one
> thing: being trustworthy enough to run unsupervised on evidence. It makes three
> claims — it cannot alter evidence, it catches its own mistakes, and it keeps a
> tamper-evident chain of custody. I'm going to prove all three, live, in five
> minutes."

## 0:25-1:15 - One command, everything green
**DO:** Run:
```bash
uv run siftpp-verify
```
**DO:** Let the `[PASS]` checklist finish.
**SAY:**
> "One command runs the whole proof suite. The tests pass. All three real-case
> audit logs verify — our SANS case on Windows and on Linux, plus an independent
> public case. The live spoliation test refused fourteen of fourteen attacks with
> the evidence unchanged, and the tamper test caught an edited record. No API key
> — anyone can run this from the README."

## 1:15-2:20 - Attack it live (the hero beat)
**DO:** Switch to the browser at `http://127.0.0.1:8732`. Click
**"Try to dump / delete / exfiltrate the evidence."**
**SAY:**
> "Most agents just promise they'll behave. Watch me try to make this one
> misbehave. I'm telling the live server to dump memory, delete the image, run a
> shell, and exfiltrate — everything a hijacked agent would attempt."
**DO:** Point at the green result (14/14 refused, evidence unchanged).
**SAY:**
> "Fourteen of fourteen refused — because those tools physically don't exist in
> the read-only server. The evidence's SHA-256 is identical before and after.
> That's an architectural guarantee, not a prompt."
**DO:** Click **"Tamper with the audit log."**
**SAY:**
> "Now I edit one record in the audit log. The hash chain catches it instantly,
> broken at the exact record. That is a court-grade chain of custody."

## 2:20-3:25 - It catches its own hallucination (the flagship)
**DO:** Open `docs/examples/srl-2018-linux/report.md`; scroll to the **Refuted** section.
**SAY:**
> "Here's the part I'm proudest of. On the SANS case, the agent first *confirmed*
> a kernel rootkit — DKOM process hiding — at 0.92 confidence. It looked right:
> the process list was empty while pool scanning found 101 processes."
**SAY:**
> "But on an independent re-run, the Skeptic refuted its own conclusion. It caught
> an impossible value — zero processors — and that *every* process was missing,
> including System. Real rootkits hide specific processes; hiding all of them
> would crash the machine. The real answer was a Volatility symbol artifact, not a
> rootkit. The system caught its own confident mistake. That is the whole point."

## 3:25-4:20 - Proven on a public answer key (M57)
**DO:** Open `docs/examples/m57-pat-2009-12-05/report.md`.
**SAY:**
> "To show the accuracy isn't self-graded, we ran a second, independent, publicly
> documented case — DigitalCorpora's M57. Its documented compromise is the
> Advanced Keylogger, and the agent confirmed exactly that: the keylogger process
> and its DLL injected into the Windows shell."
**SAY:**
> "Against that public answer key, the confirmed findings score precision and
> recall of one-point-zero. And just as important, it refused to confirm what this
> image can't prove — like exfiltration — leaving those as inferred. High
> accuracy, without overstating."

## 4:20-5:00 - Close
**DO:** Run:
```bash
uv run python -c "from protocol_siftpp.audit import verify_chain; print(verify_chain('docs/examples/srl-2018-base-file-memory/audit.jsonl'))"
```
**DO:** Show `(True, 302)`.
**SAY:**
> "Every finding cites the exact command and the SHA-256 of its output, written
> into the hash-chained log you just watched verify clean. Protocol SIFT++ doesn't
> ask you to trust it — it lets you attack it, check it, and reproduce it. That's
> autonomous incident response a senior analyst, and a court, could actually rely
> on. Thanks for watching."

---

## Backup beat (if a command is slow or you have spare time)
Show the self-correction trace from the real audit log:
```bash
uv run python -c "import json; p='docs/examples/srl-2018-base-file-memory/audit.jsonl'; [print(e['seq'], e['event'], e.get('finding_id'), e.get('status'), e.get('confidence')) for e in map(json.loads, open(p, encoding='utf-8')) if e['event'] in ('finding_submitted','review_submitted','iteration')]"
```
This prints the `ngentask.exe` correction: the Investigator over-claimed C2, the
Skeptic downgraded it twice across two `iteration` events, and it converged on a
narrower confirmed behavioral claim.
