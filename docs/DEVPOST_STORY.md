# Devpost Story Draft

## Inspiration

Autonomous incident response has a trust problem — and in forensics, "trust" has
a precise meaning: would this hold up under scrutiny? An agent that moves fast but
can hallucinate findings, or that could accidentally modify the evidence it
touches, is worse than no agent — it contaminates both the investigation and the
chain of custody. So we asked a sharper question than "can an agent find evil?":
can an autonomous DFIR agent be made forensically **defensible** — architecturally
incapable of altering evidence, adversarially self-verifying, and producing a
tamper-evident trail — not merely fast?

## What It Does

Protocol SIFT++ investigates a Windows memory image using a read-only MCP server
that exposes a curated Volatility 3 toolset. The Investigator agent forms
findings from raw tool output. The Skeptic agent independently reruns tools and
attempts to refute each finding. Claims are labeled `confirmed`, `inferred`, or
`refuted`; weak findings are sent back for automatic reinvestigation.

On the selected SANS sample, the final run produced:

```text
4 confirmed of 10 findings; 2 self-correction iteration(s); evidence integrity verified.
audit log: 302 records, hash chain OK
```

An independent Linux reproduction later refuted one Windows-confirmed
`DKOM/rootkit` claim as a Volatility symbol/KDBG artifact. Under the documented
manual-review proxy, the cross-run corrected confirmed set scores precision
1.00, recall 0.75, F1 0.86.

On a second, independent, *publicly documented* case (DigitalCorpora M57), the
confirmed findings match the documented Advanced Keylogger exactly — precision,
recall, and F1 of 1.00 against a real public answer key. A no-build local GUI
(`uv run siftpp-gui`) lets a reviewer run the same attacks and read every report,
and `uv run siftpp-verify` re-checks all of the above in one command.

The most visible correction involved `ngentask.exe`. The Investigator initially
overstated a malware/C2 attribution. The Skeptic downgraded it, the Investigator
reinvestigated, the Skeptic downgraded it again, and the system finally
converged on a narrower confirmed behavioral claim: `ngentask.exe` lived for
one second and made two connections to the same `172.16.4.10:8080` destination
used by the suspicious PowerShell chain.

## Why It Is Defensible (and We Can Prove It)

Three properties, each backed by a reproducible test, not a promise:

1. **It cannot spoliate evidence.** `siftpp-spoliation-test` throws 14 destructive
   operations (dump, write, delete, shell, exfiltrate) at the live server: all 14
   are refused because those capabilities do not exist, and the evidence SHA-256
   is identical before and after. The guardrail is architectural, not a prompt.
2. **Its chain of custody is tamper-evident.** `siftpp-tamper-test` edits one
   record in the 302-record audit log and `verify_chain` flags the break at that
   exact record. Every finding cites the precise tool command and the SHA-256 of
   its full output.
3. **It argues with itself.** The Skeptic independently reruns tools to refute
   each finding; in the reproducible demo it catches and drops a false
   injected-code claim, and on the real case it forced two revisions of an
   over-stated `ngentask.exe` attribution down to a narrower confirmed claim.

## How We Built It

The project is implemented in Python with:

- Volatility 3 for Windows memory analysis.
- A custom read-only MCP forensic server.
- An Investigator/Skeptic orchestrator.
- Pydantic schemas for findings, evidence, reviews, and reports.
- An append-only JSONL audit log with a SHA-256 hash chain.
- DeepSeek through the Anthropic-compatible Messages API.

The MCP server is the security boundary. It has no generic shell, no dumping
plugins, no write-oriented tools, and no upload capability. Each tool call
checks evidence size and mtime before and after execution, records the exact
argv, and hashes the full tool output for later citation.

## What We Learned

The strongest lesson was that correction needs to happen in the loop, not only
in the final report. The first real run downgraded weak claims but did not
reinvestigate them. We changed the orchestrator so low-confidence inferred
findings also trigger reinvestigation. The next real run produced two visible
self-correction iterations and a better final claim.

The selected memory image also forced careful reasoning. Process-list based
plugins returned zero rows, while pool scanning recovered 101 process artifacts
and network scanning recovered 145 sockets. That made it easy for an agent to
over-claim. The Skeptic's job was to keep facts separate from interpretation.

## Challenges

One engineering bug came from running Volatility inside an MCP stdio server. The
Volatility child process initially inherited the MCP stdin pipe, which could
block the server. We fixed this by launching forensic child processes with
`stdin=subprocess.DEVNULL`, keeping the tool process isolated from the MCP
transport.

Another challenge was ground truth. We did not find a public official answer key
for this exact sample artifact, so the accuracy report uses manual Volatility
review plus the Skeptic's independent tool reruns as the ground-truth proxy.

## Accomplishments

- Ran an autonomous real-case investigation on the selected SANS sample.
- Produced two real self-correction iterations.
- Verified evidence integrity with matching before/after SHA-256 hashes.
- Wrote a tamper-evident 302-record audit log.
- Built an architectural guardrail instead of relying only on prompting.
- Documented accuracy limits, missed artifacts, and no-Skeptic baseline behavior.
- Reproduced the investigation end to end on Linux (same image, sha256-identical).
  The re-run's Skeptic refuted a "DKOM rootkit" claim the Windows run had
  confirmed, correctly identifying it as a Volatility symbol-resolution artifact
  (`KeNumberProcessors=0`; even `System`/PID 4 missing) — the system catching its
  own over-claim.

## What Is Next

We deliberately optimized for verification over volume. A broader agent that
cannot verify itself just produces more unverified claims, faster. Protocol
SIFT++ chose one case, every claim adversarially checked and reproduced across
OS, because the rubric explicitly rewards depth over breadth.

The next step is breadth as configuration, not redesign: add more read-only tool
adapters for recovered command lines, registry hives, packet payloads, and
file-system artifacts, while keeping the same Investigator/Skeptic verification
loop and the same chain-of-custody guarantees.

## Submission Links

- GitHub: https://github.com/tupils1/protocol-siftpp
- Dataset documentation: `docs/DATASET.md`
- Accuracy report: `docs/ACCURACY_REPORT.md`
- Demo script: `docs/DEMO_SCRIPT.md`
- Run logs summary: `docs/RUN_LOGS.md`
