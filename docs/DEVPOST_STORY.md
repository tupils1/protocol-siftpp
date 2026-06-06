# Devpost Story Draft

## Inspiration

Autonomous incident response has a trust problem. A responder agent that moves
fast but hallucinates can waste analyst time or, worse, contaminate an
investigation. Protocol SIFT++ was built to test a narrower idea: an autonomous
DFIR agent should not only find suspicious artifacts, it should also try to
disprove its own conclusions before reporting them.

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

The most visible correction involved `ngentask.exe`. The Investigator initially
overstated a malware/C2 attribution. The Skeptic downgraded it, the Investigator
reinvestigated, the Skeptic downgraded it again, and the system finally
converged on a narrower confirmed behavioral claim: `ngentask.exe` lived for
one second and made two connections to the same `172.16.4.10:8080` destination
used by the suspicious PowerShell chain.

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

## What Is Next

The next step would be broader tool coverage: recovered command lines, registry
hives, packet payloads, and file-system artifacts where available. The same
Investigator/Skeptic architecture could also compare memory evidence against
endpoint logs or network captures, making each claim stronger before it becomes
`confirmed`.

## Submission Links

- GitHub: https://github.com/tupils1/protocol-siftpp
- Dataset documentation: `docs/DATASET.md`
- Accuracy report: `docs/ACCURACY_REPORT.md`
- Demo script: `docs/DEMO_SCRIPT.md`
- Run logs summary: `docs/RUN_LOGS.md`
