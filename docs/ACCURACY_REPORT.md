# Accuracy And Integrity Report

Final run used the selected SANS sample memory image and DeepSeek through the
Anthropic-compatible API.

## Case

- Case ID: `srl-2018-base-file-memory`
- Dataset: `SRL-2018 Compromised Enterprise Network / base-file-memory.7z`
- Evidence: `evidence/srl-2018-base-file-memory/extracted/base-file-memory.img`
- Evidence SHA-256: `4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd`
- Run timestamp: `2026-06-06T19:52:29.803172Z`
- Model: `deepseek-v4-pro`
- Provider: DeepSeek Anthropic-compatible API
- Max self-correction iterations: 3
- Actual self-correction iterations: 2
- Output directory: `analysis/srl-2018-base-file-memory`

## Methodology

1. Start the read-only MCP server against the selected memory image.
2. Let the Investigator choose and run Volatility tools without human approval.
3. Let the Skeptic independently re-run tools and attempt to refute each claim.
4. Re-investigate refuted findings and weak inferred findings.
5. Compare the final report against manual Volatility review.
6. Verify the audit log hash chain and evidence integrity.

Manual review used the same read-only Volatility plugins:

- `windows.info`
- `windows.pslist`
- `windows.pstree`
- `windows.psscan`
- `windows.cmdline`
- `windows.dlllist`
- `windows.malfind`
- `windows.netscan`
- `windows.svcscan`

No public official answer key was found for this exact sample artifact, so the
ground-truth proxy is manual Volatility review plus the Skeptic's independent
cross-checks. This limitation should be stated in the Devpost submission.

## Results Summary

```text
windows-run confirmed findings: 4
cross-run corrected confirmed findings: 3
inferred findings: 6
windows-run refuted findings: 0
cross-run corrected false positives: 1 (DKOM/rootkit)
self-correction iterations: 2
audit records: 302
model calls: 99
tool calls: 159
input tokens: 415886
output tokens: 89065
total tokens: 504951
evidence unchanged: true
audit hash chain: OK, 302 records
```

The run ended with:

```text
4 confirmed of 10 findings; 2 self-correction iteration(s); evidence integrity verified.
```

The cross-platform re-run later refuted one of those Windows confirmed findings
(`DKOM/rootkit`) as a Volatility symbol/KDBG artifact. For scoring below, that
finding is counted as a caught false positive, not as a true confirmed finding.

## Quantitative Accuracy (Manual-Review Proxy)

There is no public official answer key for this exact `base-file-memory.img`
artifact. To avoid unverifiable self-grading, we use a small manual Volatility
review proxy: four actionable artifact clusters that are directly supported by
`psscan` and `netscan` and are concrete enough to score.

Manual-review proxy positives:

1. WMI -> `powershell.exe` -> 32-bit `powershell.exe` -> short-lived
   `rundll32.exe` chain, with PowerShell connections to `172.16.4.10:8080`.
2. `Uninstall.exe` spawned by `cmd.exe`, two-second runtime, RPC connection to
   `172.16.7.12:135`.
3. `ngentask.exe` one-second process with two connections to
   `172.16.4.10:8080`, the same destination as the PowerShell chain.
4. `subject_srv.ex` service-child process with TCP 3262 listener and connection
   to `172.16.5.50:44262`; the process/socket facts are real, while the
   backdoor/C2 label is still only inferred.

Scoring is intentionally conservative:

- `TP`: a confirmed finding matches one manual-review proxy positive at the
  right level of specificity.
- `FP`: a confirmed finding is contradicted or too strong for the evidence.
- `FN`: a manual-review proxy positive was not retained as a confirmed finding.
- Inferred findings are not counted as confirmed positives.

| Scoring snapshot | Predicted confirmed | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| No-Skeptic baseline: raw high-confidence Investigator claims, cluster-level credit | 8 | 4 | 4 | 0 | 0.50 | 1.00 | 0.67 |
| Windows SIFT++ confirmed findings before cross-run correction | 4 | 3 | 1 | 1 | 0.75 | 0.75 | 0.75 |
| Cross-run corrected confirmed findings after Linux Skeptic refuted DKOM | 3 | 3 | 0 | 1 | 1.00 | 0.75 | 0.86 |

The important point is not that this proxy replaces an official answer key. It
does not. The point is that the same evidence trail lets us score the system
honestly, and the Skeptic/cross-run correction improves precision by removing
the DKOM over-claim while preserving the three strongest confirmed behavioral
findings.

## Manual Evidence Summary

Manual Volatility review found:

- `windows.info`: Windows Server 2012 R2 / Windows 6.3, 64-bit, system time
  `2018-09-06 19:28:44+00:00`.
- `windows.pslist`, `windows.pstree`, `windows.cmdline`, `windows.dlllist`,
  `windows.malfind`, and `windows.svcscan`: zero rows.
- `windows.psscan`: 101 process artifacts.
- `windows.netscan`: 145 network artifacts.

High-signal artifacts:

- `powershell.exe` PID 4072, PPID 1196 (`WmiPrvSE.exe`), created
  `2018-08-28T22:08:25+00:00`.
- `powershell.exe` PID 3164, PPID 4072, Wow64 true, created
  `2018-08-28T22:08:26+00:00`.
- 28 short-lived `rundll32.exe` children of PID 3164 across Aug 30 to Sep 6.
- `subject_srv.ex` PID 6160, PPID 536 (`services.exe`), listening on TCP 3262
  and connected to `172.16.5.50:44262`.
- `ngentask.exe` PID 7092 lived for one second and had two closed connections
  to `172.16.4.10:8080`.
- `powershell.exe` PIDs 3164 and 4072 also connected to `172.16.4.10:8080`.
- `Uninstall.exe` PID 2340, child of `cmd.exe` PID 4808, ran for two seconds
  and connected to `172.16.7.12:135`.

## Windows Run Findings And Corrected Assessment

| Windows status | Corrected scoring status | Claim summary | Confidence | Ground truth assessment |
| --- | --- | --- | ---: | --- |
| confirmed | false positive / removed | DKOM/process-list hiding: traversal plugins empty while pool scans recover processes and sockets. | 0.92 | Linux re-run refuted this as a Volatility symbol/KDBG artifact: `KeNumberProcessors=0` and even `System`/PID 4 missing from traversal views. Counted as FP in Windows-only scoring and removed in cross-run scoring. |
| confirmed | TP | PowerShell C2 chain: WMI-spawned PowerShell, child 32-bit PowerShell, many short-lived `rundll32.exe` children, connections to `172.16.4.10:8080`. | 0.95 | Process and network facts are directly supported; C2 label is a strong inference because command lines are unavailable. |
| confirmed | TP | `Uninstall.exe` child of `cmd.exe`, two-second runtime, RPC connection to `172.16.7.12:135`. | 0.85 | Supported by `psscan` and `netscan`; malicious/lateral-movement label remains interpretive. |
| confirmed | TP | `ngentask.exe` two connections to `172.16.4.10:8080`, same destination as PowerShell chain, within one-second lifespan. | 0.85 | Final corrected claim is supported after two reinvestigation rounds; exact command line and parent identity remain unavailable. |
| inferred | FN at confirmed threshold | `subject_srv.ex` as backdoor/C2 service on TCP 3262. | 0.75 | Process and sockets are real; backdoor label is plausible but not directly proven. A narrower confirmed process/socket finding would have improved recall. |
| inferred | not confirmed | `rundll32.exe` burst as beaconing or payload execution. | 0.72 | 28 child processes are real; no command line, network, DLL, or injection data confirms beaconing. |
| inferred | not confirmed | Shared C2 infrastructure at `172.16.4.10:8080`. | 0.85 | Shared destination is real; C2 role cannot be proven from memory metadata alone. |
| inferred | not confirmed | WMI persistence via event subscription. | 0.75 | WMI-spawned PowerShell is real; event subscription persistence is not directly evidenced. |
| inferred | corrected over-claim | Initial `ngentask.exe` hijack/C2 claim. | 0.65 | Downgraded by Skeptic and corrected in later iterations. |
| inferred | corrected over-claim | Intermediate `ngentask.exe` correlation claim. | 0.55 | Downgraded again; led to narrower confirmed final claim. |

## Self-Correction Evidence

The final run contains two real self-correction iterations:

| Step | Evidence |
| --- | --- |
| Initial claim | `ngentask.exe` PID 7092 made two connections to `172.16.4.10:8080`; Investigator inferred it was hijacked or renamed malware, confidence 0.85. |
| Skeptic objection | Raw evidence confirmed the connections but did not prove binary tampering, hijack, or C2 commands; status became `inferred`, confidence 0.65. |
| Iteration 1 | Orchestrator logged `iteration` event 202: `1 finding(s) refuted/low-confidence -> re-investigate`. |
| Revised claim | Investigator narrowed the claim to correlation with PowerShell C2 infrastructure but still over-reached; Skeptic downgraded it to `inferred`, confidence 0.55. |
| Iteration 2 | Orchestrator logged `iteration` event 253 for a second reinvestigation. |
| Final outcome | Investigator submitted a narrower factual behavioral claim: `ngentask.exe` made two connections to the same IP:port as the PowerShell chain within a one-second lifespan; Skeptic confirmed it at 0.85. |

This is the strongest demo segment because the system did not simply accept the
Investigator's original malware attribution. It forced two revisions until the
claim matched the evidence.

## False Positives

The Windows run had one confirmed false positive after cross-platform review:

- DKOM/rootkit: strongly supported by the plugin split, but direct pointer
  inspection was not performed. **Update: an independent Linux re-run refuted this
  as a Volatility symbol-resolution artifact (`KeNumberProcessors=0`; even
  `System`/PID 4 is missing) - see "Cross-Platform Reproduction" below. We now
  treat the DKOM confirmation as a caught over-claim, not a confirmed finding.**

One retained confirmed finding still has an interpretive label:

- PowerShell C2 chain: the behavior is highly suspicious, but command lines and
  payloads were unavailable.

The system avoided promoting six weaker claims to confirmed status. The most
important prevented overstatements were:

- `subject_srv.ex` is suspicious, but the backdoor/C2 label is not proven.
- `rundll32.exe` bursts are suspicious, but direct Cobalt Strike/beaconing
  attribution is not proven.
- WMI event-subscription persistence is plausible, but not directly evidenced.
- `ngentask.exe` hijack/tampering was downgraded and corrected.

## Missed Artifacts

Manual review found lower-priority artifacts that the final corrected report did
not cover:

- `Rar.exe` PID 2524 ran for about 9 minutes on `2018-09-05`; no command line or
  network evidence was available, so this remains a weak data-staging lead.
- `reg.exe` PID 2724 executed briefly on `2018-09-06`; no registry arguments
  were recovered, so malicious registry modification is unproven.
- `rubyw.exe` PID 1156 maintained traffic to `10.10.254.1:61613`; this may be
  enterprise monitoring or messaging infrastructure and needs host context.
- NCPA-related processes (`ncpa_passive.e`, `ncpa_listener.`) appeared to be
  monitoring components and were not treated as malicious.

These misses are acceptable for a depth-focused demo, but they should be called
out as future-work coverage gaps.

## Evidence Integrity, Spoliation Resistance, and Tamper-Evidence

Protocol SIFT++ is forensically defensible by construction, and each property is
backed by a reproducible automated test (no API key required) — not just a design
claim.

### 1. Spoliation resistance — the agent cannot alter, dump, or exfiltrate evidence

`siftpp-spoliation-test` connects to the live read-only MCP server and attempts,
exactly as a prompt-injected or malicious agent would, to dump processes,
write/delete files, run a shell, and exfiltrate. None of those capabilities are
registered, so every attempt is refused and the evidence is byte-identical before
and after. Result on the real SANS image:

```text
tools exposed: 11; destructive tools exposed: 0
destructive attempts refused: 14/14
evidence sha256 before: 4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
evidence sha256 after:  4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
evidence unchanged: True
RESULT: PASS - evidence cannot be altered/dumped/exfiltrated by construction
```

The guarantee is architectural: no generic command runner, no dump/write plugin,
and no network/upload tool exists in the server. Volatility child processes also
run with `stdin=subprocess.DEVNULL`, and evidence size + mtime are checked around
every call. Full machine-readable report: `analysis/spoliation/spoliation_report.json`.

### 2. Tamper-evident chain of custody — any edit to the audit log is detected

The append-only audit log hash-chains each record into the previous one.
`siftpp-tamper-test` verifies the real 302-record log, then alters one historical
record in a copy and re-verifies:

```text
original audit: analysis/srl-2018-base-file-memory/audit.jsonl
  verify_chain -> (True, 302)
tampered record #152 of 302 (was a tool_call for vol_cmdline)
  verify_chain -> (False, 152)
RESULT: PASS - tampering detected at record 152
```

Every finding additionally cites the exact tool command plus the SHA-256 of its
full output, so the report traces back to specific, hash-verified executions.

### 3. Final-run integrity values

```text
sha256_before: 4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
sha256_after:  4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
unchanged: true
audit_verify_chain: OK, 302 records
```

Both tests are part of the suite (`tests/test_spoliation.py`, `tests/test_tamper.py`).

## Baseline Comparison

The no-Skeptic baseline is the Investigator's raw iteration-0 output from the
same run. Without the Skeptic, the report would have accepted eight high
confidence findings with submitted confidence between 0.85 and 1.00.

With Skeptic verification:

- 3 of the 8 initial findings were confirmed.
- 5 of the 8 initial findings were downgraded to inferred.
- 1 downgraded finding (`ngentask.exe`) triggered two self-correction rounds.
- The final corrected report ended with 4 confirmed and 6 inferred findings.
- The cross-platform re-run then removed the DKOM false positive, leaving 3
  retained confirmed findings for the manual-review proxy score.

The most important improvement is qualitative: the system replaced a stronger
unsupported claim about `ngentask.exe` hijacking/C2 with a narrower confirmed
behavioral claim tied to `psscan` and `netscan`. Quantitatively, the
manual-review proxy score improved from F1 0.75 on the Windows confirmed set to
F1 0.86 after cross-run DKOM correction, with precision rising from 0.75 to 1.00.

## Cross-Platform Reproduction (Linux) and a Real Self-Correction on "DKOM"

The full investigation was re-run end to end on Linux (Ubuntu 22.04 / WSL2,
uv-managed CPython 3.12.13) against the same image (sha256 `4c192e5d…`, confirmed
identical) via `tools/linux_volcheck.sh` then `tools/linux_realrun.sh`. Outputs:
`docs/examples/srl-2018-linux/`.

```text
Linux run: 2 confirmed of 8 findings; 2 self-correction iterations; integrity verified.
audit: 256 records, hash chain OK (mcp-server log: 127, OK); model calls: 84; tool calls: 136.
```

LLM runs are non-deterministic, so the two runs are not identical — which is
precisely why the adversarial Skeptic and the audit trail matter. The key
difference is a self-correction the Windows run did not make:

- Windows run: **confirmed** a "DKOM rootkit" (empty `pslist`/`pstree`, while
  `psscan` recovers 101 processes), confidence 0.92.
- Linux run: the Investigator proposed the same DKOM claim; the **Skeptic refuted
  it** and the Investigator converged on the more defensible reading — a **KDBG /
  symbol-resolution failure, not DKOM**. Decisive signals: `KeNumberProcessors=0`
  (impossible for a running host) and *every* process missing from the
  ActiveProcessLinks views, including `System` (PID 4). Real DKOM unlinks
  *specific* processes; unlinking System would crash the OS, yet `psscan` shows it
  running.

The Linux reading is the more forensically defensible one: "empty traversal +
full pool scan" is commonly taught as DKOM but is ambiguous, and on this Windows
Server 2012 R2 (6.3) image the corroborating signals indicate a Volatility
symbol/parse limitation. We therefore treat the Windows run's "confirmed DKOM" as
an **over-claim that the system itself caught on re-run** — the strongest concrete
demonstration of judging criterion #2 (catching its own errors). Both runs still
surfaced the real suspicious artifacts (`subject_srv.ex`, the
WMI -> PowerShell -> rundll32 chain, the internal `172.16.x` connections) and
both kept evidence integrity intact (sha256 unchanged).
