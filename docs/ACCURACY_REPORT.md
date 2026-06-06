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
confirmed findings: 4
inferred findings: 6
refuted findings: 0
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

## Findings Table

| Final status | Claim summary | Confidence | Ground truth assessment |
| --- | --- | ---: | --- |
| confirmed | DKOM/process-list hiding: traversal plugins empty while pool scans recover processes and sockets. | 0.92 | Supported by the sharp split between empty EPROCESS-list plugins and populated `psscan`/`netscan`; rare Volatility compatibility issues cannot be fully excluded. |
| confirmed | PowerShell C2 chain: WMI-spawned PowerShell, child 32-bit PowerShell, many short-lived `rundll32.exe` children, connections to `172.16.4.10:8080`. | 0.95 | Process and network facts are directly supported; C2 label is a strong inference because command lines are unavailable. |
| confirmed | `Uninstall.exe` child of `cmd.exe`, two-second runtime, RPC connection to `172.16.7.12:135`. | 0.85 | Supported by `psscan` and `netscan`; malicious/lateral-movement label remains interpretive. |
| confirmed | `ngentask.exe` two connections to `172.16.4.10:8080`, same destination as PowerShell chain, within one-second lifespan. | 0.85 | Final corrected claim is supported after two reinvestigation rounds; exact command line and parent identity remain unavailable. |
| inferred | `subject_srv.ex` as backdoor/C2 service on TCP 3262. | 0.75 | Process and sockets are real; backdoor label is plausible but not directly proven without binary/path/service data. |
| inferred | `rundll32.exe` burst as beaconing or payload execution. | 0.72 | 28 child processes are real; no command line, network, DLL, or injection data confirms beaconing. |
| inferred | Shared C2 infrastructure at `172.16.4.10:8080`. | 0.85 | Shared destination is real; C2 role cannot be proven from memory metadata alone. |
| inferred | WMI persistence via event subscription. | 0.75 | WMI-spawned PowerShell is real; event subscription persistence is not directly evidenced. |
| inferred | Initial `ngentask.exe` hijack/C2 claim. | 0.65 | Downgraded by Skeptic and corrected in later iterations. |
| inferred | Intermediate `ngentask.exe` correlation claim. | 0.55 | Downgraded again; led to narrower confirmed final claim. |

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

No final `confirmed` finding is directly contradicted by manual Volatility
review. However, two confirmed findings retain interpretive labels:

- DKOM/rootkit: strongly supported by the plugin split, but direct pointer
  inspection was not performed.
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

## Evidence Integrity / Spoliation Test

Protocol SIFT++ is designed so the agent cannot alter evidence:

- No generic command execution is exposed.
- No dumping/write plugins are registered.
- Volatility child processes run with `stdin=subprocess.DEVNULL` so they cannot
  interfere with the MCP stdio channel.
- Evidence size and mtime are checked around every Volatility call.
- Full-file SHA-256 is verified at the end.

Final run values:

```text
sha256_before: 4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
sha256_after:  4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
unchanged: true
audit_verify_chain: OK, 302 records
```

## Baseline Comparison

The no-Skeptic baseline is the Investigator's raw iteration-0 output from the
same run. Without the Skeptic, the report would have accepted eight high
confidence findings with submitted confidence between 0.85 and 1.00.

With Skeptic verification:

- 3 of the 8 initial findings were confirmed.
- 5 of the 8 initial findings were downgraded to inferred.
- 1 downgraded finding (`ngentask.exe`) triggered two self-correction rounds.
- The final corrected report ended with 4 confirmed and 6 inferred findings.

The most important improvement is qualitative: the system replaced a stronger
unsupported claim about `ngentask.exe` hijacking/C2 with a narrower confirmed
behavioral claim tied to `psscan` and `netscan`.
