# Accuracy And Integrity Report

This is the working template for the final Devpost accuracy deliverable. Fill it
after running Protocol SIFT++ on the selected SANS sample.

## Case

- Case ID: TBD
- Dataset: `SRL-2018 Compromised Enterprise Network / base-file-memory.7z`
- Evidence: `evidence/srl-2018-base-file-memory/extracted/base-file-memory.img`
- Evidence SHA-256: TBD from final run
- Run timestamp: TBD
- Model: `deepseek-v4-pro` via DeepSeek Anthropic-compatible API, or fallback TBD
- Max self-correction iterations: TBD

## Methodology

1. Run the read-only MCP server against the selected memory image.
2. Let the Investigator produce initial findings without human approval.
3. Let the Skeptic independently try to refute each finding.
4. Re-investigate every refuted or low-confidence finding.
5. Compare final findings against manual analysis / known answer.
6. Verify the audit log hash chain and evidence integrity.

## Results Summary

```text
confirmed findings: TBD
inferred findings: TBD
refuted findings: TBD
self-correction iterations: TBD
false positives after verification: TBD
missed artifacts: TBD
evidence unchanged: TBD
audit hash chain: TBD
```

## Findings Table

| ID | Final status | Claim | Confidence | Evidence | Ground truth | Notes |
| --- | --- | --- | ---: | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD | TBD | TBD |

## Hallucination / Self-Correction Evidence

Document at least one correction shown in the demo video.

| Initial claim | Skeptic objection | Follow-up tool run | Final outcome |
| --- | --- | --- | --- |
| TBD | TBD | TBD | TBD |

## False Positives

TBD.

For each false positive:

- What was claimed.
- What evidence appeared to support it.
- Why the Skeptic did or did not catch it.
- How it should be handled in future runs.

## Missed Artifacts

TBD.

For each missed artifact:

- What was missed.
- Which tool output contained it, if any.
- Whether the issue was tool coverage, model reasoning, output truncation, or
  prompt/orchestration behavior.

## Evidence Integrity / Spoliation Test

Protocol SIFT++ is designed so the agent cannot alter evidence:

- No generic command execution is exposed.
- No dumping/write plugins are registered.
- Evidence size and mtime are checked around every Volatility call.
- Full-file SHA-256 is verified at the end.

Final run values:

```text
sha256_before: TBD
sha256_after: TBD
unchanged: TBD
audit_verify_chain: TBD
```

## Baseline Comparison

TBD.

Compare against:

- Stock Protocol SIFT run, if time allows.
- A no-Skeptic Protocol SIFT++ run, if stock baseline is not practical.

Track:

- Which findings survive verification.
- Which hallucinations are removed.
- Whether self-correction improves the final report.

## Pre-Run Smoke Notes

Manual Volatility checks on the selected image show a useful verification trap:

- `windows.pslist` / `windows.cmdline` returned no rows.
- `windows.psscan` recovered process artifacts, including `powershell.exe`
  PID 4072/3164, multiple short-lived `rundll32.exe` processes with PPID 3164,
  `subject_srv.ex` PID 6160, and `rubyw.exe` PID 1156.
- `windows.netscan` recovered network artifacts for `powershell.exe`,
  `rubyw.exe`, and `subject_srv.ex`.
- `windows.malfind` returned no rows.

This should force the final agent to distinguish confirmed network/process
artifacts from unsupported code-injection claims.
