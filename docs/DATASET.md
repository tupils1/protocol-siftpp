# Dataset Documentation

This document tracks the selected SANS sample case data used for the final
Protocol SIFT++ run.

## Selected Scenario

- Scenario name: SRL-2018 Compromised Enterprise Network
- Selected artifact: `base-file-memory.7z`
- Case ID: `srl-2018-base-file-memory`
- Source URL: https://sansorg.egnyte.com/fl/HhH7crTYT4JK
- Direct download entry ID: `a6fba49f-a7c9-4b9f-bf10-5826a3840ce9`
- Evidence type: Windows memory image
- Extracted evidence file: `evidence/srl-2018-base-file-memory/extracted/base-file-memory.img`
- Archive size: 318,241,288 bytes
- Extracted evidence size: 2,147,483,648 bytes
- Archive SHA-256: `6a1df2332cb8157e3634f5fbee900afeefb5ad44044877e93ca0745e7e7920cf`
- Evidence SHA-256: `4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd`
- Acquisition MD5 from included dc3dd log: `3313cd1d72e27c6ee891eec5953ec616`
- Acquisition notes: Provided by the SANS FIND EVIL! sample set.

## Why This Scenario

This is the smallest directly memory-focused archive in the official
`Compromised APT Attack Scenarios / SRL-2018` folder. It keeps the project
focused on a narrow read-only Volatility MCP path and is small enough for
repeated download, extraction, and agent-run iteration before the deadline.

Selection criteria:

- It supports a focused five-minute demo.
- It contains a useful evidence trap: normal process-list plugins return empty
  while pool-scanning plugins recover process and network artifacts.
- It forces the agent to separate confirmed facts from plausible but unproven
  interpretations.
- It demonstrates depth over broad tool coverage.

## Reproduction

Download and extract:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-download-case
```

The command writes `evidence/srl-2018-base-file-memory/case_manifest.json` and
prints candidate extracted memory-image paths for `siftpp-investigate`.

Run the final investigation:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-investigate `
  --provider deepseek `
  --evidence evidence\srl-2018-base-file-memory\extracted\base-file-memory.img `
  --out analysis\srl-2018-base-file-memory `
  --case-id srl-2018-base-file-memory `
  --offline `
  --max-iterations 3
```

Final run summary:

```text
4 confirmed of 10 findings; 2 self-correction iteration(s); evidence integrity verified.
audit log: 302 records, hash chain OK
```

## Volatility Smoke Test

```text
windows.info: OK
SystemTime: 2018-09-06 19:28:44+00:00
NtSystemRoot: C:\windows
NtMajorVersion/NtMinorVersion: 6.3
Is64Bit: True
```

Manual plugin results:

- `windows.pslist`: 0 rows
- `windows.pstree`: 0 rows
- `windows.cmdline`: 0 rows
- `windows.dlllist`: 0 rows
- `windows.malfind`: 0 rows
- `windows.svcscan`: 0 rows
- `windows.psscan`: 101 rows
- `windows.netscan`: 145 rows

High-signal artifacts from manual review:

- `powershell.exe` PID 4072, PPID 1196 (`WmiPrvSE.exe`), created
  `2018-08-28T22:08:25+00:00`.
- `powershell.exe` PID 3164, PPID 4072, Wow64 true, created
  `2018-08-28T22:08:26+00:00`.
- 28 short-lived `rundll32.exe` children of PID 3164.
- `subject_srv.ex` PID 6160, PPID 536 (`services.exe`), listening on TCP 3262
  and connected to `172.16.5.50:44262`.
- `ngentask.exe` PID 7092 with two connections to `172.16.4.10:8080`.
- `Uninstall.exe` PID 2340, child of `cmd.exe` PID 4808, connected to
  `172.16.7.12:135`.

## Tooling

Primary tools exposed through the read-only MCP server:

- `vol_info`
- `vol_pslist`
- `vol_pstree`
- `vol_psscan`
- `vol_cmdline`
- `vol_dlllist`
- `vol_malfind`
- `vol_netscan`
- `vol_svcscan`

Excluded tool classes:

- Dumping tools.
- Write-oriented tools.
- Generic shell execution.
- Network upload or exfiltration tools.

## Chain Of Custody

```text
evidence_path: evidence/srl-2018-base-file-memory/extracted/base-file-memory.img
sha256_before: 4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
sha256_after:  4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd
unchanged: true
audit_verify_chain: OK, 302 records
```

## Ground Truth Notes

No public official answer key was found for this exact artifact. The final
accuracy report therefore uses:

- manual Volatility review,
- the Skeptic agent's independent tool re-runs,
- evidence-output SHA-256 citations,
- and the final evidence-integrity hash check.

The report deliberately keeps several conclusions as `inferred` when memory
metadata confirms suspicious behavior but cannot prove binary tampering, command
line intent, code injection, or payload content.

## Limitations

- The implementation is focused on Windows memory forensics.
- Output returned to the model is row/character capped, while full output is
  still hashed for citation.
- The allowlist is intentionally narrow to preserve the read-only guardrail.
- Because EPROCESS-list traversal plugins return empty rows on this image, the
  investigation relies heavily on `psscan` and `netscan`.
- The memory image alone does not provide packet payloads, recovered binaries,
  registry hives, or endpoint event logs.
