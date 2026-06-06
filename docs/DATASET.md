# Dataset Documentation

This document tracks the selected SANS sample case data.

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
- Evidence SHA-256: computed by `siftpp-investigate` at run start
- Acquisition MD5 from included dc3dd log: `3313cd1d72e27c6ee891eec5953ec616`
- Acquisition notes: Provided by the SANS FIND EVIL! sample set.

## Why This Scenario

This is the smallest directly memory-focused archive in the official
`Compromised APT Attack Scenarios / SRL-2018` folder. It keeps the project
focused on the read-only Volatility MCP path and is small enough for repeated
download/extract/test iterations before the deadline.

Selection criteria:

- It supports a focused 5-minute demo.
- It has enough evidence for at least one adversarial self-correction.
- It can be analyzed with the read-only Volatility tool subset.
- It demonstrates depth over broad tool coverage.

Download and extract:

```powershell
C:\Users\Administrator\.local\bin\uv.exe run siftpp-download-case
```

The command writes `evidence/srl-2018-base-file-memory/case_manifest.json` and
prints candidate extracted memory-image paths for `siftpp-investigate`.

Volatility smoke test:

```text
windows.info: OK
SystemTime: 2018-09-06 19:28:44+00:00
NtSystemRoot: C:\windows
NtMajorVersion/NtMinorVersion: 6.3
Is64Bit: True
```

Early evidence notes from manual plugin smoke tests:

- `windows.pslist` and `windows.cmdline` returned empty arrays on this image.
- `windows.psscan` recovered active and terminated processes, including
  `powershell.exe`, repeated `rundll32.exe` children, `rubyw.exe`, and
  `subject_srv.ex`.
- `windows.netscan` recovered network activity for `powershell.exe`,
  `rubyw.exe`, `subject_srv.ex`, and normal Windows services.
- `windows.malfind` and `windows.svcscan` returned empty arrays in the smoke
  test, so injection/service-persistence claims should be treated carefully.

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

## Chain of Custody

Record these before the final run:

```text
evidence_path: evidence/srl-2018-base-file-memory/extracted/base-file-memory.img
sha256_before: computed at run start
sha256_after: computed by verify_evidence_integrity
unchanged: TBD after final agent run
```

The final run must include `verify_evidence_integrity` and cite the output in
the accuracy report.

## Known Answer / Ground Truth

TBD after manual review of the selected sample and/or official documentation.

Track:

- Confirmed malicious artifacts.
- Benign artifacts that look suspicious.
- Expected false-positive traps.
- Artifacts outside the selected scope.

## Limitations

TBD after the final run.

Expected limitations:

- The current implementation is focused on Windows memory forensics.
- Output returned to the model is row/character capped, while full output is
  still hashed for citation.
- The allowlist is intentionally narrow to preserve the read-only guardrail.
