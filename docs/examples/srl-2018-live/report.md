# Incident Report — srl-2018-live

- Evidence: `/home/dministrator/ev/base-file-memory.img`
- Evidence sha256: `4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd`
- Self-correction iterations: 1
- Summary: 4 confirmed of 8 findings; 1 self-correction iteration(s); evidence integrity verified.

## Confirmed (4)
### [critical] Suspicious backdoor process 'subject_srv.ex' (PID 6160) running as a Windows service (PPID services.exe/536), listening on TCP port 3262 with an active ESTABLISHED connection to 172.16.5.50:44262, and a prior CLOSED connection to 172.16.5.25:5682.
- confidence: 0.88
- ATT&CK: T1543.002, T1571, T1041
- Skeptic: All five factual claims (process name/PID, PPID=services.exe/536, TCP 3262 LISTENING, ESTABLISHED to 172.16.5.50:44262, CLOSED to 172.16.5.25:5682) are directly confirmed by psscan and netscan. The "Windows service" label is inferred from PPID but unverifiable (svcscan returns empty). The "backdoor" characterization is interpretive but consistent with the observed behavior. Confidence reduced from 0.95 to 0.88 due to: reliance on pool-scan rather than EPROCESS walk, empty svcscan preventing service registration confirmation, and inability to run cmdline/dlllist/malfind for further corroboration.
- evidence: `vol_psscan` (sha256 `f7e253cac99a942b…`)
- evidence: `vol_netscan` (sha256 `73bf946ea0df9acf…`)

### [high] WMI-based compromise vector: WmiPrvSE.exe (PID 1196) is the parent of a 64-bit PowerShell (PID 4072) that launched the attack chain, indicating the adversary used Windows Management Instrumentation (WMI) to trigger the initial PowerShell execution — consistent with WMI-based lateral movement or persistence.
- confidence: 0.90
- ATT&CK: T1047
- Skeptic: psscan directly confirms WmiPrvSE.exe (PID 1196, PPID 600) is the parent of powershell.exe (PID 4072, 64-bit, Wow64=false). PID 4072 then spawned powershell.exe (PID 3164, 32-bit, Wow64=true) which spawned ~30 short-lived rundll32.exe instances. Netscan shows both PowerShell processes connecting to 172.16.4.10:8080. WmiPrvSE.exe as parent of PowerShell is the canonical forensic indicator of WMI-based process creation (Win32_Process.Create or __EventFilter/__EventConsumer). The multi-stage PowerShell → rundll32 chain with external network connections confirms this is an attack chain, not benign activity. Slight confidence reduction from 0.85 to 0.90 reflects the inability to distinguish lateral movement from persistence without event logs, though both fall under the claimed WMI compromise vector.
- evidence: `vol_psscan` (sha256 `f7e253cac99a942b…`)

### [high] WmiPrvSE.exe (PID 1196) spawned a 64-bit powershell.exe (PID 4072) on 2018-08-28, which spawned a 32-bit (Wow64) powershell.exe (PID 3164) that then spawned at least 28 short-lived rundll32.exe instances between 2018-08-30 and 2018-09-06, with lifetimes ranging from 2 to 38 seconds. Both powershell.exe processes remain alive and made TCP connections to 172.16.4.10:8080 — a pattern consistent with a PowerShell-based remote access / C2 framework but not attributable to any specific toolkit on available evidence.
- confidence: 0.82
- ATT&CK: T1059.001, T1218.011, T1105
- Skeptic: All material factual claims are directly supported by psscan and netscan: the WmiPrvSE→powershell64→powershell32 parent chain with create times, the Wow64 architecture split, exactly 28 rundll32.exe instances with PPID 3164 spanning 2018-08-30 through 2018-09-06 with 2-38 second lifetimes, and both powershell processes connecting to 172.16.4.10:8080. The only weakness is inability to cross-validate via pslist (empty on this image) and no cmdline/malfind data. The ngentask.exe connection to the same IP:port is noted but doesn't materially refute the finding. Confidence reduced from the investigator's 0.85 to 0.82 due to the empty pslist limiting process-liveness confirmation.
- evidence: `vol_psscan` (sha256 `f7e253cac99a942b…`)
- evidence: `vol_netscan` (sha256 `73bf946ea0df9acf…`)

### [medium] On 2018-09-06, cmd.exe (PID 4808, PPID 6956) spawned Uninstall.exe (PID 2340) which initiated an outbound TCP connection to 172.16.7.12:135 (MSRPC endpoint mapper). Both processes were extremely short-lived (~2 seconds each). The MSRPC connection to a remote internal host is consistent with remote administration or software deployment activity, but benign alternatives (e.g. McAfee ePO-driven uninstall, evidenced by macompatsvc.exe/masvc.exe/macmnsvc.exe/mfemactl.exe on the host) cannot be ruled out.
- confidence: 0.90
- ATT&CK: T1021.003
- Skeptic: All factual claims are directly supported by raw evidence from psscan and netscan. The parent-child relationship (cmd.exe→Uninstall.exe) is confirmed by matching PPID 4808. The MSRPC connection to 172.16.7.12:135 is confirmed. The McAfee ePO agent processes are present. The only minor gap is that PPID 6956 (cmd.exe's parent) cannot be identified from the available pool data, but the claim does not assert its identity. Confidence reduced from 1.0 to 0.9 solely because the upstream parent is unknown and the benign-alternative caveat cannot be ruled in or out from memory alone.
- evidence: `vol_psscan` (sha256 `f7e253cac99a942b…`)
- evidence: `vol_netscan` (sha256 `73bf946ea0df9acf…`)

## Inferred (4)
### [critical] PowerShell-based attack chain: WmiPrvSE.exe (PID 1196) spawned powershell.exe (PID 4072, 64-bit), which spawned a 32-bit powershell.exe (PID 3164, Wow64=true), which then spawned at least 28 short-lived rundll32.exe instances (each lasting 2-5 seconds) between 2018-08-30 and 2018-09-06 — a classic Cobalt Strike / Empire process injection pattern.
- confidence: 0.65
- ATT&CK: T1047, T1059.001, T1218.011, T1055
- Skeptic: The parent-child chain and run count are directly corroborated by psscan. However, the investigator's claim goes beyond what psscan can show: no injection was found (malfind empty), no command-line evidence exists to confirm Cobalt Strike/Empire, and the "2-5 second" lifetime characterization is overstated. The finding is plausible for a PowerShell-based attack chain but over-attributed and over-precise for the available evidence.
- evidence: `vol_psscan` (sha256 `f7e253cac99a942b…`)

### [high] Both PowerShell processes communicated with C2 server 172.16.4.10 on TCP port 8080: powershell.exe (PID 4072) had a CLOSED connection and powershell.exe (PID 3164, 32-bit) had a connection in CLOSE_WAIT state. Additionally, ngentask.exe (PID 7092) also contacted the same server on port 8080.
- confidence: 0.85
- ATT&CK: T1071.001, T1571
- Skeptic: The factual claims about connection tuples (process, PID, remote IP:port, state) are all directly confirmed by my independent netscan re-run. The C2 classification is an inference: netscan shows only connection metadata, not the content or purpose of the communication. No legitimate processes were observed connecting to 172.16.4.10:8080, and the pattern (parent 64-bit PowerShell → child 32-bit PowerShell, both + ngentask.exe to same IP:8080) is highly consistent with C2 activity, but the cited tools (netscan, psscan) alone cannot definitively prove 172.16.4.10 is a C2 server vs. another type of malicious or misconfigured internal server.
- evidence: `vol_netscan` (sha256 `73bf946ea0df9acf…`)
- evidence: `vol_psscan` (sha256 `f7e253cac99a942b…`)

### [medium] Adversary executed cmd.exe (PID 4808) which spawned Uninstall.exe (PID 2340) that made an outbound MSRPC connection to 172.16.7.12:135 — consistent with lateral movement or remote reconnaissance activity on 2018-09-06.
- confidence: 0.65
- ATT&CK: T1021.003, T1059.003
- Skeptic: The factual core of the claim holds up under independent verification: psscan confirms cmd.exe (PID 4808) spawned Uninstall.exe (PID 2340) on 2018-09-06, and netscan confirms Uninstall.exe had a TCP connection to 172.16.7.12:135 (MSRPC). These are directly observable from the pool-scan evidence. However, the "adversary" attribution and "lateral movement/reconnaissance" characterization are inferences that go beyond what the raw data can prove — especially given the EPROCESS corruption that prevents examining command lines, DLL loads, or executable paths. Multiple legitimate alternative explanations exist (enterprise software uninstall, McAfee ePO communication to a management server on 172.16.7.12). The evidence is consistent with the claim's interpretation but does not directly support it over benign alternatives.
- evidence: `vol_psscan` (sha256 `f7e253cac99a942b…`)
- evidence: `vol_netscan` (sha256 `73bf946ea0df9acf…`)

### [medium] Suspicious reg.exe execution (PID 2724) on 2018-09-06 16:00:04, consistent with adversary modifying registry for persistence or configuration changes during the compromise window.
- confidence: 0.30
- ATT&CK: T1112
- Skeptic: The raw psscan evidence confirms reg.exe PID 2724 ran briefly at the stated time — that part is factually correct. However, the claim that this is "suspicious" and "consistent with adversary modifying registry for persistence" is inferential. No command-line arguments, no parent process traceability, no registry artifacts, and no memory-resident code (malfind empty) link this specific reg.exe execution to adversary activity. The broader image does contain other suspicious indicators (powershell.exe C2 chain, subject_srv.exe), but the investigator did not tie reg.exe to those, and many legitimate Windows operations invoke reg.exe in Session 0. The finding overstates what can be concluded from a pool-tag remnant alone.
- evidence: `vol_psscan` (sha256 `f7e253cac99a942b…`)
