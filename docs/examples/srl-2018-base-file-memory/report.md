# Incident Report — srl-2018-base-file-memory

- Evidence: `evidence\srl-2018-base-file-memory\extracted\base-file-memory.img`
- Evidence sha256: `4c192e5dc751350777be5ca3dec8bd264baaba73e08e98d759825983b5ce22fd`
- Self-correction iterations: 2
- Summary: 4 confirmed of 10 findings; 2 self-correction iteration(s); evidence integrity verified.

## Confirmed (4)
### [critical] DKOM rootkit: Active process list (EPROCESS ActiveProcessLinks) has been unlinked. vol_pslist and vol_pstree return zero rows, while vol_psscan finds 101 processes via pool scanning. Likewise, vol_cmdline, vol_dlllist, vol_malfind, and vol_svcscan all return zero rows — consistent with kernel-level process hiding.
- confidence: 0.92
- ATT&CK: T1014
- Skeptic: The raw evidence directly supports the claim. Pool-scanning plugins (psscan: 101 processes, netscan: 145 connections) work normally while ALL EPROCESS ActiveProcessLinks-dependent plugins (pslist, pstree, cmdline, dlllist, malfind, svcscan) return zero rows. This tight binary split between traversal-based and pool-scanning enumeration is the textbook forensic signature of DKOM process-list unlinking. Confidence is 0.92 rather than 1.00 because we cannot directly inspect the Flink/Blink pointers to rule out a rare Volatility3/Windows-6.3 compatibility issue without deeper manual memory carving — but the presence of suspicious processes (subject_srv.ex, ncpa_passive.e/ncpa_listener., massed rundll32.exe) in the pool scan data provides corroborating context.
- evidence: `vol_pslist` (sha256 `d9163d874acf3f29…`)
- evidence: `vol_pstree` (sha256 `d9163d874acf3f29…`)
- evidence: `vol_psscan` (sha256 `b7e9c4731b1c230f…`)
- evidence: `vol_cmdline` (sha256 `d9163d874acf3f29…`)
- evidence: `vol_dlllist` (sha256 `d9163d874acf3f29…`)
- evidence: `vol_malfind` (sha256 `d9163d874acf3f29…`)
- evidence: `vol_svcscan` (sha256 `d9163d874acf3f29…`)

### [critical] PowerShell C2 chain: powershell.exe (PID 4072) was spawned by WmiPrvSE.exe (PID 1196) on 2018-08-28 22:08:25. It then spawned a 32-bit powershell.exe (PID 3164, Wow64), which spawned dozens of short-lived rundll32.exe processes across Aug 30–Sep 6 2018. Both PowerShell processes have TCP connections to 172.16.4.10:8080 — PID 4072 (CLOSED) and PID 3164 (CLOSE_WAIT).
- confidence: 0.95
- ATT&CK: T1059.001, T1105, T1571
- Skeptic: All four factual claims are directly confirmed by the raw evidence: (a) psscan shows powershell.exe PID 4072 with PPID 1196 (WmiPrvSE.exe) and CreateTime 2018-08-28T22:08:25; (b) psscan shows powershell.exe PID 3164 with PPID 4072, Wow64=true (32-bit), CreateTime 2018-08-28T22:08:26; (c) psscan shows 20+ short-lived rundll32.exe processes with PPID 3164 spanning 2018-08-30 through 2018-09-06, with lifespans of 2-38 seconds each; (d) netscan shows PID 4072 → 172.16.4.10:8080 (CLOSED) and PID 3164 → 172.16.4.10:8080 (CLOSE_WAIT). The "C2 chain" label is an interpretive overlay on these facts but is well-supported by the classic attack pattern (WMI spawn → PowerShell → 32-bit PowerShell → rundll32 activity → HTTP C2 channel). Confidence is 0.95 rather than 1.0 only because cmdline is unavailable to confirm the specific commands, and malfind couldn't confirm injection.
- evidence: `vol_psscan` (sha256 `b7e9c4731b1c230f…`)
- evidence: `vol_netscan` (sha256 `43647f01f3d9935c…`)

### [medium] Suspicious Uninstall.exe execution: cmd.exe (PID 4808) spawned Uninstall.exe (PID 2340) on 2018-09-06 16:36:33. The binary ran for only 2 seconds and made a TCP connection to 172.16.7.12:135 (RPC endpoint mapper) before exiting — consistent with lateral movement or reconnaissance.
- confidence: 0.85
- ATT&CK: T1021.003, T1047
- Skeptic: The factual elements (cmd.exe PID 4808 spawned Uninstall.exe PID 2340, 2-second runtime, TCP to 172.16.7.12:135) are all directly supported by psscan and netscan evidence. The "lateral movement/recon" label is inferential but reasonable given the RPC endpoint mapper target, cmd.exe parentage, and extremely short execution window. Confidence is 0.85 rather than higher because (a) cmd.exe's parent PID 6956 is missing from psscan, leaving the launch chain incomplete; (b) pslist/cmdline/malfind/svcscan all returned empty, limiting corroboration; and (c) without the binary path or hash, we cannot definitively rule out a legitimate but oddly-behaved uninstaller.
- evidence: `vol_psscan` (sha256 `b7e9c4731b1c230f…`)
- evidence: `vol_netscan` (sha256 `43647f01f3d9935c…`)

### [medium] ngentask.exe (PID 7092) established two TCP connections to 172.16.4.10:8080 within its 1-second lifespan — the same destination IP:port contacted by two long-running powershell.exe processes (PIDs 3164 and 4072). powershell.exe PID 4072 was spawned via WMI (parent WmiPrvSE.exe PID 1196); its child powershell.exe PID 3164 spawned approximately 28 short-lived rundll32.exe instances (2–38 seconds each) over 7 days. The destination 172.16.4.10:8080 is contacted exclusively by these three processes. ngentask.exe — a .NET compilation tool — has no legitimate operational reason for outbound HTTP connections. While cmdline and DLL data are unavailable to confirm C2 commands, the aggregate behavioral pattern is highly anomalous and consistent with attacker activity.
- confidence: 0.85
- ATT&CK: T1047, T1059.001, T1071.001, T1218.011, T1105
- Skeptic: Every factual sub-claim in the finding is directly supported by raw evidence: (a) ngentask.exe PID 7092 has two CLOSED TCPv4 connections to 172.16.4.10:8080 (LocalPorts 56322, 56324) in netscan; (b) psscan shows its lifespan is exactly 1 second (2018-09-06T07:27:10→07:27:11); (c) powershell.exe PID 3164 (CLOSE_WAIT on LocalPort 56932) and PID 4072 (CLOSED on LocalPort 54794) both connect to the same 172.16.4.10:8080; (d) PID 4072 PPID=1196 (WmiPrvSE.exe) confirms WMI spawning; (e) PID 3164 PPID=4072 confirms parent-child; (f) exactly 28 rundll32.exe entries with PPID=3164 in psscan, spanning Aug 30–Sep 6, with lifespans from 2 to 38 seconds; (g) no other process in the 145-entry netscan contacts 172.16.4.10 on any port. The assessment that ngentask.exe has no legitimate reason for outbound HTTP connections is well-founded (NGEN compiles on-disk assemblies, never fetches over HTTP). The key limitation — empty EPROCESS list preventing cmdline/DLL/injection analysis — is acknowledged by the investigator and does not weaken the confirmed network/process-pool facts. Confidence is 0.85 rather than higher only because Created=null on all four 172.16.4.10:8080 connections and the ngentask.exe parent (PPID 2536) is absent from psscan, leaving minor timeline and ancestry gaps.
- evidence: `vol_netscan` (sha256 `43647f01f3d9935c…`)
- evidence: `vol_psscan` (sha256 `b7e9c4731b1c230f…`)

## Inferred (6)
### [critical] Backdoor process "subject_srv.ex" (PID 6160): Running as a child of services.exe (PPID 536), 32-bit (Wow64) on 64-bit OS, 12 threads, created 2018-09-06 19:25:36. Listening on TCP port 3262 (0.0.0.0 and ::), with an ESTABLISHED C2 connection to 172.16.5.50:44262.
- confidence: 0.75
- ATT&CK: T1543.003, T1571
- Skeptic: The factual elements of the claim are solidly confirmed by psscan and netscan: process "subject_srv.ex" (PID 6160, PPID 536/services.exe), Wow64=true, 12 threads, created 2018-09-06 19:25:36, listening on TCP 3262 (0.0.0.0 + ::), and an ESTABLISHED connection to 172.16.5.50:44262. However, critical plugins (pslist, cmdline, dlllist, malfind, svcscan, pstree) all return empty — the memory image appears to have EPROCESS list corruption, limiting analysis to pool-scanning artifacts only. The "backdoor" classification and "C2" label are plausible inferences but cannot be directly proven: the process could be a custom enterprise monitoring agent, an NCPA-adjacent component, or another legitimate tool. Without cmdline, DLL list, binary path, or injection evidence, calling it definitively a backdoor overreaches the available evidence. Confidence reduced from 1.00 to 0.75 due to these evidential gaps.
- evidence: `vol_psscan` (sha256 `b7e9c4731b1c230f…`)
- evidence: `vol_netscan` (sha256 `43647f01f3d9935c…`)

### [high] Rundll32 beaconing/execution pattern: The 32-bit powershell.exe (PID 3164) spawned at least 28 rundll32.exe processes in rapid bursts across multiple days (Aug 30, Aug 31, Sep 5, Sep 6 2018). Each rundll32.exe ran for only 2–5 seconds and had 0 threads at capture time, consistent with a C2 beacon or staged payload execution model.
- confidence: 0.72
- ATT&CK: T1218.011, T1059.001
- Skeptic: The factual elements of the claim are largely corroborated by psscan: powershell.exe PID 3164 is 32-bit (Wow64=true), spawned 28 short-lived 64-bit rundll32.exe children across four days, all with 0 threads at capture. However, the "beaconing/C2" interpretation cannot be directly confirmed because cmdline/dlllist/malfind all failed (empty EPROCESS list), no rundll32 network artifacts exist in netscan, a minority of runtimes exceed the "2–5 seconds" claim, and alternative benign explanations (scheduled monitoring tasks) exist on this managed server. The finding is plausible but the evidence quality does not warrant the 1.00 confidence claimed.
- evidence: `vol_psscan` (sha256 `b7e9c4731b1c230f…`)

### [high] Common C2 infrastructure at 172.16.4.10:8080: At least three separate processes connected to this IP/port — powershell.exe PID 3164 (CLOSE_WAIT), powershell.exe PID 4072 (CLOSED), and ngentask.exe PID 7092 (two CLOSED connections, ephemeral ports 56322 and 56324). This indicates a shared C2 server used by multiple compromised processes.
- confidence: 0.85
- ATT&CK: T1571, T1071.001
- Skeptic: The factual core — three processes (powershell.exe 3164, powershell.exe 4072, ngentask.exe 7092) connecting to 172.16.4.10:8080 — is directly confirmed by netscan with 4 distinct TCP sockets. Psscan independently confirms the process names, PIDs, and relationships. However, the leap to "C2 infrastructure" is inferential: we cannot see packet payloads, process command lines, or loaded DLLs (all related plugins fail on this image). The circumstantial evidence strongly favors malicious C2 — powershell.exe 4072 was WMI-launched (PPID WmiPrvSE.exe 1196), powershell.exe 3164 spawned ~25 short-lived rundll32.exe children (classic Cobalt Strike pattern), and ngentask.exe lived only 1 second while making two TCP connections (anomalous for legitimate .NET NGEN). But without payload inspection or code analysis, a legitimate internal proxy/application server at 172.16.4.10:8080 cannot be logically excluded. Hence, inferred rather than confirmed.
- evidence: `vol_netscan` (sha256 `43647f01f3d9935c…`)
- evidence: `vol_psscan` (sha256 `b7e9c4731b1c230f…`)

### [high] WMI-based persistence: The initial PowerShell C2 process (PID 4072, powershell.exe) was spawned by WmiPrvSE.exe (PID 1196) on 2018-08-28 22:08:25. WmiPrvSE.exe is the WMI Provider Host, and spawning PowerShell from it is a well-known technique for WMI event subscription persistence (e.g., __EventFilter / __EventConsumer bindings).
- confidence: 0.75
- ATT&CK: T1546.003
- Skeptic: The factual core — PID 4072 (powershell.exe, PPID 1196/WmiPrvSE.exe, CreateTime 2018-08-28 22:08:25) — is directly supported by psscan. Netscan confirms both PowerShell processes had TCP connections to 172.16.4.10:8080, supporting C2 characterization. However, the specific claim of "__EventFilter / __EventConsumer bindings" (WMI event subscription persistence) is not directly evidenced. Multiple plugins (pslist, pstree, cmdline, svcscan, malfind) returned empty results, indicating significant memory structure corruption. The evidence comes from a single memory view (psscan) with no corroborating EPROCESS list data. Alternative explanations for WmiPrvSE spawning PowerShell (legitimate WMI administration, scheduled tasks via WMI, WinRM) cannot be excluded. The persistence mechanism is plausible and consistent with the evidence, but not directly proven.
- evidence: `vol_psscan` (sha256 `b7e9c4731b1c230f…`)

### [medium] Suspicious ngentask.exe C2 connections: ngentask.exe (PID 7092, parent PID 2536) ran briefly on 2018-09-06 07:27:10–07:27:11 and made two TCP connections to 172.16.4.10:8080 (the shared C2 server). While ngentask.exe is a legitimate .NET NGEN task binary, its use of the C2 channel suggests it was either hijacked or is a renamed malicious binary.
- confidence: 0.65
- ATT&CK: T1571, T1036.003
- Skeptic: The raw evidence from psscan confirms ngentask.exe (PID 7092, PPID 2536) existed briefly (07:27:10–07:27:11 UTC). Netscan independently confirms two TCPv4 connections from PID 7092 to 172.16.4.10:8080 (CLOSED). However, the C2 interpretation rests on powershell.exe PIDs 3164/4072 also connecting to the same server. No direct evidence confirms the binary is malicious, hijacked, or renamed — malfind, dlllist, and cmdline all returned empty due to the degraded memory state (pslist also empty). The parent PID 2536 is unidentifiable. The connections are CLOSED, providing no timing data to link them precisely to the process's 1-second window. These gaps prevent full confirmation but the correlation with powershell C2 activity makes the inference plausible.
- evidence: `vol_psscan` (sha256 `b7e9c4731b1c230f…`)
- evidence: `vol_netscan` (sha256 `43647f01f3d9935c…`)

### [medium] ngentask.exe (PID 7092, PPID 2536) established two TCP connections to 172.16.4.10:8080 — the same IP:port used by powershell.exe C2 processes (PIDs 3164 and 4072). The connections are correlated with malicious C2 infrastructure, but no direct evidence confirms the ngentask.exe binary itself was hijacked, replaced, or otherwise tampered with.
- confidence: 0.55
- ATT&CK: T1043, T1071.001
- Skeptic: The claim contains two layers: factual (connections exist, same IP:port) and interpretive (C2/malicious). The factual layer is directly confirmed by netscan and psscan. The interpretive layer relies on labeling powershell.exe as C2, but with cmdline/dlllist/malfind all returning empty, no raw evidence proves powershell.exe was executing C2 commands — only that it connected to the same IP:port. Alternative explanations (internal web service, monitoring agent, McAfee-adjacent infrastructure on port 8080 near port 8081) cannot be ruled out. The investigator's own 0.65 confidence and admission of no tampering evidence align with this assessment. Confidence 0.55 reflects: connections confirmed (+), IP:port correlation confirmed (+), but C2 label unproven and alternative explanations viable (−).
- evidence: `vol_psscan` (sha256 `b7e9c4731b1c230f…`)
- evidence: `vol_netscan` (sha256 `43647f01f3d9935c…`)
