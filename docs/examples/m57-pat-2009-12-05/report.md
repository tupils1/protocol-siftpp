# Incident Report — m57-pat-2009-12-05

- Evidence: `C:\Users\Administrator\find-evil\evidence\m57-pat-2009-12-05\extracted\pat-2009-12-05.winddramimage`
- Evidence sha256: `91df773dd3316d447661085715344e3aa58b136815698e2cc03dbffc777a9e1b`
- Self-correction iterations: 2
- Summary: 4 confirmed of 9 findings; 2 self-correction iteration(s); evidence integrity verified.

## Confirmed (4)
### [critical] ToolKeyloggerDLL.dll is injected into explorer.exe (PID 168) at base address 0x10000000. The DLL is loaded from C:\Program Files\XP Advanced\DLLs\ToolKeyloggerDLL.dll with LoadCount=1, indicating it was deliberately injected rather than loaded as a normal shared dependency. Explorer.exe is the Windows shell — injecting a keylogging DLL here allows the malware to intercept keystrokes and window messages across the entire user session.
- confidence: 0.95
- ATT&CK: T1055.001, T1056.001
- Skeptic: The core factual claims are directly confirmed by the raw evidence: ToolKeyloggerDLL.dll is loaded in explorer.exe (PID 168) at base 0x10000000 (268435456 decimal), from path C:\Program Files\XP Advanced\DLLs\ToolKeyloggerDLL.dll, with LoadCount=1. The LoadCount of 1 (versus -1 for static imports) indicates dynamic loading via LoadLibrary, which in context of a process named ToolKeylogger.exe running as a child of explorer.exe strongly supports the injection interpretation. Malfind showed no RWX regions, but that is expected for LoadLibrary-based injection which retains file backing. The Windows shell context and keylogging implication is a standard and accurate analytical assessment. The only minor caveat is that the exact injection mechanism (CreateRemoteThread vs AppInit_DLLs vs SetWindowsHookEx) is not directly evidenced, but the loading itself is unequivocal.
- evidence: `vol_dlllist` (sha256 `7ee3c22e0c1c453a…`)
- evidence: `vol_pslist` (sha256 `5c9aae21c57472b4…`)

### [medium] PID 280 (ToolKeylogger.exe, path C:\Program Files\XP Advanced\ToolKeylogger.exe) is a child process of explorer.exe (PID 168). Explorer.exe started at 02:11:20 UTC; ToolKeylogger.exe started at 02:11:23 UTC — a 3-second delta consistent with user-logon autostart execution. However, the specific persistence mechanism (e.g., registry Run keys, Startup folder) cannot be determined from memory alone — no registry analysis tools are available, and the command line contains no switches or parent-process evidence pointing to a specific autostart location.
- confidence: 0.85
- ATT&CK: T1547.001
- Skeptic: Every directly observable element is corroborated by multiple independent Volatility plugins. The parent-child relationship (PID 280 → PPID 168), the 3-second CreateTime delta, the executable path, and the empty command line are all confirmed by pslist, pstree, cmdline, and psscan. The "autostart" label is an inference but a well-supported one given the batch-launch pattern at 02:11:23 across six explorer.exe children. The investigator's own acknowledgment that the precise persistence mechanism cannot be determined without registry tools is honest and correct. One minor note: pslist truncates the ImageFileName to "ToolKeylogger.e" (14-char EPROCESS limit on XP), but the full name is confirmed by both pstree (Path) and dlllist (Name/Path). This does not weaken the finding.
- evidence: `vol_pslist` (sha256 `5c9aae21c57472b4…`)
- evidence: `vol_pstree` (sha256 `6265a576df08049c…`)
- evidence: `vol_cmdline` (sha256 `4022f8c40da55b82…`)

### [medium] No hidden or unlinked processes were detected: vol_pslist returned 33 active processes and vol_psscan also returned 33, with identical PIDs in both outputs. No terminated or pool-only remnants of additional malware processes were found. However, vol_malfind for PID 168 (explorer.exe) returned zero results, meaning the claim of "injected code" in explorer.exe is directly refuted. ToolKeyloggerDLL.dll is loaded in explorer.exe (Base 0x10000000, Path C:\Program Files\XP Advanced\DLLs\ToolKeyloggerDLL.dll, Size 192512) as a normally-backed module — this is a legitimate loaded DLL (not code injection via RWX private regions). The same DLL is also loaded in PID 280 (ToolKeylogger.exe). This means the keylogger DLL is present in the shell process via normal loading, not injection. vol_netscan is completely broken on this XP image and vol_malfind crashes for PID 280 (VAD tree too deep).
- confidence: 0.90
- ATT&CK: T1055, T1120
- Skeptic: Every factual sub-claim checks out against independent tool runs: (1) pslist/psscan both yield 33 identical PIDs with no pool-only remnants; (2) vol_malfind for PID 168 returns zero results; (3) ToolKeyloggerDLL.dll in explorer.exe is file-backed at 0x10000000, not a private RWX region; (4) the same DLL is file-backed in PID 280; (5) netscan crashes with NotImplementedError on this XP image; (6) malfind for PID 280 crashes with "Vad tree is too deep." The only caveat is that malfind's emptiness does not rule out all injection techniques (e.g., reflective DLL injection, hooking), so the word "refuted" is scoped to malfind-style private-RWX injection. That nuance accounts for the 0.90 rather than 1.0 confidence.
- evidence: `vol_pslist` (sha256 `5c9aae21c57472b4…`)
- evidence: `vol_psscan` (sha256 `e95531207f893372…`)
- evidence: `vol_malfind` (sha256 `7eb70257593da06f…`)
- evidence: `vol_dlllist` (sha256 `fe2a17f18bf471ec…`)
- evidence: `vol_netscan` (sha256 `7eb70257593da06f…`)
- evidence: `vol_svcscan` (sha256 `929941027717a07d…`)

### [low] PID 280 (ToolKeylogger.exe from "C:\Program Files\XP Advanced\") loads WinSock (ws2_32.dll, WS2HELP.dll) and the WinINet HTTP/HTTPS client stack (WININET.dll, urlmon.dll, iertutil.dll), giving the process TCP/IP networking and HTTP communication capability. It also loads ieframe.dll (IE browser frame container for embedded browser UI) and msxml3.dll (XML parsing). The process loads vendor-ecosystem DLLs: ToolKeyloggerDLL.dll (core keylogging), SkinMagic.dll (UI skinning), and LicenseManager.dll from XPToolsLicenseComponent (license validation — same "XPTools"/"XP Advanced" vendor suite). No actual network connections, remote endpoints, or data exfiltration can be confirmed: vol_netscan is incompatible with Windows XP SP3 (raises NotImplementedError), and vol_malfind fails with a VAD tree depth error. The DLL evidence demonstrates networking and keylogging capability but does not prove active C2 or exfiltration.
- confidence: 0.92
- ATT&CK: T1056.001, T1071.001
- Skeptic: Every factual claim about loaded DLLs (names, paths, PIDs) is directly corroborated by my independent vol_dlllist run. The tool failures (netscan NotImplementedError, malfind VAD tree depth) are also independently verified. The interpretive labels (e.g., "core keylogging", "UI skinning", "license validation", "vendor suite") are reasonable inferences from the DLL names and install paths but not independently proven — however, the analyst explicitly frames these as capability evidence, not proof of activity, and correctly notes the absence of exfiltration proof. Confidence is slightly reduced (0.92 vs 0.85) only because "core keylogging" from ToolKeyloggerDLL.dll is a name-based inference without behavioral confirmation, but the overall finding remains solidly supported.
- evidence: `vol_dlllist` (sha256 `0dcd2a46810ccbef…`)
- evidence: `vol_pslist` (sha256 `5c9aae21c57472b4…`)
- evidence: `vol_pstree` (sha256 `6265a576df08049c…`)
- evidence: `vol_cmdline` (sha256 `4022f8c40da55b82…`)
- evidence: `vol_netscan` (sha256 `7eb70257593da06f…`)
- evidence: `vol_malfind` (sha256 `7eb70257593da06f…`)
- evidence: `vol_psscan` (sha256 `e95531207f893372…`)

## Inferred (4)
### [critical] PID 280 (ToolKeylogger.e / ToolKeylogger.exe) is a malicious keylogger process running from C:\Program Files\XP Advanced\ToolKeylogger.exe. Its ImageFileName is truncated to 14 chars in the EPROCESS structure. It loads a dedicated keylogging DLL (ToolKeyloggerDLL.dll), a UI skinning library (SkinMagic.dll), and a license manager from XPToolsLicenseComponent. The process has 675 handles, unusually high for a user application. It was launched by explorer.exe (PID 168).
- confidence: 0.75
- ATT&CK: T1056.001, T1056
- Skeptic: The core factual claims (PID, path, DLLs, parent, handle count, EPROCESS truncation) are all directly supported by the raw evidence and therefore not refuted. However, the "malicious" classification requires an inference about intent and authorization that memory forensics alone cannot prove — this is a commercial-grade keylogger with a licensing component, not necessarily malware. The "unusually high handles" characterization is borderline. Overall, the finding is plausible and well-supported factually, but falls short of "confirmed" on the interpretive elements. Confidence 0.75 reflects high agreement on the facts, moderate on the interpretation.
- evidence: `vol_pslist` (sha256 `5c9aae21c57472b4…`)
- evidence: `vol_pstree` (sha256 `6265a576df08049c…`)
- evidence: `vol_cmdline` (sha256 `4022f8c40da55b82…`)
- evidence: `vol_dlllist` (sha256 `7ee3c22e0c1c453a…`)

### [high] The ToolKeylogger malware has network exfiltration capability. PID 280 loads ws2_32.dll and WS2HELP.dll (Windows Sockets API) plus WININET.dll, urlmon.dll, iertutil.dll, and ieframe.dll (Internet Explorer HTTP/HTTPS stack). This combination enables the keylogger to exfiltrate captured keystrokes to a remote server over HTTP or raw TCP sockets. Network connection data is unavailable due to vol_netscan incompatibility with Windows XP SP3.
- confidence: 0.60
- ATT&CK: T1041, T1071.001
- Skeptic: The DLL loading facts are correct: PID 280 (ToolKeylogger.exe) does load ws2_32.dll, WS2HELP.dll, WININET.dll, urlmon.dll, iertutil.dll, and ieframe.dll. These provide Windows Sockets and IE HTTP/HTTPS capabilities. However, the claim that this combination "enables the keylogger to exfiltrate captured keystrokes to a remote server" is an inference, not directly shown by the DLL evidence alone. Loading networking DLLs demonstrates networking *capability*, not exfiltration *behavior*. Alternative benign explanations exist (license validation, GUI-embedded browser, update checks). The netscan incompatibility means we cannot confirm or refute actual network connections. Confidence is moderate (0.60): the DLL presence is solidly confirmed, but the exfiltration purpose remains speculative without connection data or behavioral evidence.
- evidence: `vol_dlllist` (sha256 `7ee3c22e0c1c453a…`)
- evidence: `vol_netscan` (sha256 `7eb70257593da06f…`)

### [high] The ToolKeylogger achieves user-mode persistence by launching as a child process of explorer.exe (PID 168). Explorer.exe is the Windows shell, and child processes spawned by it at user login typically originate from registry Run keys (HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run) or the Startup folder. The keylogger process was created at 2009-12-05T02:11:23, approximately 21 seconds after explorer.exe started (02:11:20), consistent with autostart execution at user logon.
- confidence: 0.55
- ATT&CK: T1547.001
- Skeptic: The claim has two parts: (a) ToolKeylogger is a child of explorer.exe launched near logon — this is directly supported. (b) The persistence mechanism is specifically registry Run keys or Startup folder — this is NOT supported by the cited tools and is pure inference. The investigator also miscalculated the time delta (3s, not 21s). The finding is plausible (autostart is a reasonable guess) but not directly evidenced, so it's inferred rather than confirmed. Confidence is moderate (0.55) because the factual error and unsupported leap on mechanism reduce trust in the analysis.
- evidence: `vol_pstree` (sha256 `6265a576df08049c…`)
- evidence: `vol_pslist` (sha256 `5c9aae21c57472b4…`)
- evidence: `vol_cmdline` (sha256 `4022f8c40da55b82…`)

### [medium] PID 280 (ToolKeylogger.exe) loads the Windows Sockets API stack (ws2_32.dll, WS2HELP.dll) and the Internet Explorer HTTP/HTTPS stack (WININET.dll, urlmon.dll, iertutil.dll, ieframe.dll), demonstrating the process has networking and HTTP communication capability. However, vol_netscan is incompatible with Windows XP SP3 and fails entirely — no actual network connections, remote endpoints, or exfiltration behavior can be confirmed or refuted. The presence of LicenseManager.dll (XPToolsLicenseComponent) provides a benign alternative explanation for network capability (license validation).
- confidence: 0.60
- ATT&CK: T1071.001, T1041
- Skeptic: The raw DLL-loading facts are directly supported by vol_dlllist output and the netscan failure is confirmed. However, the characterization of LicenseManager.dll as a "benign alternative explanation" is misleading — it lives in XPToolsLicenseComponent, almost certainly the same vendor ("XP Advanced" / "XPTools") that ships the keylogger. This makes it part of the same software ecosystem, not an independent benign factor. Additionally, ieframe.dll (11 MB, IE frame/window container) is mischaracterized as part of the "HTTP/HTTPS stack" — it is primarily a browser UI framework, though it ships with IE. The severity of "medium" is questionable given zero confirmed network connections (netscan inoperable on XP SP3) and no evidence of actual data exfiltration. The core factual observations are correct but the interpretive framing inflates the threat level.
- evidence: `vol_dlllist` (sha256 `fe2a17f18bf471ec…`)
- evidence: `vol_netscan` (sha256 `7eb70257593da06f…`)
- evidence: `vol_pslist` (sha256 `5c9aae21c57472b4…`)
- evidence: `vol_cmdline` (sha256 `4022f8c40da55b82…`)

## Refuted (1)
### [info] No hidden or unlinked processes were detected. vol_psscan returned 33 processes, matching vol_pslist's 33 exactly. All processes visible in the active process list were also found by pool scanning, and no terminated/hidden remnants of additional malware processes were discovered. The compromise is confined to the ToolKeylogger family (ToolKeylogger.exe PID 280 and its injected DLL in explorer.exe PID 168). No malicious Windows services related to the keylogger were found in the 234 services enumerated by vol_svcscan.
- confidence: 0.65
- Skeptic: The finding makes three sub-claims, of which one is directly refuted: the "injected DLL" in explorer.exe. Malfind returned zero results for PID 168 — ToolKeyloggerDLL.dll is a normally loaded module with disk backing, not injected code. This materially changes the nature of the compromise assessment. The pslist/psscan parity claim (no hidden processes) is confirmed. The svcscan claim about no malicious services is partially verifiable but not fully confirmable due to truncation, and netscan failed entirely. Given the core "injection" assertion is wrong and two tools produced errors/gaps, the overall confidence must be downgraded and the claim marked as refuted in its current form.
- evidence: `vol_pslist` (sha256 `5c9aae21c57472b4…`)
- evidence: `vol_psscan` (sha256 `e95531207f893372…`)
- evidence: `vol_svcscan` (sha256 `929941027717a07d…`)
