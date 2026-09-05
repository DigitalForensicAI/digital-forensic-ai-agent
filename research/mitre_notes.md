# MITRE-Related Notes (for Person 3)

**Author:** Person 4 (Research / Dataset)
**Priority:** Day 2
**Purpose:** Point out which activities in our chosen data likely correspond to MITRE ATT&CK techniques, and give general event → technique heuristics. Person 3 will handle the actual correlation code — this is reference material, not an implementation.

## Techniques present in `incident_01.csv` (worked example)

| Event(s) in sample | Activity | MITRE Technique | Tactic |
|---|---|---|---|
| 1 | Obfuscated PowerShell execution | T1059.001 (PowerShell) | Execution |
| 2 | Tool dropped to disk from PowerShell | T1105 (Ingress Tool Transfer) | Command and Control |
| 3–5 | `m.exe` opens a handle into `lsass.exe` and dumps credentials | T1003.001 (LSASS Memory) | Credential Access |
| 6–8 | Directory replication request to DC mimicking a domain controller peer | T1003.006 (DCSync) | Credential Access |
| 9 | Logon success following replication rights use | T1078 (Valid Accounts) | Defense Evasion / Persistence |
| 10 | Dumped output written to disk | T1074.001 (Local Data Staging) | Collection |
| 11 | Output compressed before transfer | T1560 (Archive Collected Data) | Collection |
| 12–13 | Outbound HTTPS connection carrying the archive | T1041 (Exfiltration Over C2 Channel) / T1071.001 (Web Protocols) | Exfiltration / Command and Control |
| 14–15 | Attacker process killed, dump file deleted | T1070 (Indicator Removal) / T1070.004 (File Deletion) | Defense Evasion |

This gives a full **kill-chain-style spread across 6 tactics** (Execution → C2 → Credential Access → Collection → Exfiltration → Defense Evasion) from a single 15-row sample — useful for testing that the correlation logic isn't just pattern-matching one tactic.

## General event → technique heuristics (for extending beyond this sample)

These are common, well-established mappings that show up across most Windows/Sysmon-based datasets (including future Mordor sessions or BOTS data), useful as a starting rule set:

- **Process accesses `lsass.exe` (Sysmon EID 10)** → credential dumping family (T1003.x). Sub-technique depends on *how* — direct memory read (T1003.001) vs. registry SAM/SECURITY hive dump (T1003.002) vs. NTDS.dit access (T1003.003) vs. DCSync-style replication request (T1003.006, seen as EVTX 4662 on a DC, not an lsass access at all).
- **PowerShell/cmd with encoded, obfuscated, or download-cradle command lines** → T1059 (Command and Scripting Interpreter) for execution, often paired with T1027 (Obfuscated Files or Information) or T1140 (Deobfuscate/Decode Files) if there's a decode step visible.
- **New scheduled task, new service, or registry Run-key write** → persistence family: T1053 (Scheduled Task/Job), T1543 (Create/Modify System Process), or T1547.001 (Registry Run Keys).
- **Unusual parent/child process pairs** (e.g. `winword.exe` spawning `powershell.exe`, or `svchost.exe` spawning a shell) → T1055 (Process Injection) or general suspicious execution; strong candidate for "unusual" flagging even without a specific technique match.
- **Outbound connection to a rare/external IP shortly after file staging or archiving activity** → T1041/T1048 (Exfiltration) family; correlate timing (archive → connection within a short window) rather than any single event.
- **File or event log deletion, process/service stop shortly after suspicious activity** → T1070 (Indicator Removal) family — usually the last step in a chain, useful as a "closing" signal for timeline reconstruction.
- **Logon events with unusual logon type (e.g. Type 3 network logon under an admin account from an atypical source) or immediately following privilege-related events (EVTX 4672)** → T1078 (Valid Accounts) or lateral movement family (T1021.x), depending on the protocol used.

## Practical note for the correlation logic

- Technique confidence should generally come from a **combination** of fields (process name/hash + target object + parent process + timing), not a single field — several techniques share the same raw event type (e.g. T1003.001 vs. T1003.002 both start as a process touching sensitive OS memory/files, but the target differs).
- Where the sample data doesn't give enough signal to be certain (e.g. we don't have a file hash for `m.exe` in this trimmed sample), it's fine for the correlation output to carry a confidence/likelihood note rather than a hard label — that's consistent with the "evidence-grounded" design goal: only claim what the evidence actually supports.
