# MITRE ATT&CK Shortlist — Host/Log Correlation

15 techniques selected for detectability from host + log evidence alone
(Windows Event Logs, syslog, basic network connection logs) — no memory or
disk forensics required, matching MVP scope.

| # | Technique ID | Technique Name | Tactic | Log/Event Indicator | Priority |
|---|---|---|---|---|---|
| 1 | T1078 | Valid Accounts | Initial Access / Persistence | 4624 (logon) at unusual time/source/account; repeated 4625 followed by success | High |
| 2 | T1110 | Brute Force | Credential Access | Multiple 4625 (failed logon) in a short window against one account or from one source | High |
| 3 | T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | 4104 (script block logging) or 4688 with `powershell.exe`, especially `-enc`/`-EncodedCommand` | High |
| 4 | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution | 4688 with `cmd.exe` as parent spawning unusual child processes | Medium |
| 5 | T1053.005 | Scheduled Task | Persistence / Execution | 4698 (task created) or 4702 (task updated) with unfamiliar task name or binary path | High |
| 6 | T1543.003 | Create or Modify System Process: Windows Service | Persistence | 7045 (new service installed) with unusual name/path, e.g. in Temp or user-writable dirs | High |
| 7 | T1136 | Create Account | Persistence | 4720 (account created) outside normal provisioning windows | Medium |
| 8 | T1098 | Account Manipulation | Persistence / Privilege Escalation | 4732 (member added to security group), especially admin groups | Medium |
| 9 | T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion | 1102 (audit log cleared) | High |
| 10 | T1105 | Ingress Tool Transfer | Command and Control | Outbound connection to unfamiliar IP followed by new file creation or process execution | High |
| 11 | T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | Outbound HTTP/HTTPS to new/non-standard domains at odd hours from non-browser processes | Medium |
| 12 | T1021.001 | Remote Services: RDP | Lateral Movement | 4624 with LogonType 10 (RemoteInteractive) from unexpected source host | Medium |
| 13 | T1560 | Archive Collected Data | Collection | Process creation invoking `zip`/`rar`/`tar`/`7z` shortly before an outbound connection | Medium |
| 14 | T1041 | Exfiltration Over C2 Channel | Exfiltration | Sustained outbound transfer to a host already flagged under T1105 or T1071.001 | High |
| 15 | T1204.002 | User Execution: Malicious File | Execution | 4688 showing a script/executable launched from Downloads/Temp by an Office process | Medium |

## Suggested attack-chain demo path

For the MVP demo, these techniques chain naturally into a single narrative
if the dataset supports it:

```
T1078 / T1110  →  T1059.001  →  T1053.005 / T1543.003  →  T1070.001
   (access)        (execution)      (persistence)          (evasion)
     →  T1105 / T1071.001  →  T1560  →  T1041
          (C2)              (collect)  (exfil)
```

This gives the Correlation Agent a coherent end-to-end scenario to map
evidence against, and gives the Hypothesis Agent a natural six-stage
structure to fill in (see `prompt_design.md`).

## Notes

- All fields map directly to `artifact_type` / `event_id` in the normalized
  event schema — no additional parsing logic is required beyond what the
  Collector Agent already extracts.
- Priority reflects how strong and unambiguous the log signal is on its
  own, not how severe the technique is — use it to decide correlation
  rule order, not incident severity scoring.
