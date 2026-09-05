# MITRE ATT&CK Shortlist — Host/Log Correlation

15 techniques relevant to host + log based incidents, for the correlation
module.

| Technique ID | Technique Name | Log/Event Indicator |
|---|---|---|
| T1078 | Valid Accounts | 4624 (logon) at unusual time/source; repeated 4625 followed by success |
| T1110 | Brute Force | Multiple 4625 (failed logon) in a short window against one account |
| T1059.001 | PowerShell | 4104 (script block) or 4688 with `powershell.exe`, especially `-enc` |
| T1059.003 | Windows Command Shell | 4688 with `cmd.exe` spawning unusual child processes |
| T1053.005 | Scheduled Task | 4698/4702 with unfamiliar task name or binary path |
| T1543.003 | Windows Service | 7045 (new service) with unusual name/path, e.g. in Temp |
| T1136 | Create Account | 4720 (account created) outside normal provisioning windows |
| T1098 | Account Manipulation | 4732 (added to security group), especially admin groups |
| T1070.001 | Clear Windows Event Logs | 1102 (audit log cleared) |
| T1105 | Ingress Tool Transfer | Outbound connection to unfamiliar IP followed by new file/process |
| T1071.001 | Web Protocols (C2) | Outbound HTTP/HTTPS to new domains at odd hours from non-browser processes |
| T1021.001 | Remote Desktop Protocol | 4624 with LogonType 10 from unexpected source host |
| T1560 | Archive Collected Data | Process creation invoking `zip`/`rar`/`tar`/`7z` before outbound connection |
| T1041 | Exfiltration Over C2 Channel | Sustained outbound transfer to a host already flagged for T1105/T1071.001 |
| T1204.002 | User Execution: Malicious File | 4688 showing script/executable launched from Downloads/Temp |
