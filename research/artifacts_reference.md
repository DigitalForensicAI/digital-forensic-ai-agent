# Forensic Artifact Reference

**Author:** Person 4 (Research / Dataset)
**Priority:** Day 2
**Purpose:** Give Person 2 (parser/timeline dev) a quick reference for what fields common logs/artifacts actually contain, and how those fields map onto our canonical event format so the parser has a consistent schema to normalize into.

## Canonical event format (target schema)

Every event the parser emits should be normalizable to these fields (some optional per source):

| Field | Meaning |
|---|---|
| `event_id` | Internal sequence/row id assigned by our pipeline (not a Windows Event ID) |
| `timestamp` | UTC, ISO-8601 |
| `host` | Hostname or IP of the machine the event occurred on |
| `log_source` | Which artifact/log produced the event (Sysmon, WinEventLog-Security, auth.log, Zeek-conn, etc.) |
| `sysmon_event_id` / `native_event_id` | The original event ID from the source log, if applicable |
| `process_name`, `process_id` | The process associated with the event |
| `parent_process_name`, `parent_process_id` | The launching process, if applicable |
| `user` | Account associated with the event |
| `action` | Normalized verb: ProcessCreate, ProcessAccess, FileCreate, FileDelete, NetworkConnect, LogonSuccess, LogonFailure, DirectoryReplicationRequest, etc. |
| `target_object` | File path, registry key, process handle target, or replicated object, depending on `action` |
| `command_line` | Full command line, if captured |
| `network_dest_ip`, `network_dest_port` | Destination of a network connection, if applicable |
| `mitre_technique`, `mitre_tactic` | Filled in later by Person 3's correlation step — not expected from raw logs |

## Artifact → useful fields → mapping

| Artifact / Log | What it's good for | Key fields to extract | Maps to canonical field(s) |
|---|---|---|---|
| **Windows Security Event Log (EVTX)** | Authentication, account management, object access, and — critically — Active Directory replication requests. Core events: 4624 (logon success), 4625 (logon failure), 4672 (special/admin privileges assigned), 4688 (process creation, if enabled), 4662 (directory service object access, e.g. DCSync). | EventID, TimeCreated, SubjectUserName/TargetUserName, LogonType, IpAddress, ProcessName, ObjectType/Properties (for 4662) | `timestamp`, `user`, `action` (LogonSuccess/LogonFailure/DirectoryReplicationRequest), `network_dest_ip` (for remote logons), `sysmon_event_id`/`native_event_id` = the EventID |
| **Sysmon** | High-fidelity endpoint telemetry: process creation with full command line and hashes (Event ID 1), network connections (3), process termination (5), file creation (11), process access — e.g. handle opened to lsass.exe (10), file delete (23), registry events (12–14). | EventID, UtcTime, Image, ProcessId, ParentImage, ParentProcessId, CommandLine, TargetFilename, DestinationIp, DestinationPort, TargetObject | `sysmon_event_id`, `process_name`, `process_id`, `parent_process_name`, `parent_process_id`, `command_line`, `target_object`, `network_dest_ip`, `network_dest_port` |
| **Linux auth.log / secure log** | SSH and local authentication attempts, sudo usage, account changes. | Timestamp, hostname, PAM/sshd message text, source IP, username, session open/close | `timestamp`, `host`, `user`, `action` (LogonSuccess/LogonFailure), `network_dest_ip` (source becomes relevant context) |
| **Linux auditd** | Fine-grained syscall-level auditing: process exec, file access, privilege use — the closest Linux equivalent to Sysmon. | `type=SYSCALL`/`EXECVE` records, `pid`, `ppid`, `exe`, `comm`, `uid`, `auid`, argument list | `process_name`, `process_id`, `parent_process_id`, `user`, `command_line`, `action` (ProcessCreate, FileAccess) |
| **Process creation/termination events (generic)** | The backbone of any host timeline — establishes parent/child chains an attacker's tooling leaves behind. | Process name, PID, parent process/PID, start/stop time, command line, user context | `process_name`, `process_id`, `parent_process_name`, `parent_process_id`, `command_line`, `action` |
| **Network connection logs (Zeek `conn.log`, firewall/NetFlow)** | Shows lateral movement, C2 beaconing, and exfiltration — connects host activity to external or internal destinations. | Source/dest IP, source/dest port, protocol, duration, bytes transferred, allow/deny decision | `network_dest_ip`, `network_dest_port`, `action` (NetworkConnect/ConnectionAllowed/ConnectionDenied), `host` |

## Notes for the parser

- Not every source has every field — the parser should treat all canonical fields except `timestamp`, `host`, `log_source`, and `action` as optional.
- `sysmon_event_id`/native event IDs should be preserved even after normalization; they're useful for debugging and for Person 3's technique mapping (many MITRE mappings are conventionally keyed off specific Sysmon/EVTX event IDs — see `mitre_notes.md`).
- Timestamps across sources should be normalized to UTC before merging into a single timeline — see `incident_01.csv` for the expected output format.
- `incident_01.csv` (Day 1 deliverable) is a worked example that already follows this schema and mixes three of the source types above (Sysmon, Windows Security, network/firewall) — good as a first parser test case.
