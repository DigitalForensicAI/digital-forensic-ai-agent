"""
build_sample_correlations.py

Converts the Review 1 incident_01 sample into the Review 2 shared JSON contract
(canonical event fields + correlation fields), so the reasoning/verification
stage has real data to build and test against before Riya's larger dataset
lands.

Canonical fields (fixed since Review 1):
  artifact_id, timestamp, event_type, actor, object, command, src_ip, dst_ip, raw

Correlation fields (added by Nahal's stage):
  suspicious, technique_id, technique_name, reason, confidence
"""
import json

HOST_IPS = {
    "WORKSTATION5": "10.1.2.50",
    "DC01": "10.0.0.10",
    "PERIMETER-FW": "10.1.2.1",
}

TECHNIQUE_NAMES = {
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1105": "Ingress Tool Transfer",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.006": "OS Credential Dumping: DCSync",
    "T1078": "Valid Accounts",
    "T1074.001": "Data Staged: Local Data Staging",
    "T1560": "Archive Collected Data",
    "T1041": "Exfiltration Over C2 Channel",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1070": "Indicator Removal",
    "T1070.004": "Indicator Removal: File Deletion",
}

# Row: (timestamp, host, event_type, actor, object, command, dst_ip, dst_port, technique_id, reason, confidence)
ROWS = [
    ("2020-05-01T18:31:44Z", "WORKSTATION5", "ProcessCreate", "powershell.exe", "", "powershell.exe -nop -w hidden -enc SQBFAFgA...", "", "", "T1059.001", "Obfuscated PowerShell invocation (-enc, -w hidden) matches known encoded-command execution pattern.", 0.9),
    ("2020-05-01T18:32:02Z", "WORKSTATION5", "FileCreate", "powershell.exe", "C:\\Users\\jsmith\\AppData\\Local\\Temp\\m.exe", "", "", "", "T1105", "Executable dropped to a temp directory immediately following PowerShell execution.", 0.75),
    ("2020-05-01T18:32:15Z", "WORKSTATION5", "ProcessCreate", "m.exe", "", "m.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"", "", "", "T1003.001", "Command line matches known Mimikatz credential-dumping syntax (sekurlsa::logonpasswords).", 0.95),
    ("2020-05-01T18:32:16Z", "WORKSTATION5", "ProcessAccess", "m.exe", "C:\\Windows\\System32\\lsass.exe", "", "", "", "T1003.001", "Process opened a handle into lsass.exe with memory-read access, consistent with LSASS credential dumping.", 0.9),
    ("2020-05-01T18:32:47Z", "WORKSTATION5", "ProcessCreate", "m.exe", "", "m.exe \"lsadump::dcsync /user:CONTOSO\\krbtgt\"", "", "", "T1003.006", "Command line matches known DCSync syntax targeting the krbtgt account.", 0.95),
    ("2020-05-01T18:32:48Z", "DC01", "DirectoryReplicationRequest", "lsass.exe", "DRSGetNCChanges", "", "", "", "T1003.006", "Directory replication request received on the domain controller from a non-DC peer, consistent with DCSync.", 0.9),
    ("2020-05-01T18:32:50Z", "DC01", "LogonSuccess", "jsmith", "", "", "", "", "T1078", "Logon success on the domain controller immediately following replication-rights use.", 0.6),
    ("2020-05-01T18:33:05Z", "WORKSTATION5", "FileCreate", "m.exe", "C:\\Users\\jsmith\\AppData\\Local\\Temp\\creds_dump.txt", "", "", "", "T1074.001", "Output file written locally right after credential dumping activity, consistent with staging for exfiltration.", 0.7),
    ("2020-05-01T18:33:40Z", "WORKSTATION5", "ProcessCreate", "powershell.exe", "", "powershell.exe -c Compress-Archive creds_dump.txt out.zip", "", "", "T1560", "Staged file compressed into an archive prior to network activity.", 0.8),
    ("2020-05-01T18:34:02Z", "WORKSTATION5", "NetworkConnect", "powershell.exe", "203.0.113.55:443", "", "203.0.113.55", "443", "T1041", "Outbound HTTPS connection to an external IP immediately following archive creation.", 0.75),
    ("2020-05-01T18:34:03Z", "PERIMETER-FW", "ConnectionAllowed", "PERIMETER-FW", "203.0.113.55:443", "", "203.0.113.55", "443", "T1071.001", "Firewall allowed outbound HTTPS to the same external IP seen in the workstation's exfil connection.", 0.6),
    ("2020-05-01T18:34:10Z", "WORKSTATION5", "ProcessTerminate", "m.exe", "", "", "", "", "T1070", "Attacker tool process terminated shortly after exfiltration.", 0.55),
    ("2020-05-01T18:35:22Z", "WORKSTATION5", "FileDelete", "m.exe", "C:\\Users\\jsmith\\AppData\\Local\\Temp\\creds_dump.txt", "", "", "", "T1070.004", "Local evidence file deleted after use, consistent with anti-forensic cleanup.", 0.7),
]

def build():
    events = []
    for i, row in enumerate(ROWS, start=1):
        ts, host, event_type, actor, obj, command, dst_ip, dst_port, tech_id, reason, confidence = row
        artifact_id = f"evt_{i:05d}"
        canonical = {
            "artifact_id": artifact_id,
            "timestamp": ts,
            "event_type": event_type,
            "actor": actor,
            "object": obj,
            "command": command,
            "src_ip": HOST_IPS.get(host, ""),
            "dst_ip": dst_ip,
            "raw": {
                "host": host,
                "dst_port": dst_port,
                "source": "incident_01 (Review 1 sample, converted to Review 2 schema)",
            },
        }
        correlation = {
            "suspicious": True,
            "technique_id": tech_id,
            "technique_name": TECHNIQUE_NAMES.get(tech_id, ""),
            "reason": reason,
            "confidence": confidence,
        }
        events.append({**canonical, **correlation})
    return events

if __name__ == "__main__":
    events = build()
    with open("/home/claude/data/samples/correlations_sample.json", "w") as f:
        json.dump(events, f, indent=2)
    print(f"Wrote {len(events)} events to correlations_sample.json")
