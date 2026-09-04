# Ground Truth — incident_01

**Source dataset:** OTRF / Mordor Security Datasets — small "credential access" attack session (Windows host + domain controller), style-matched to the public Mimikatz/DCSync APT29-technique sessions.
**Sample file:** `data/samples/incident_01.csv` (15 events)
**Host(s) involved:** `WORKSTATION5` (compromised user endpoint), `DC01` (domain controller), `PERIMETER-FW` (network egress point)
**User account involved:** `CONTOSO\jsmith`

## What actually happened (narrative)

1. **Execution (18:31)** — An obfuscated PowerShell command runs on `WORKSTATION5` under user `jsmith` (event 1). This is the initial foothold action — likely the payload from a prior phishing/delivery step that isn't in this trimmed sample.
2. **Tool staging (18:32)** — PowerShell writes a binary, `m.exe`, to a temp folder (event 2). This is a Mimikatz-style credential-dumping tool being dropped to disk.
3. **Credential dumping (18:32)** — `m.exe` runs `sekurlsa::logonpasswords` and opens a handle into `lsass.exe` to read credentials directly out of memory (events 3–5). This is classic **OS Credential Dumping — LSASS Memory** (MITRE T1003.001).
4. **Domain credential replication (18:32)** — The same tool issues a `lsadump::dcsync` command targeting the `krbtgt` account and opens a network connection to the domain controller (events 6–7). The DC logs a directory-replication request (`DRSGetNCChanges`) as if `jsmith` were a domain controller peer (event 8) — this is **DCSync** (MITRE T1003.006), a technique that abuses legitimate AD replication rights to steal password hashes without ever touching `lsass.exe` on the DC itself.
5. **Successful logon on the DC (18:32)** — A logon success is recorded for `jsmith` on `DC01` (event 9), consistent with the account already holding (or having obtained) replication-capable rights.
6. **Collection (18:33)** — The dumped output is written to `creds_dump.txt` and then compressed into `out.zip` (events 10–11) — staging the stolen material for exfiltration.
7. **Exfiltration (18:34)** — `powershell.exe` opens an outbound HTTPS connection to an external IP (`203.0.113.55:443`), and the perimeter firewall logs the connection as allowed (events 12–13) — data is exfiltrated over an encrypted C2-style channel.
8. **Cleanup / anti-forensics (18:34–18:35)** — The attacker process is terminated and the dumped credentials file is deleted from disk (events 14–15), an attempt to remove local evidence.

## Why this incident is a good MVP sample

- It is **small but complete**: it has a clear beginning (execution), middle (credential theft + replication abuse), and end (exfiltration + cleanup) in only 15 events — enough to test a parser and a timeline builder without needing to handle a huge log volume.
- It **exercises multiple log sources** the dev team's parser will eventually need to normalize: Sysmon (process/file/network events), Windows Security event log (process access, logon, directory replication), and a network/firewall log (Zeek-style connection log) — a good first stress-test of the canonical event format.
- It has **unambiguous MITRE mappings** per step (T1059.001, T1105, T1003.001, T1003.006, T1074.001, T1560, T1041, T1071.001, T1070/T1070.004), which gives Person 3 real technique labels to correlate against instead of needing to invent test cases.
- It shows **the DCSync pattern specifically**, which is a good "is our system evidence-grounded?" test case: the interesting signal is *not* on the DC's `lsass.exe` at all, it's a legitimate-looking replication call from an unusual peer — the kind of subtle, cross-host reasoning our multi-agent approach is meant to catch and that a single-log-source tool would likely miss.

## What Person 2 needs to know for the parser/timeline

- Timestamps are already normalized to UTC ISO-8601 in the CSV — no timezone conversion needed for this sample.
- Not every row has every field populated (e.g., network rows don't have a `sysmon_event_id`, DC rows don't have a `process_id`) — the parser should tolerate sparse/optional columns rather than assuming all fields are always present.
- `event_id` in this CSV is just a row/sequence number for our sample, **not** a Windows Event ID — Windows Event IDs live in the `sysmon_event_id` column (or are implied by `log_source` for non-Sysmon rows). Worth flagging clearly in the canonical schema so it isn't confused with `sysmon_event_id`.
- The host field lets you group events into a per-host timeline, and then the `network_dest_ip`/`network_dest_port` fields are what tie the `WORKSTATION5` → `DC01` → `PERIMETER-FW` hops together into one cross-host story.

## Status

✅ Dataset chosen and justified (`research/datasets.md`)
✅ 15-row incident sample extracted (`data/samples/incident_01.csv`)
✅ Ground truth note written (this file)
➡️ Next: send `incident_01.csv` + this ground-truth note to Person 2, then post the Day 1 update in the group.
