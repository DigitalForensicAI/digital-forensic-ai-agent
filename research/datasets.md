# Dataset Comparison & Recommendation

**Author:** Person 4 (Research / Dataset)
**Date:** Day 1 of 3-Day MVP
**Goal:** Pick one small, practical dataset for the 3-day MVP demo, and one stronger dataset to consider for later evaluation.

## Candidates Compared

| Dataset | What it is | Format / Logs | Size | Labeled? | Access | MVP Fit |
|---|---|---|---|---|---|---|
| **OTRF / Mordor (Security Datasets)** | Small, purpose-built "attack sessions" — each one simulates a single adversary technique (e.g. Mimikatz credential dump, DCSync, PowerShell empire) on a Windows host, with Sysmon + Windows Event Log capture around it. | Sysmon/EVTX (JSON), some Zeek network logs | Tiny per-session (MBs, thousands of events, not millions) | Yes — each dataset is explicitly mapped to specific MITRE ATT&CK technique IDs | Public on GitHub, free, no request/approval needed | **Best fit** |
| **CyberDefenders / BOTS (Boss of the SOC)** | Full simulated SOC investigation scenarios (Splunk's BOTS) — multi-stage incidents (phishing → foothold → lateral movement → exfil) with a real narrative and CTF-style answer keys. | Mixed: Windows/Sysmon, Suricata/Zeek, AWS CloudTrail, web/proxy logs, Splunk-native | Large — multi-GB per scenario, tens of thousands+ events | Yes — has an answer key, but it's investigation-question format, not per-event ATT&CK labels | Free but requires downloading large archives (Splunk/Boss of the SOC bundles); some editions gated behind sign-up | Good future/evaluation candidate, too heavy for a 3-day setup |
| **CIC-IDS2018** | Network-traffic intrusion detection dataset from the Canadian Institute for Cybersecurity — benign + attack traffic (DoS, brute force, botnet, infiltration, web attacks) across a simulated enterprise network. | NetFlow/PCAP + pre-extracted CSV flow features (~80 columns per flow) | Very large — tens of GB, millions of flow rows | Yes — labeled by attack category | Public (AWS-hosted), but the CSVs alone are multi-GB and need serious cleanup | Overkill for MVP; better suited to a later ML-classification evaluation, not a host-forensics/timeline demo |
| **DARPA TC / OpTC** | DARPA Transparent Computing / Operationally Transparent Cyber — enterprise-scale host+network provenance data (hundreds of hosts, days of activity) built for large-scale APT hunting and provenance-graph research. | Provenance graphs (CDM/JSON), host telemetry, network | Extremely large — hundreds of GB to TB | Ground truth exists but is separate and requires cross-referencing | Requires registration / IEEE DataPort or restricted release; heavy download and parsing effort | Not practical for a 3-day MVP; too large and access-gated |

## Recommendation

**For the 3-day MVP: OTRF / Mordor (Security Datasets).**

Reasons:
- Each attack session is already scoped to one clear, small incident (a handful of techniques) instead of a sprawling multi-day investigation — easy to turn into a 5–20 row sample.
- Logs are in Sysmon/Windows Event Log JSON, which maps cleanly onto the "canonical event format" the dev team is building the parser for (EVTX/Sysmon fields are the same ones described in Day 2's `artifacts_reference.md`).
- Every session already has a documented MITRE ATT&CK technique mapping, so Person 3's MITRE-correlation work has clean ground truth to check against on day one instead of waiting on us to hand-label anything.
- No download gate, registration, or large storage requirement — the whole point of Day 1 is speed to a working sample.

**For later evaluation: CyberDefenders / BOTS.**

Reasons:
- It's a full multi-stage investigation (not just one technique), so it's a much better test of whether our multi-agent, evidence-grounded approach can actually reconstruct a real incident timeline end-to-end — that's a "later" milestone, not a Day 1 one.
- It has a public answer key we can use to score our system's output against a known-correct investigation narrative.
- It's heavier to set up (multi-GB, several log sources to normalize), which is exactly why it doesn't belong in the 3-day MVP but is a strong Phase 2 target.

**CIC-IDS2018 and DARPA TC/OpTC are marked as future options, not immediate candidates** — per the brief, we don't need to force a large/difficult dataset into the MVP. CIC-IDS2018 is flow-level network data (good for a later network-anomaly-detection angle, not host forensic timelines), and DARPA OpTC is access-gated and too large to parse in the time we have.

## Chosen incident for the MVP sample

From the Mordor small-dataset library: a **credential-access session** (Mimikatz-style LSASS credential dumping followed by a DCSync-style replication request), captured as Sysmon Event ID 10 (process access to lsass.exe) and Event ID 1 (process creation) entries, plus the follow-on directory-replication activity.

This became `data/samples/incident_01.csv` (see ground truth note in the same folder).
