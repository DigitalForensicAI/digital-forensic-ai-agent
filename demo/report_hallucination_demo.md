# Digital Forensic Investigation Report

**Case:** incident_01_hallucination_demo
**Grounding score:** 0.667 (2/3 claims backed by real evidence)

## Summary
Incident triage identified 3 attack stages. One claim could not be verified against the evidence.

## Attack narrative (evidence-grounded)

### Execution  [OK]
Adversary executed an encoded PowerShell command.

- Evidence: evt_00001
- Confidence (model-reported): high

### Exfiltration  [OK]
PowerShell connected to a known-bad external IP (185.23.44.9).

- Evidence: evt_00003
- Confidence (model-reported): medium

### Impact  [UNSUPPORTED]
Files on disk were encrypted by ransomware.

- Evidence: evt_00099
- Confidence (model-reported): low
- WARNING: cited non-existent evidence: evt_00099

## Flagged unsupported claims
The following claims were NOT backed by real evidence and should not be trusted:

- Files on disk were encrypted by ransomware.

## Limitations
The verifier confirmed cited IDs exist in evidence; semantic correctness of each citation is future work.
