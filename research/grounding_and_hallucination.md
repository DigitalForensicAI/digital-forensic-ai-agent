# Grounding & Hallucination Rules — v1

## 1. Problem

An LLM asked to reconstruct an incident will produce a coherent narrative
even when evidence is thin, missing, or contradictory. These rules define
how the Evidence Verifier checks model output before it reaches a report,
so unsupported claims are caught rather than passed through as fact.

## 2. Verifier Rules

### Rule 1 — Every major claim must cite an artifact ID

A "major claim" is any statement describing initial access, execution,
persistence, lateral movement, exfiltration, or impact.

- Required format: `<claim text> (evidence: [EVT-00231, EVT-00245])`
- A claim with zero cited IDs, or an ID that does not exist in the evidence
  store, fails verification and must not be included as a finding.
- Multiple IDs may be cited for one claim; all must resolve.

**Verifier check:**
```
for each claim in model_output:
    ids = extract_ids(claim)              # regex: \[EVT-\d+\]
    if len(ids) == 0:
        reject(claim, reason="no citation")
    for id in ids:
        if id not in evidence_store:
            reject(claim, reason="citation does not exist")
```

### Rule 2 — Unsupported or inferred claims must be explicitly marked

If a claim bridges a gap between two non-adjacent events, or asserts intent
that the evidence doesn't directly state, it must be prefixed `[INFERRED]`
and paired with a statement of what evidence would confirm it.

- Valid: `[INFERRED] Attacker escalated privileges to move laterally —
  would be confirmed by: an admin-group modification event (T1098) on the
  target host.`
- Invalid: stating the same claim as fact with no `[INFERRED]` tag and no
  confirming evidence.

**Verifier check:** any claim that fails Rule 1 (no valid citation) is
automatically downgraded — either reclassified as `[INFERRED]` if it
contains a stated confirmation path, or rejected outright if it doesn't.

### Rule 3 — Insufficient evidence must be stated, not omitted

If a stage of the attack chain (Initial Access, Execution, Persistence,
Lateral Movement, Exfiltration, Impact) has no supporting evidence, the
model must output an explicit insufficient-evidence statement for that
stage rather than skipping it or inventing a plausible default:

> "Insufficient evidence to determine exfiltration method. No outbound
> transfer artifacts were found in the collected data."

**Verifier check:** confirm every one of the six stages appears in the
output — either with findings, or with an explicit insufficient-evidence
statement. A missing stage (neither present) fails verification.

## 3. Grounding Score

### Definition

```
grounding_score(claim) =
    valid_relevant_citations(claim) / total_assertions(claim)
```

- `valid_relevant_citations`: cited artifact IDs that (a) exist in the
  evidence store, and (b) are topically relevant — same host/timeframe/
  artifact type as the claim's subject matter.
- `total_assertions`: number of distinct factual statements in the claim
  (a compound claim with two assertions and one citation scores 0.5).

### Report-level score

```
report_grounding_score = mean(grounding_score(c) for c in all_claims)
```

Displayed to the analyst as a single number, e.g. `Grounding: 0.78`, as an
at-a-glance trust signal — not a pass/fail gate.

### Worked example

Claim: `"Attacker gained access via brute force and immediately created a
scheduled task (evidence: [EVT-00112])"`

- Two assertions: (1) brute-force access, (2) scheduled task creation.
- One citation (`EVT-00112`), relevant only to assertion 2.
- `grounding_score = 1 / 2 = 0.5` — flags this claim for review since half
  of it is uncited.

### Relevance check (kept simple for v1)

A citation is "relevant" if the cited event's `artifact_type` and
`timestamp` plausibly relate to the claim's subject (same host, and within
a reasonable time window of the described action). This is a coarse filter
— it exists to catch citation padding (citing real but unrelated IDs to
inflate the score), not to do deep semantic matching.

## 4. Pipeline placement

1. Reasoning agent generates output following the citation format above.
2. Evidence Verifier applies Rules 1–3 and computes the grounding score.
3. Claims failing Rule 1/2 are downgraded to `[INFERRED]` or dropped before
   reaching the Report Agent.
4. The report surfaces the grounding score alongside findings so the human
   analyst knows which sections warrant closer manual review.
