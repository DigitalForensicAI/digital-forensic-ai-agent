# Prompt Design — Evidence-Grounded Incident Reconstruction (v1)

For: implementation of the Hypothesis/reasoning agent. This defines the
exact prompt structure, citation format, and output contract the Evidence
Verifier depends on — the citation rules here are the same ones defined in
`grounding_and_hallucination.md`.

## 1. Evidence input format

Evidence is passed as a numbered list of normalized events, never as raw
log text. Each event keeps the same `[EVT-xxxxx]` ID used everywhere else
in the pipeline.

```
EVIDENCE:
[EVT-00231] 2024-07-15T03:42:11Z | host: WORKSTATION-01 | user: DOMAIN\jsmith
  type: process_creation | process: powershell.exe | parent: cmd.exe
  command_line: "powershell -enc JABjAG..."

[EVT-00245] 2024-07-15T03:43:02Z | host: WORKSTATION-01
  type: scheduled_task_created | task_name: "UpdaterSvc"

[EVT-00312] 2024-07-15T04:10:55Z | host: WORKSTATION-01
  type: network_connection | dest_ip: 185.220.101.42 | dest_port: 443
```

Events should be sorted chronologically before being passed in — the model
should not have to re-sort evidence itself.

## 2. System / instruction prompt

```
You are a digital forensics reasoning assistant. You will be given a set
of normalized forensic events, each with a unique ID in brackets
(e.g. [EVT-00231]).

Rules you must follow:
1. Every factual claim about what happened must cite the specific EVT-ID(s)
   it is based on, in this exact format:
   "<claim> (evidence: [EVT-XXXXX, EVT-YYYYY])"
2. If you are inferring something beyond what the evidence directly shows
   (bridging a gap, guessing intent), prefix it with [INFERRED] and state
   what additional evidence would confirm or refute it.
3. If the evidence does not support a conclusion for a given attack stage,
   say so explicitly rather than omitting the stage or guessing.
4. Never invent an EVT-ID that was not provided in the evidence list.
5. State a confidence level (High / Medium / Low) for each attack-stage
   conclusion, based on how directly the cited evidence supports it.
6. Do not use outside knowledge of "typical" attacks to fill gaps — reason
   only from the evidence provided; use [INFERRED] for anything beyond it.
```

## 3. Output contract

The model must return one block per attack stage, in this fixed order:
Initial Access, Execution, Persistence, Lateral Movement, Exfiltration,
Impact.

```
## Attack Stage: <stage name>
Confidence: <High | Medium | Low | Insufficient evidence>

Findings:
- <claim> (evidence: [EVT-IDs])
- [INFERRED] <claim> — would be confirmed by: <evidence needed>

Evidence gaps:
- <what is missing for this stage, if anything>
```

A stage with no supporting evidence still gets a block — with
`Confidence: Insufficient evidence` and the findings section stating that
directly. This is a required output, not an optional one; the Evidence
Verifier checks that all six stages are present.

## 4. Confidence levels — definition

| Level | Meaning |
|---|---|
| High | Multiple corroborating events directly support the claim |
| Medium | One direct event supports it, or multiple weakly-related events |
| Low | Only inferred/circumstantial support |
| Insufficient evidence | No relevant events found for this stage |

## 5. Worked example

**Input evidence:** the three events shown in Section 1.

**Expected output (Persistence stage):**
```
## Attack Stage: Persistence
Confidence: High

Findings:
- Attacker created a scheduled task named "UpdaterSvc" to maintain access
  (evidence: [EVT-00245])
- [INFERRED] The task was created via the PowerShell session opened
  immediately prior — would be confirmed by: a parent-process link between
  EVT-00231 and EVT-00245 in process-tree data, which is not present in
  the current evidence set.

Evidence gaps:
- No evidence of what the scheduled task executes (task action/binary path
  not captured in this event)
```

This shows the pattern: the directly-evidenced part (task creation) is
cited and confident; the causal link to the earlier PowerShell session is
correctly marked `[INFERRED]` rather than stated as fact, because no event
directly ties the two together.

## 6. Whole-incident insufficient-evidence case

If the total evidence set is too sparse to reconstruct any stage reliably,
the model states this before attempting the six-stage template:

```
Overall assessment: Evidence set is insufficient to reconstruct a reliable
attack narrative. Available evidence: <brief description>. Recommend
collecting: <additional artifact types needed>.
```

This check should run before invoking the full per-stage prompt, so the
model isn't forced to stretch two or three events across six stages.

## 7. Grounding score — finalized definition

Used by the Evidence Verifier to score every claim produced by this prompt.

```
grounding_score(claim) =
    valid_relevant_citations(claim) / total_assertions(claim)
```

- `valid_relevant_citations`: cited EVT-IDs that (a) exist in the evidence
  store, and (b) match the claim's host/timeframe/artifact type.
- `total_assertions`: number of distinct factual statements in the claim.
- `report_grounding_score = mean(grounding_score(c) for c in all_claims)`,
  shown to the analyst as e.g. `Grounding: 0.78`.

Full rule definitions and the worked score example are in
`grounding_and_hallucination.md` — this prompt's output format is what
makes those rules mechanically checkable (fixed citation syntax, fixed
`[INFERRED]` tag, fixed stage structure).
