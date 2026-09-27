# Provenance Reasoning and Verification — Review 2

**Workstream:** Reasoning and Verification
**Owner:** Shikha
**Input:** `correlations.json` (Nahal's tagged events)
**Output:** `hypothesis.json`, `verification.json`, `adversarial_results.json`

## 1. Hypothesis Agent (`src/hypothesis_agent.py`)

**What it does:** takes the flat list of technique-tagged events and reconstructs them into a structured, kill-chain-ordered incident hypothesis. Each stage of the kill chain that actually appears in the data (Execution, Credential Access, Collection, Command and Control, Exfiltration, Defense Evasion, etc.) becomes one entry containing:

- a short narrative of what happened in that stage,
- which specific `artifact_id`s support it (the citation list the Verifier checks),
- the ATT&CK techniques observed in that stage,
- a stage-level confidence score (mean of the underlying events' confidence),
- start/end timestamps for that stage.

**Design choice — deterministic grouping, not open-ended generation:** the technique→tactic mapping and kill-chain ordering are simple lookup tables, not something an LLM decides on the fly. This means the *structure* of the hypothesis (which events belong to which stage, in what order) can never be hallucinated — only the narrative phrasing is templated text built directly from the actual field values of the cited events. This mirrors the same design philosophy as the Review 1 reasoning agent's fallback mode.

**Verified output on the sample data** (`data/samples/correlations_sample.json`, the Review 1 `incident_01` sample converted to the Review 2 schema): 13 events, all flagged suspicious, correctly grouped into 6 ordered stages — Execution → Defense Evasion → Credential Access → Collection → Command and Control → Exfiltration — each with its exact supporting artifact IDs. (Full run output in `research/hypothesis_sample_output.txt`.)

## 2. Upgraded Verifier (`src/verifier.py`)

**Review 1's verifier** answered one question: *does the cited artifact_id exist?* That catches an outright invented event ID (the `evt_00099` example from Review 1), but misses a subtler failure: the model cites a **real** event, but that event doesn't actually support the specific claim being made.

**Review 2's verifier checks two things, both deterministically (no second LLM doing the checking, so the check itself cannot hallucinate):**

1. **Existence** — same as before: does the cited `artifact_id` exist in the evidence store?
2. **Relevance** — does the cited event actually support *this* claim? Checked two ways:
   - **Technique alignment:** does the claim's stated `technique_id` match what's actually recorded against the cited event?
   - **Keyword grounding:** does the claim's text share meaningful vocabulary with the cited event's `object`/`command`/`technique_name`?

Each claim gets one of three verdicts instead of two:

| Verdict | Meaning |
|---|---|
| **GROUNDED** | Citation exists and actually supports the claim. Full credit. |
| **MISMATCHED** *(new in Review 2)* | Citation exists, but the evidence doesn't actually back this claim — wrong evidence cited. |
| **UNSUPPORTED** | Citation doesn't exist at all — fabricated. |

**Grounding score** = (# GROUNDED claims) / (# total claims).

**Verified example:** a claim "Files were encrypted by ransomware" citing a real event (`evt_00002`, which is actually a tool being dropped to disk) is correctly flagged **MISMATCHED** — something a pure existence check would have passed as fine, since the ID is real.

## 3. Adversarial Validation (`src/adversarial_test.py`)

Per the team's plan, this is framed strictly as **defensive robustness testing**: a fixed set of hand-crafted claims — some accurate, some deliberately fabricated in different ways — run through two paths:

- **Unguarded model:** accepts every claim at face value, no evidence check. Represents the failure mode the grounding layer exists to prevent.
- **Grounded pipeline:** our actual Verifier checks every claim before acceptance.

### Results

| Case | Fabricated? | Unguarded result | Grounded result | Caught? |
|---|---|---|---|---|
| A1 — true PowerShell execution claim | No | Accepted | GROUNDED (1.0) | n/a |
| A2 — true LSASS credential-dump claim | No | Accepted | GROUNDED (1.0) | n/a |
| B1 — fabricated artifact ID (Review 1-style) | Yes | Accepted | UNSUPPORTED (0.0) | ✅ Yes |
| B2 — real ID, mismatched evidence (ransomware claim citing a tool-drop event) | Yes | Accepted | MISMATCHED (0.0) | ✅ Yes |
| B3 — real ID, correct technique, but exaggerated detail ("500 files") not in the evidence | Yes | Accepted | GROUNDED (1.0) | ❌ No |

**Headline numbers:** the grounded pipeline caught **2 of 3** fabricated claims; the unguarded model caught **0 of 3**, by construction (it performs no check at all).

### Known limitation (worth stating plainly in the review, not hiding)

Case B3 shows a real gap: when a claim has the *correct* technique and cites *real* evidence, but adds a specific, unverifiable magnitude ("500 files") that the underlying event doesn't actually specify, the current relevance check (technique alignment + keyword overlap) passes it as GROUNDED. Catching this class of claim would need a stronger check — e.g., extracting and comparing numeric/quantitative details between the claim and the raw event, not just topical overlap. This is a good candidate for the Final Review's evaluation scope, not something to quietly work around now.

## Files produced

- `src/hypothesis_agent.py`, `src/verifier.py`, `src/adversarial_test.py`
- `data/samples/correlations_sample.json` — Review 1 sample converted to the Review 2 shared schema
- `data/samples/hypothesis_sample.json`, `verification_sample.json`, `adversarial_results.json` — verified run outputs
- This document

## Hand-off

The hypothesis reconstruction and adversarial results feed directly into Dev's evaluation stage (grounding score, technique precision/recall, adversarial comparison table). Everything here is built and verified against the sample data first, per the team plan, and re-runs unchanged once Riya's larger validated dataset lands — the code only depends on the shared JSON contract fields, not on this specific sample's content.
