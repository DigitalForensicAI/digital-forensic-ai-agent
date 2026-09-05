# Evaluation Plan (v1)

Practical, implementable evaluation for the four things that matter:
grounding, MITRE correlation accuracy, reconstruction quality, and whether
the multi-agent split is actually worth it.

## 1. Grounding score evaluation

**Goal:** measure how well model claims trace to real evidence.

**Method:**
- Automated pass: extract every `[EVT-xxxxx]` citation from generated
  output; check each ID exists in the evidence store that was actually
  provided. Compute per-claim and report-level grounding score using the
  formula finalized in `grounding_and_hallucination.md` /
  `prompt_design.md`.
- Manual pass (sample-based): pull ~10 claims at random, confirm the cited
  evidence actually supports the claim's content, not just that the ID is
  valid — catches citation padding the automated check can't detect.

**Metric:**
```
citation_validity_rate = valid citations / total citations
report_grounding_score = mean(grounding_score(claim)) across all claims
manual_accuracy_rate   = correctly-supported claims / sampled claims
```

## 2. MITRE technique precision/recall

**Goal:** measure correlation accuracy against the shortlist in
`mitre_shortlist.md`.

**Method:**
- Pick one test case with a documented, published ground truth (a
  CyberDefenders/BOTS scenario or CTF challenge with a known writeup).
- Build a ground-truth table: `technique_id → present (yes/no)` from the
  15-technique shortlist.
- Run correlation against the same evidence set and compare.

**Metric:**
```
precision = correctly flagged techniques / total techniques flagged
recall    = correctly flagged techniques / total techniques actually present
```

## 3. Reconstruction quality

**Goal:** measure whether the generated narrative matches what actually
happened, in the right order, with correct stage-level conclusions.

**Method:** score each of the six stages (Initial Access, Execution,
Persistence, Lateral Movement, Exfiltration, Impact) against the known
timeline, using a simple 0–2 rubric per stage:

| Score | Meaning |
|---|---|
| 2 | Stage correctly identified, correct timing/order |
| 1 | Partially correct (right stage, wrong detail/order) |
| 0 | Missed or incorrect |

A stage correctly marked "insufficient evidence" (when that's actually
true) scores 2, not 0 — honesty about gaps is a correct answer, not a
miss.

**Metric:** `reconstruction_score = sum(stage scores) / 12` (max 2 × 6
stages).

## 4. Single-LLM vs. multi-agent comparison

**Goal:** test whether splitting the pipeline into agents actually
outperforms one LLM call doing everything at once.

**Method:**
- Baseline: same evidence set, one prompt: "analyze this incident and
  produce a full report" — no agent split, no Evidence Verifier.
- Treatment: full pipeline (Collector → Timeline → Correlation →
  Hypothesis → Verifier → Report) on the same evidence.
- Compare both outputs using the same three metrics above: grounding
  score, MITRE precision/recall, reconstruction score.

**Metric:** report as a side-by-side table:

| Metric | Single-LLM | Multi-agent |
|---|---|---|
| Grounding score | | |
| MITRE precision/recall | | |
| Reconstruction score | | |

## Scope for now vs. later

**Implement now:**
- Automated citation-validity check (part of #1)
- One single-LLM vs. multi-agent run on the demo dataset (#4), reusing
  metrics from #1–#3

**Defer:**
- Manual grounding-accuracy sampling at scale
- Precision/recall across multiple datasets
- Reconstruction scoring across multiple test cases
- Repeating the single-LLM vs. multi-agent comparison across datasets to
  confirm the result generalizes

---

## Why Multi-Agent? (Research Justification)

Rationale for why #4 above is expected to favor the multi-agent pipeline —
for the project report / research discussion.

### The single-LLM alternative

The simplest approach: pass all evidence into one prompt and ask for a
full report — timeline, technique mapping, and narrative in one
generation. This has three specific weaknesses for forensic work:

1. **No separation between fact-finding and interpretation.** Ordering
   events, matching techniques, and inferring intent are different tasks.
   One call doing all three makes it hard to tell which part failed when
   the output is wrong — the timeline, the technique mapping, or the
   narrative logic.
2. **No structural checkpoint for grounding.** A single free-form
   generation has no intermediate stage where citations can be verified
   before the next step builds on them — errors compound silently.
3. **No reusable intermediate output.** Reasoning and evidence stay
   entangled in prose, so nothing downstream (a correlation engine, a
   verifier) has a defined, structured input to work from.

### What the agent split provides

- **Auditable intermediate artifacts.** Each agent outputs a structured
  result (normalized events → ordered timeline → technique matches →
  staged hypothesis) that can be checked independently — this is what
  makes the grounding score and citation checks in
  `grounding_and_hallucination.md` possible at all.
- **A defined checkpoint for verification.** The Hypothesis Agent's output
  follows a fixed format (see `prompt_design.md`), giving the Evidence
  Verifier something concrete to check rather than parsing free-form
  prose.
- **Error isolation.** A wrong technique correlation with a correct
  timeline is visible and fixable independently; in a single-shot design
  that distinction is lost.
- **Mirrors how investigators actually work.** Real DFIR workflows already
  separate collection, timelining, correlation, and hypothesis formation
  as distinct steps — the architecture reflects an existing analytical
  division of labor rather than an artificial one.

### What this is not claiming

This is a design rationale, not a proven result. Whether the split
actually outperforms a single LLM call is the empirical question answered
by comparison #4 above. This section explains why that result is
expected, so the report can present it as a hypothesis being tested rather
than an assumption being asserted.

### One-line summary

"Splitting the pipeline into specialized agents turns one opaque
generation into a sequence of auditable, independently-verifiable steps —
which is what makes citation checking and a grounding score possible."
