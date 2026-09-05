# Evaluation Plan

## 1. Grounding score

- Extract all cited `[EVT-xxxxx]` IDs from generated output and check each
  resolves to a real event in the evidence store — gives a citation
  validity rate.
- Sample a subset manually to confirm cited evidence actually supports the
  claim, not just that the ID exists.
- Report as: % claims with valid citations, and % claims judged accurately
  supported (sample-based).

## 2. MITRE technique precision/recall

- Use a test case with a documented ground-truth technique list (a public
  dataset or CTF challenge with a published writeup).
- Precision = correctly flagged techniques / total techniques flagged
- Recall = correctly flagged techniques / total techniques actually present

## 3. Reconstruction quality

- Use a test scenario with a known timeline.
- Score each attack stage 0–2 (0 = missed/wrong, 1 = partial, 2 = correct)
  on: stage identified correctly, timing/order correct, and correctly
  flagged as "insufficient evidence" when applicable.

## 4. Single-LLM vs. multi-agent comparison

- Baseline: feed the same evidence to a single LLM call with a general
  "reconstruct this incident" prompt.
- Compare against the full pipeline output using the same grounding score
  and reconstruction quality rubric above.
- One side-by-side run on the demo dataset is enough for a concrete
  before/after result.

## Scope

**Now:** automatic citation-validity check (#1), one single-LLM vs.
multi-agent comparison run (#4).

**Later:** manual grounding accuracy sampling, full precision/recall across
multiple datasets, reconstruction scoring across multiple test cases,
repeating the comparison across datasets.
