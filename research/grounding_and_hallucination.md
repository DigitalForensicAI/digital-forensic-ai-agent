# Grounding & Hallucination Rules

## Rules for the Evidence Verifier

1. **Cite artifact IDs.** Every major claim (initial access, execution,
   persistence, lateral movement, exfiltration, impact) must reference the
   specific evidence ID(s) it is based on: `claim (evidence: [EVT-00231])`.

2. **Flag unsupported claims.** Any claim without a valid, matching artifact
   ID is not a finding — it must be marked `[INFERRED]` and state what
   evidence would confirm it.

3. **State insufficient evidence explicitly.** If a stage of the attack
   chain has no supporting evidence, say so directly instead of omitting it
   or guessing:
   > "Insufficient evidence to determine exfiltration method."

## Grounding score

```
grounding_score(claim) =
    (cited artifact IDs that exist AND are relevant to the claim)
    / (total factual assertions in the claim)
```

- 1.0 = fully supported by evidence
- 0.0 = fully unsupported
- Report-level score = mean of all claim-level scores
