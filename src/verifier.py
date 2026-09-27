"""
verifier.py

Provenance Reasoning stage (Review 2, owned by Shikha).

Review 1's verifier answered one question: "does the cited artifact_id exist?"
That catches outright invented event IDs, but not a subtler failure mode: the
model cites a *real* artifact_id, but the evidence at that ID doesn't actually
support the claim being made (e.g. citing a network-connect event as proof of
"files were encrypted by ransomware").

This upgraded verifier checks both:
  1. EXISTENCE -- does the cited artifact_id exist in the evidence store?
  2. RELEVANCE -- does the cited event actually support this specific claim?
     Relevance is checked two ways, deterministically (no second LLM involved,
     so the check itself cannot hallucinate):
       a) Technique alignment: if the claim states a technique_id, does it
          match the technique_id actually recorded against the cited event?
       b) Keyword grounding: does the claim's free text share meaningful
          vocabulary with the cited event's object/command/technique_name?
          (a basic but effective substitute for a real semantic-similarity
          model, and fully explainable/deterministic)

Each claim gets one of three verdicts:
  GROUNDED    -- exists AND relevant. Full credit.
  MISMATCHED  -- exists but NOT relevant to this claim (wrong evidence cited).
  UNSUPPORTED -- artifact_id does not exist at all (fabricated citation).

Grounding score = (# GROUNDED claims) / (# total claims).
"""
import json
import re

STOPWORDS = {
    "the", "a", "an", "was", "were", "is", "are", "to", "of", "on", "in",
    "by", "and", "or", "that", "this", "with", "from", "at", "as", "it",
    "be", "for", "via", "then",
}


def _keywords(text):
    words = re.findall(r"[a-zA-Z0-9_.]+", text.lower())
    return {w for w in words if w not in STOPWORDS and len(w) > 2}


def load_event_index(events):
    return {e["artifact_id"]: e for e in events}


def verify_claim(claim, event_index):
    """
    claim: {
        "text": str,                  # the natural-language claim
        "cited_artifact_ids": [str],  # evidence the model says supports it
        "technique_id": str | None,   # technique the claim asserts, if any
    }
    Returns a verdict dict.
    """
    missing = [aid for aid in claim["cited_artifact_ids"] if aid not in event_index]
    if missing:
        return {
            "claim": claim["text"],
            "verdict": "UNSUPPORTED",
            "grounding": 0.0,
            "detail": f"Cited artifact id(s) not found in evidence store: {missing}. "
                      f"This citation is fabricated.",
        }

    cited_events = [event_index[aid] for aid in claim["cited_artifact_ids"]]
    claim_kw = _keywords(claim["text"])

    relevant_any = False
    detail_parts = []
    for e in cited_events:
        technique_match = (
            claim.get("technique_id") is not None
            and claim["technique_id"] == e.get("technique_id")
        )
        event_kw = _keywords(
            f"{e.get('object','')} {e.get('command','')} {e.get('technique_name','')} {e.get('event_type','')}"
        )
        overlap = claim_kw & event_kw
        keyword_match = len(overlap) > 0

        is_relevant = technique_match or keyword_match
        relevant_any = relevant_any or is_relevant

        detail_parts.append(
            f"{e['artifact_id']}: technique_match={technique_match}, "
            f"keyword_overlap={sorted(overlap) if overlap else 'none'}"
        )

    if relevant_any:
        return {
            "claim": claim["text"],
            "verdict": "GROUNDED",
            "grounding": 1.0,
            "detail": "; ".join(detail_parts),
        }
    else:
        return {
            "claim": claim["text"],
            "verdict": "MISMATCHED",
            "grounding": 0.0,
            "detail": "Cited artifact id(s) exist, but neither technique nor keyword content "
                      "matches this specific claim; the evidence does not actually support it. "
                      "(" + "; ".join(detail_parts) + ")",
        }


def verify_claims(claims, events):
    event_index = load_event_index(events)
    results = [verify_claim(c, event_index) for c in claims]
    overall_score = round(sum(r["grounding"] for r in results) / len(results), 2) if results else 0.0
    return {"overall_grounding_score": overall_score, "claims": results}


if __name__ == "__main__":
    with open("/home/claude/data/samples/correlations_sample.json") as f:
        events = json.load(f)

    # A small set of demo claims: two true, one from the Review 1 fabricated-ID
    # example, and one new "mismatched evidence" case that only the upgraded
    # (semantic) verifier catches.
    demo_claims = [
        {
            "text": "The adversary ran an obfuscated PowerShell command to begin execution.",
            "cited_artifact_ids": ["evt_00001"],
            "technique_id": "T1059.001",
        },
        {
            "text": "The adversary dumped credentials directly from LSASS memory.",
            "cited_artifact_ids": ["evt_00004"],
            "technique_id": "T1003.001",
        },
        {
            "text": "Files were encrypted by ransomware.",
            "cited_artifact_ids": ["evt_00099"],  # does not exist -- Review 1 style fabrication
            "technique_id": "T1486",
        },
        {
            "text": "Files were encrypted by ransomware.",
            "cited_artifact_ids": ["evt_00002"],  # exists, but is really T1105 tool-drop, not ransomware
            "technique_id": "T1486",
        },
    ]

    result = verify_claims(demo_claims, events)
    with open("/home/claude/data/samples/verification_sample.json", "w") as f:
        json.dump(result, f, indent=2)

    print(f"Overall grounding score: {result['overall_grounding_score']}\n")
    for r in result["claims"]:
        print(f"[{r['verdict']}] {r['claim']}\n  -> {r['detail']}\n")
