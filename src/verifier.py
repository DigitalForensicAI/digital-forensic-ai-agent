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


import os
try:
    from src.ai.parameter_verifier import check_parameter_consistency
except ImportError:
    from ai.parameter_verifier import check_parameter_consistency


def load_event_index(events):
    return {e["artifact_id"]: e for e in events}


def verify_claim(claim, event_index):
    """
    claim: {
        "text": str,                  # the natural-language claim
        "cited_artifact_ids": [str],  # evidence the model says supports it
        "technique_id": str | None,   # technique the claim asserts, if any
    }
    Returns a verdict dict adhering to:
    Claim -> Artifact existence -> Lexical relevance -> Parameter consistency -> Final classification
    """
    claim_text = claim.get("text") or claim.get("claim", "")
    cited_ids = claim.get("cited_artifact_ids") or claim.get("artifact_ids", [])
    technique_id = claim.get("technique_id")

    # 1. EXISTENCE CHECK
    missing = [aid for aid in cited_ids if aid not in event_index]
    if missing or not cited_ids:
        return {
            "claim": claim_text,
            "artifact_id": cited_ids[0] if cited_ids else None,
            "artifact_ids": cited_ids,
            "artifact_exists": False,
            "relevance_score": 0.0,
            "parameter_check": {
                "passed": False,
                "unsupported_parameters": [f"Missing artifact ID(s): {missing}" if missing else "No artifact IDs cited"]
            },
            "verdict": "UNSUPPORTED",
            "classification": "unsupported",
            "grounding": 0.0,
            "detail": f"Cited artifact id(s) not found in evidence store: {missing}. "
                      f"This citation is fabricated.",
        }

    cited_events = [event_index[aid] for aid in cited_ids]
    claim_kw = _keywords(claim_text)

    # 2. LEXICAL / SEMANTIC RELEVANCE CHECK
    relevant_any = False
    detail_parts = []
    max_overlap_ratio = 0.0
    for e in cited_events:
        technique_match = (
            technique_id is not None
            and technique_id == e.get("technique_id")
        )
        event_kw = _keywords(
            f"{e.get('object','')} {e.get('command','')} {e.get('technique_name','')} "
            f"{e.get('event_type','')} {e.get('src_ip','')} {e.get('dst_ip','')} "
            f"{e.get('reason','')} {e.get('raw','')}"
        )
        overlap = claim_kw & event_kw
        keyword_match = len(overlap) > 0
        ratio = len(overlap) / len(claim_kw) if claim_kw else 0.0
        if ratio > max_overlap_ratio:
            max_overlap_ratio = ratio

        is_relevant = technique_match or keyword_match
        relevant_any = relevant_any or is_relevant

        detail_parts.append(
            f"{e['artifact_id']}: technique_match={technique_match}, "
            f"keyword_overlap={sorted(overlap) if overlap else 'none'}"
        )

    if not relevant_any:
        return {
            "claim": claim_text,
            "artifact_id": cited_ids[0] if cited_ids else None,
            "artifact_ids": cited_ids,
            "artifact_exists": True,
            "relevance_score": round(max_overlap_ratio, 2),
            "parameter_check": {
                "passed": False,
                "unsupported_parameters": ["Claim not semantically relevant to evidence"]
            },
            "verdict": "MISMATCHED",
            "classification": "mismatched",
            "grounding": 0.0,
            "detail": "Cited artifact id(s) exist, but neither technique nor keyword content "
                      "matches this specific claim; the evidence does not actually support it. "
                      "(" + "; ".join(detail_parts) + ")",
        }

    # 3. PARAMETER & FACTUAL CONSISTENCY CHECK
    param_res = check_parameter_consistency(claim_text, cited_events)
    if not param_res["passed"]:
        unsupported_str = ", ".join(param_res["unsupported_parameters"])
        return {
            "claim": claim_text,
            "artifact_id": cited_ids[0] if cited_ids else None,
            "artifact_ids": cited_ids,
            "artifact_exists": True,
            "relevance_score": round(max_overlap_ratio, 2),
            "parameter_check": {
                "passed": False,
                "unsupported_parameters": param_res["unsupported_parameters"]
            },
            "verdict": "MISMATCHED",
            "classification": "unsupported",
            "grounding": 0.0,
            "detail": f"Evidence is topically relevant, but contains unsupported factual parameters/scope: {unsupported_str}. "
                      f"({'; '.join(detail_parts)})",
        }

    # 4. FINAL CLASSIFICATION: FULLY GROUNDED
    return {
        "claim": claim_text,
        "artifact_id": cited_ids[0] if cited_ids else None,
        "artifact_ids": cited_ids,
        "artifact_exists": True,
        "relevance_score": round(max_overlap_ratio, 2),
        "parameter_check": {
            "passed": True,
            "unsupported_parameters": [],
            "supported_parameters": param_res.get("supported_parameters", [])
        },
        "verdict": "GROUNDED",
        "classification": "grounded",
        "grounding": 1.0,
        "detail": "; ".join(detail_parts),
    }


def verify_claims(claims, events):
    event_index = load_event_index(events)
    results = [verify_claim(c, event_index) for c in claims]
    overall_score = round(sum(r["grounding"] for r in results) / len(results), 2) if results else 0.0
    return {"overall_grounding_score": overall_score, "claims": results}


if __name__ == "__main__":
    candidates = [
        "data/samples/correlations_sample.json",
        "data/samples/correlations.json",
        "/home/claude/data/samples/correlations_sample.json",
    ]
    corr_file = next((c for c in candidates if os.path.exists(c)), candidates[0])
    with open(corr_file, "r", encoding="utf-8") as f:
        events = json.load(f)

    # Demo claims covering:
    # 1. True baseline
    # 2. True baseline
    # 3. Review 1 fabricated artifact ID
    # 4. Review 2 mismatched evidence
    # 5. Review 3 / Final Review B3 scope inflation (overclaim)
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
        {
            "text": "The adversary exfiltrated over 500 files to a foreign server.",
            "cited_artifact_ids": ["evt_00010"],  # exists and matches technique, but 500 files is unsupported
            "technique_id": "T1041",
        },
    ]

    result = verify_claims(demo_claims, events)
    out_candidates = [
        "data/samples/verification_sample.json",
        "/home/claude/data/samples/verification_sample.json",
    ]
    out_file = out_candidates[0]
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"Overall grounding score: {result['overall_grounding_score']}\n")
    for r in result["claims"]:
        print(f"[{r['verdict']}] {r['claim']}\n  -> {r['detail']}\n")
