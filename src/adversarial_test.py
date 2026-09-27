"""
adversarial_test.py

Provenance Reasoning stage (Review 2, owned by Shikha) -- adversarial
robustness testing.

Framed strictly as DEFENSIVE robustness testing (per the team's Review 2
plan): we are not attacking a live system, we are running a fixed set of
crafted, hand-authored claims -- some accurate, some containing fabricated
evidence -- through two paths:

  UNGUARDED  -- simulates a model whose claims are accepted at face value,
               with no evidence check at all. This represents the failure
               mode our grounding layer exists to prevent.
  GROUNDED   -- our actual pipeline: verifier.py checks every claim's cited
               evidence for existence AND semantic relevance before it is
               accepted.

The comparison demonstrates that the grounding layer detects fabricated or
mismatched claims that an unguarded model would simply pass through --
this is the evidence Dev's evaluation stage needs for the adversarial
comparison table.
"""
import json
from verifier import verify_claims, load_event_index

CRAFTED_CASES = [
    {
        "id": "A1_true_claim",
        "text": "The adversary ran an obfuscated PowerShell command to begin execution.",
        "cited_artifact_ids": ["evt_00001"],
        "technique_id": "T1059.001",
        "is_fabricated": False,
        "description": "Baseline: accurate claim, real evidence, correct technique.",
    },
    {
        "id": "A2_true_claim",
        "text": "The adversary dumped credentials directly from LSASS memory.",
        "cited_artifact_ids": ["evt_00004"],
        "technique_id": "T1003.001",
        "is_fabricated": False,
        "description": "Baseline: accurate claim, real evidence, correct technique.",
    },
    {
        "id": "B1_fabricated_id",
        "text": "Files were encrypted by ransomware.",
        "cited_artifact_ids": ["evt_00099"],
        "technique_id": "T1486",
        "is_fabricated": True,
        "description": "Fabricated citation: cited artifact id does not exist at all "
                        "(Review 1-style hallucination).",
    },
    {
        "id": "B2_mismatched_evidence",
        "text": "Files were encrypted by ransomware.",
        "cited_artifact_ids": ["evt_00002"],
        "technique_id": "T1486",
        "is_fabricated": True,
        "description": "Subtler fabrication: cited artifact id is real, but the evidence "
                        "(a tool being dropped to disk) does not support a ransomware "
                        "encryption claim. A pure existence check (Review 1) would miss this.",
    },
    {
        "id": "B3_overclaim",
        "text": "The adversary exfiltrated over 500 files to a foreign server.",
        "cited_artifact_ids": ["evt_00010"],
        "technique_id": "T1041",
        "is_fabricated": True,
        "description": "Overclaim: the technique is correctly identified (T1041, matches), "
                        "so technique-alignment alone would pass this. Flagged here as a "
                        "known limitation -- see notes below.",
    },
]


def run_unguarded(cases):
    """An unguarded model just accepts every claim it makes -- no check at all."""
    return [
        {"id": c["id"], "verdict": "ACCEPTED", "note": "No verification performed."}
        for c in cases
    ]


def run_grounded(cases, events):
    claims = [
        {"text": c["text"], "cited_artifact_ids": c["cited_artifact_ids"], "technique_id": c["technique_id"]}
        for c in cases
    ]
    result = verify_claims(claims, events)
    return result


def main():
    with open("/home/claude/data/samples/correlations_sample.json") as f:
        events = json.load(f)

    unguarded_results = run_unguarded(CRAFTED_CASES)
    grounded_result = run_grounded(CRAFTED_CASES, events)

    comparison = []
    caught = 0
    should_catch = sum(1 for c in CRAFTED_CASES if c["is_fabricated"])
    for c, unguarded, grounded in zip(CRAFTED_CASES, unguarded_results, grounded_result["claims"]):
        grounded_caught = c["is_fabricated"] and grounded["verdict"] != "GROUNDED"
        if c["is_fabricated"] and grounded["verdict"] != "GROUNDED":
            caught += 1
        comparison.append({
            "case_id": c["id"],
            "description": c["description"],
            "is_fabricated": c["is_fabricated"],
            "unguarded_result": unguarded["verdict"],
            "grounded_verdict": grounded["verdict"],
            "grounded_score": grounded["grounding"],
            "grounding_layer_caught_it": grounded_caught if c["is_fabricated"] else "n/a (not fabricated)",
        })

    summary = {
        "total_cases": len(CRAFTED_CASES),
        "fabricated_cases": should_catch,
        "fabricated_cases_caught_by_grounded_pipeline": caught,
        "fabricated_cases_caught_by_unguarded_model": 0,  # by construction -- it checks nothing
        "overall_grounding_score_on_case_set": grounded_result["overall_grounding_score"],
        "comparison": comparison,
    }

    with open("/home/claude/data/samples/adversarial_results.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"Fabricated cases: {should_catch} / {len(CRAFTED_CASES)}")
    print(f"Caught by GROUNDED pipeline: {caught} / {should_catch}")
    print(f"Caught by UNGUARDED model:   0 / {should_catch}  (never checks evidence)\n")
    for row in comparison:
        print(f"[{row['case_id']}] fabricated={row['is_fabricated']} | "
              f"unguarded={row['unguarded_result']} | grounded={row['grounded_verdict']} "
              f"(score {row['grounded_score']})")


if __name__ == "__main__":
    main()
