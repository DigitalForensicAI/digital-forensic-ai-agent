import json
import sys

from src.graph.provenance import load_events


def real_artifact_ids(events):
    """The set of artifact_ids that actually exist in the evidence."""
    return {e["artifact_id"] for e in events}


def verify(investigation, events):
    """Check each stage's cited artifact_ids against real evidence."""
    real_ids = real_artifact_ids(events)
    stages = investigation.get("stages", [])

    grounded = 0
    checked = []
    for s in stages:
        cited = s.get("artifact_ids", [])
        # a claim is grounded if it cites at least one id AND every cited id is real
        missing = [aid for aid in cited if aid not in real_ids]
        is_grounded = bool(cited) and not missing
        if is_grounded:
            grounded += 1
        checked.append({
            **s,
            "grounded": is_grounded,
            "missing_ids": missing,  # ids the LLM cited that don't exist = hallucinated
        })

    total = len(stages)
    score = round(grounded / total, 3) if total else 0.0

    return {
        **investigation,
        "stages": checked,
        "grounding_score": score,
        "grounded_claims": grounded,
        "total_claims": total,
        "unsupported_claims": [c["claim"] for c in checked if not c["grounded"]],
    }


def run(correlations_path, investigation_path):
    _, events = load_events(correlations_path)
    with open(investigation_path) as f:
        investigation = json.load(f)

    result = verify(investigation, events)

    with open("output/verified.json", "w") as f:
        json.dump(result, f, indent=2)
    return result


if __name__ == "__main__":
    corr = sys.argv[1] if len(sys.argv) > 1 else "data/samples/correlations.json"
    inv = sys.argv[2] if len(sys.argv) > 2 else "output/investigation.json"
    result = run(corr, inv)
    print(f"grounding score: {result['grounding_score']} "
          f"({result['grounded_claims']}/{result['total_claims']} claims grounded)")
    if result["unsupported_claims"]:
        print("UNSUPPORTED (flagged):")
        for c in result["unsupported_claims"]:
            print(f"  - {c}")
    # show any hallucinated ids too
    for s in result["stages"]:
        if s.get("missing_ids"):
            print(f"  ! stage '{s.get('stage')}' cited non-existent ids: {s['missing_ids']}")
    print("--- saved output/verified.json ---")
