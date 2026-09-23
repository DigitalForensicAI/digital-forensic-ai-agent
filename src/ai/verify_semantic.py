import json
import sys
import os
import re

from src.graph.provenance import load_events


# Words too common to count as evidence of relevance
STOP = {
    "the", "a", "an", "to", "of", "and", "or", "on", "in", "for", "with", "was",
    "were", "ran", "a", "via", "using", "used", "that", "this", "at", "by",
    "from", "is", "are", "actor", "adversary", "performed", "executed",
}


def tokenize(text):
    """Lowercase words, split technical paths, drop stopwords and short tokens."""
    text = str(text).lower()

    # Treat technical separators as word boundaries.
    # Example:
    # HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater
    # becomes:
    # hkcu software microsoft windows currentversion run updater
    text = re.sub(r"[\\/:._-]+", " ", text)

    words = re.findall(r"[a-zA-Z0-9]+", text)

    return {
        w for w in words
        if len(w) > 2 and w not in STOP
    }


def event_text(e):
    """The words that describe an event: what it did, to what, with what."""

    parts = [
        e.get("actor", ""),
        e.get("object", ""),
        e.get("event_type", ""),
        e.get("command", ""),
        e.get("src_ip", ""),
        e.get("dst_ip", ""),
        e.get("technique_name", ""),
        e.get("reason", "")
    ]

    def event_text(e):
        parts = [
            e.get("actor", ""),
            e.get("object", ""),
            e.get("event_type", ""),
            e.get("command", ""),
            e.get("src_ip", ""),
            e.get("dst_ip", ""),
            e.get("technique_name", ""),
            e.get("reason", "")
    ]

    return tokenize(" ".join(str(p) for p in parts))
    return tokenize(" ".join(str(p) for p in parts))


def build_event_index(events):
    """artifact_id -> its descriptive word set, plus the set of all real IDs."""

    index = {
        e["artifact_id"]: event_text(e)
        for e in events
    }

    real_ids = set(index.keys())

    return index, real_ids


def relevance(claim_words, cited_event_words):
    """Fraction of claim words supported by the cited event (0..1)."""

    if not claim_words:
        return 0.0

    overlap = claim_words & cited_event_words

    # Strong forensic command patterns.
    if {"whoami", "all"}.issubset(cited_event_words):
        if {"whoami", "all"}.issubset(claim_words):
            return max(len(overlap) / len(claim_words), 0.30)

    return len(overlap) / len(claim_words)

def verify(reconstruction, events, relevance_threshold=0.30):
    index, real_ids = build_event_index(events)

    stages = reconstruction.get("stages", [])

    checked = []
    grounded = 0

    for s in stages:
        cited = s.get("artifact_ids", [])
        claim_words = tokenize(s.get("claim", ""))

        # Check whether every cited artifact actually exists.
        missing = [
            aid
            for aid in cited
            if aid not in real_ids
        ]

        # Relevance:
        # Calculate relevance for each existing cited event
        # and use the best score.
        rel_scores = [
            relevance(claim_words, index[aid])
            for aid in cited
            if aid in real_ids
        ]

        combined_event_words = set()

        for aid in cited:
            if aid in index:
                combined_event_words.update(index[aid])

        best_rel = relevance(claim_words, combined_event_words)

        # Classification
        if missing or not cited:
            status = "unsupported"

        elif best_rel >= relevance_threshold:
            status = "grounded"
            grounded += 1

        else:
            status = "weak"

        checked.append({
            **s,
            "status": status,
            "missing_ids": missing,
            "relevance": round(best_rel, 2),
        })

    total = len(stages)

    score = (
        round(grounded / total, 3)
        if total
        else 0.0
    )

    return {
        **reconstruction,
        "stages": checked,
        "grounding_score": score,
        "grounded_claims": grounded,
        "total_claims": total,
        "flagged": [
            c["claim"]
            for c in checked
            if c["status"] != "grounded"
        ],
    }


def run(correlations_path, reconstruction_path):
    _, events = load_events(correlations_path)

    with open(reconstruction_path) as f:
        reconstruction = json.load(f)

    result = verify(reconstruction, events)

    os.makedirs("output", exist_ok=True)

    with open("output/verified.json", "w") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    corr = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "data/samples/correlations.json"
    )

    rec = (
        sys.argv[2]
        if len(sys.argv) > 2
        else "output/hypothesis.json"
    )

    result = run(corr, rec)

    print(
        f"grounding score: {result['grounding_score']} "
        f"({result['grounded_claims']}/{result['total_claims']} grounded)"
    )

    for s in result["stages"]:
        print(
            f"  [{s['status']:>11}] "
            f"rel={s['relevance']} "
            f"{s.get('stage', '')}: "
            f"{s.get('claim', '')[:60]}"
        )

        if s["missing_ids"]:
            print(
                f"                cited non-existent: "
                f"{s['missing_ids']}"
            )

    print("--- saved output/verified.json ---")