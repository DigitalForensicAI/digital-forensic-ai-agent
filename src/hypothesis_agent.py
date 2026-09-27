"""
hypothesis_agent.py

Provenance Reasoning stage (Review 2, owned by Shikha).

Takes correlations.json (canonical events + technique tags from Nahal's stage)
and reconstructs the incident along the MITRE ATT&CK kill-chain: groups
suspicious events by tactic, orders the tactics into a coherent attack
sequence, and produces a structured hypothesis per stage with the specific
artifact_ids that support it.

Design note: technique->tactic mapping and stage narration are done with
straightforward, deterministic rules rather than a live LLM call, matching
the "fallback" design already used in the Review 1 reasoning agent
(reason.py). If/when an LLM is wired in for richer prose, this module's
grouping and artifact-citation logic stays the same -- only the narration
step would call out to the model, and it would be given the same evidence
list.
"""
import json
from collections import defaultdict

# --- Technique -> Tactic mapping -------------------------------------------
# Kept local to this module (does not add fields to the shared correlations.json
# contract). Extend this as Nahal's correlation stage adds coverage for new
# datasets / techniques.
TECHNIQUE_TACTIC = {
    "T1059.001": "Execution",
    "T1105":     "Command and Control",
    "T1003.001": "Credential Access",
    "T1003.006": "Credential Access",
    "T1078":     "Defense Evasion",
    "T1074.001": "Collection",
    "T1560":     "Collection",
    "T1041":     "Exfiltration",
    "T1071.001": "Command and Control",
    "T1070":     "Defense Evasion",
    "T1070.004": "Defense Evasion",
}

# Canonical MITRE ATT&CK tactic ordering (kill-chain order). Only tactics that
# actually appear in the data are included in a given hypothesis, in this order.
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

STAGE_TEMPLATES = {
    "Execution":            "{actors} executed {count} action(s) to run attacker code on {hosts}.",
    "Persistence":          "{actors} established persistence via {count} action(s) on {hosts}.",
    "Privilege Escalation": "{actors} escalated privileges via {count} action(s) on {hosts}.",
    "Defense Evasion":      "{actors} took {count} action(s) to evade defenses or remove traces on {hosts}.",
    "Credential Access":    "{actors} accessed or dumped credentials via {count} action(s) on {hosts}.",
    "Discovery":            "{actors} performed {count} discovery action(s) on {hosts}.",
    "Lateral Movement":     "{actors} moved laterally via {count} action(s) involving {hosts}.",
    "Collection":           "{actors} staged/collected data via {count} action(s) on {hosts}.",
    "Command and Control":  "{actors} communicated with external infrastructure via {count} action(s) from {hosts}.",
    "Exfiltration":         "{actors} exfiltrated data via {count} action(s) from {hosts}.",
    "Impact":               "{actors} caused impact (e.g. destruction/encryption) via {count} action(s) on {hosts}.",
}


def load_events(path):
    with open(path) as f:
        return json.load(f)


def build_hypothesis(events):
    """Group suspicious events into kill-chain stages and build a structured
    hypothesis with supporting artifact IDs for each stage."""
    suspicious = [e for e in events if e.get("suspicious")]

    stages = defaultdict(list)
    for e in suspicious:
        tactic = TECHNIQUE_TACTIC.get(e["technique_id"], "Unknown")
        stages[tactic].append(e)

    ordered_tactics = [t for t in TACTIC_ORDER if t in stages] + \
                      [t for t in stages if t not in TACTIC_ORDER]

    hypothesis = {"stages": [], "total_events_considered": len(events),
                  "total_suspicious_events": len(suspicious)}

    for tactic in ordered_tactics:
        stage_events = sorted(stages[tactic], key=lambda e: e["timestamp"])
        actors = sorted({e["actor"] for e in stage_events if e["actor"]})
        hosts = sorted({e["raw"].get("host", "") for e in stage_events if e["raw"].get("host")})
        techniques = sorted({(e["technique_id"], e["technique_name"]) for e in stage_events})

        template = STAGE_TEMPLATES.get(tactic, "{actors} performed {count} action(s) on {hosts}.")
        narrative = template.format(
            actors=", ".join(actors) or "an unidentified actor",
            count=len(stage_events),
            hosts=", ".join(hosts) or "an unidentified host",
        )

        stage_confidence = round(sum(e["confidence"] for e in stage_events) / len(stage_events), 2)

        hypothesis["stages"].append({
            "tactic": tactic,
            "narrative": narrative,
            "techniques": [{"technique_id": tid, "technique_name": tname} for tid, tname in techniques],
            "supporting_artifact_ids": [e["artifact_id"] for e in stage_events],
            "stage_confidence": stage_confidence,
            "start_time": stage_events[0]["timestamp"],
            "end_time": stage_events[-1]["timestamp"],
        })

    return hypothesis


def render_narrative(hypothesis):
    """Render the full ordered narrative with citations, for the report agent."""
    lines = []
    for i, stage in enumerate(hypothesis["stages"], start=1):
        cites = ", ".join(stage["supporting_artifact_ids"])
        lines.append(
            f"{i}. [{stage['tactic']}] {stage['narrative']} "
            f"(confidence {stage['stage_confidence']}) [{cites}]"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    events = load_events("/home/claude/data/samples/correlations_sample.json")
    hyp = build_hypothesis(events)

    with open("/home/claude/data/samples/hypothesis_sample.json", "w") as f:
        json.dump(hyp, f, indent=2)

    print(f"Considered {hyp['total_events_considered']} events, "
          f"{hyp['total_suspicious_events']} flagged suspicious, "
          f"grouped into {len(hyp['stages'])} kill-chain stages.\n")
    print(render_narrative(hyp))
