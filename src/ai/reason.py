"""
reason.py  —  Person 1

The reasoning half. Takes structured evidence (events + correlations + graph text),
sends it to the local LLM, and gets back a grounded reconstruction where every
claim cites artifact_ids.

Run:
    python -m src.ai.reason data/samples/correlations.json
Produces:
    output/investigation.json
"""

import json
import sys
import os

from src.graph.provenance import load_events, build_graph, graph_to_text
from src.ai.llm.base import get_provider

SYSTEM = (
    "You are a digital forensic analyst. You reconstruct incidents ONLY from the "
    "evidence given. You NEVER invent events. Every claim MUST cite the artifact_id(s) "
    "it is based on. If evidence is missing, say so in limitations."
)

# JSON shape we want back (also used to constrain Ollama output)
SCHEMA = {
    "type": "object",
    "properties": {
        "case_id": {"type": "string"},
        "summary": {"type": "string"},
        "stages": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "stage": {"type": "string"},
                    "claim": {"type": "string"},
                    "artifact_ids": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "string"},
                },
                "required": ["stage", "claim", "artifact_ids", "confidence"],
            },
        },
        "limitations": {"type": "string"},
    },
    "required": ["case_id", "summary", "stages", "limitations"],
}


def build_evidence_text(case_id, events, graph_text):
    """Compact, LLM-readable view of the evidence. Timeline + flags + graph."""
    lines = [f"CASE: {case_id}", "", "TIMELINE (sorted events):"]
    for e in sorted(events, key=lambda x: x["timestamp"]):
        flag = ""
        if e.get("suspicious"):
            flag = f"  [SUSPICIOUS {e.get('technique_id','')} {e.get('technique_name','')}: {e.get('reason','')}]"
        lines.append(
            f"  {e['timestamp']} {e['artifact_id']} "
            f"{e['actor']} {e['event_type']} {e['object']} "
            f"{e.get('command','')} {e.get('dst_ip','')}".rstrip() + flag
        )
    lines += ["", "PROVENANCE GRAPH (edges):", graph_text]
    return "\n".join(lines)


def reconstruct(path, provider_name="ollama"):
    case_id, events = load_events(path)
    g = build_graph(events)
    evidence = build_evidence_text(case_id, events, graph_to_text(g))

    prompt = (
        evidence
        + "\n\nReconstruct the incident stage by stage "
        "(Initial Access, Execution, Persistence, Exfiltration where they apply). "
        "Return JSON only. Each stage claim must include the artifact_ids it relies on."
    )

    provider = get_provider(provider_name)
    raw = provider.complete(SYSTEM, prompt, json_schema=SCHEMA)

    # local models sometimes wrap JSON in text — be forgiving
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        start, end = raw.find("{"), raw.rfind("}")
        result = json.loads(raw[start:end + 1])

    os.makedirs("output", exist_ok=True)
    with open("output/investigation.json", "w") as f:
        json.dump(result, f, indent=2)
    return result


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/samples/correlations.json"
    out = reconstruct(path)
    print(json.dumps(out, indent=2))
    print("\n--- saved output/investigation.json ---")
