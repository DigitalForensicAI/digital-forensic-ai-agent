import json
import sys
import os

# reuse what you already have
from src.graph.provenance import load_events, build_graph, graph_to_text
from src.ai.llm.base import get_provider


# The kill-chain stages we ask the model to reason over, in order.
KILL_CHAIN = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Discovery",
    "Exfiltration",
]


SYSTEM = (
    "You are a digital forensic analyst. You reconstruct incidents ONLY from the "
    "evidence provided. You NEVER invent events. For each kill-chain stage that the "
    "evidence supports, produce a hypothesis; if a stage has no supporting evidence, "
    "say so explicitly and cite no artifacts for it. Every claim MUST cite the "
    "artifact_id(s) it is based on."
)


# JSON shape we want back (also used to constrain Ollama output via the format field)
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
                    "artifact_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "mitre": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "confidence": {"type": "string"},
                    "evidence_present": {"type": "boolean"},
                },
                "required": [
                    "stage",
                    "claim",
                    "artifact_ids",
                    "evidence_present",
                ],
            },
        },
        "limitations": {"type": "string"},
    },
    "required": [
        "case_id",
        "summary",
        "stages",
        "limitations",
    ],
}


def build_evidence_text(case_id, events, graph_text):
    """Compact, LLM-readable view: timeline + suspicious flags + graph edges."""
    lines = [
        f"CASE: {case_id}",
        "",
        "TIMELINE (sorted events):",
    ]

    for e in sorted(events, key=lambda x: x["timestamp"]):
        flag = ""

        if e.get("suspicious"):
            flag = (
                f"  [SUSPICIOUS {e.get('technique_id', '')} "
                f"{e.get('technique_name', '')}: {e.get('reason', '')}]"
            )

        if e.get("mitre"):
            mitre_text = []

            for m in e["mitre"]:
                if isinstance(m, dict):
                    mitre_text.append(
                        f"{m.get('technique_id', '')} {m.get('name', '')}"
                    )

            if mitre_text:
                flag += "  [MITRE: " + "; ".join(mitre_text) + "]"

        lines.append(
            f"  {e['timestamp']} {e['artifact_id']} "
            f"{e.get('actor', '')} {e.get('event_type', '')} "
            f"{e.get('object', '')} {e.get('command', '')} "
            f"{e.get('dst_ip', '')}".rstrip()
            + flag
        )

    lines += [
        "",
        "PROVENANCE GRAPH (edges):",
        graph_text,
    ]

    return "\n".join(lines)


def reconstruct(path, provider_name="ollama"):
    case_id, events = load_events(path)

    g = build_graph(events)

    evidence = build_evidence_text(
        case_id,
        events,
        graph_to_text(g),
    )

    stage_list = ", ".join(KILL_CHAIN)

    # Give the model the exact artifact IDs it is allowed to use.
    valid_artifact_ids = ", ".join(
        e["artifact_id"]
        for e in events
        if e.get("artifact_id")
    )

    prompt = (
        evidence
        + f"\n\nReconstruct the incident along these kill-chain stages in order: "
        f"{stage_list}.\n"
        + f"VALID ARTIFACT IDS: {valid_artifact_ids}. "
        "Every artifact_id MUST be copied exactly from this list. "
        "Never invent, rename, or describe an artifact ID. "
        "Use ONLY observable facts from the timeline and provenance graph. "
        "Do not infer an attack stage merely because a MITRE technique annotation exists. "
        "MITRE annotations are metadata and must not be treated as independent proof. "
        "A network connection alone does not prove exfiltration. "
        "A process_creation event for PowerShell supports Execution; cite only the "
        "PowerShell process_creation artifact for that stage. "
        "A registry_write to a Windows Run key supports Persistence; do not treat a "
        "file_write event alone as Persistence. "
        "A registry_write to a Windows Run key supports Persistence. "
        "A whoami /all command supports Discovery. "
        "Only claim Initial Access if the evidence explicitly shows how access was obtained. "
        "If the evidence only shows a process starting, set Initial Access to false. "
        "Only claim Exfiltration if the evidence explicitly shows data being transferred out. "
        "For EACH stage, output exactly one entry with the stage name, a factual claim, "
        "the artifact_ids that directly support that claim, any MITRE technique IDs "
        "present in those artifacts, a confidence value, and evidence_present true/false. "
        "Every artifact_id must come directly from the provided evidence. "
        "If the evidence does not support a stage, set evidence_present to false, "
        "use an empty artifact_ids list, and say that there is no supporting evidence. "
        "Do not invent events, actions, access methods, C2 activity, or data transfers. "
        "Return JSON only."
    )

    provider = get_provider(provider_name)

    raw = provider.complete(
        SYSTEM,
        prompt,
        json_schema=SCHEMA,
    )

    # Local models sometimes wrap JSON in text — be forgiving.
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")

        if start == -1 or end == -1:
            raise ValueError("Ollama did not return valid JSON.")

        result = json.loads(raw[start:end + 1])

    os.makedirs("output", exist_ok=True)

    with open("output/hypothesis.json", "w") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "data/samples/correlations.json"
    )

    out = reconstruct(path)

    print(json.dumps(out, indent=2))
    print("\n--- saved output/hypothesis.json ---")