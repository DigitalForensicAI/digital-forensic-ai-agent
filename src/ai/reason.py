import json
import sys
import os
import requests

from src.graph.provenance import load_events, build_graph, graph_to_text
from src.ai.llm.base import get_provider

SYSTEM = (
    "You are a digital forensic analyst. You reconstruct incidents ONLY from the "
    "evidence given. You NEVER invent events. Every claim MUST cite the artifact_id(s) "
    "it is based on. If evidence is missing, say so in limitations."
)

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
    lines = [f"CASE: {case_id}", "", "TIMELINE (sorted events):"]

    for e in sorted(events, key=lambda x: x["timestamp"]):
        mitre = e.get("mitre", [])
        mitre_text = ", ".join(
            f"{m.get('technique_id', '')} - {m.get('name', '')}"
            for m in mitre
        ) or "None"

        lines.append(
            f"  {e['timestamp']} | {e['artifact_id']} | "
            f"event_type={e['event_type']} | actor={e['actor']} | "
            f"object={e['object']} | command={e.get('command', '')} | "
            f"dst_ip={e.get('dst_ip', '')} | MITRE={mitre_text}"
        )

    lines += ["", "PROVENANCE GRAPH (edges):", graph_text]
    return "\n".join(lines)


def build_fallback_reconstruction(case_id, events):
    stages = []
    suspicious_events = [e for e in events if e.get("suspicious") or e.get("mitre")]

    for e in suspicious_events:
        aid = e.get("artifact_id")
        mitre_list = e.get("mitre", [])
        tech_names = [m.get("name", "") for m in mitre_list if m.get("name")]
        tech_str = ", ".join(tech_names) if tech_names else e.get("event_type", "activity")
        
        stage_name = "Execution"
        if "Registry" in tech_str or e.get("event_type") == "registry_write":
            stage_name = "Persistence"
        elif "Exfiltration" in tech_str or "Network" in tech_str:
            stage_name = "Exfiltration"
        elif "Discovery" in tech_str or "whoami" in e.get("command", ""):
            stage_name = "Discovery"

        stages.append({
            "stage": stage_name,
            "claim": f"Adversary performed {tech_str} using {e.get('object', '')} ({e.get('command', '') or e.get('dst_ip', '')}).",
            "artifact_ids": [aid],
            "confidence": "high",
        })

    return {
        "case_id": case_id,
        "summary": f"Incident triage for {case_id} identified {len(stages)} attack stages correlated across {len(events)} events.",
        "stages": stages,
        "limitations": "Generated via forensic correlation rules; local LLM server was offline.",
    }


def reconstruct(path, provider_name="ollama", offline=False):
    case_id, events = load_events(path)
    g = build_graph(events)
    evidence = build_evidence_text(case_id, events, graph_text=graph_to_text(g))

    if offline:
        result = build_fallback_reconstruction(case_id, events)
    else:
        prompt = (
            evidence
            + "\n\nReconstruct the incident using ONLY the supplied evidence. "
            "The MITRE technique name and tactic attached to each event are authoritative. "
            "Use the supplied MITRE tactic as the stage name whenever a tactic is present. "
            "Do not rename, reinterpret, or invent a different tactic or attack stage. "
            "Do not infer lateral movement, privilege escalation, malware execution, or other activity "
            "unless it is explicitly supported by the event or its MITRE mapping. "
            "Do not treat a network connection as exfiltration unless the supplied MITRE mapping identifies "
            "it as Exfiltration. "
            "Do not create duplicate stages for the same artifact and technique. "
            "Group related evidence when appropriate and order stages chronologically. "
            "Every claim must cite the artifact_ids that directly support it. "
            "Confidence must be exactly one of: high, medium, low. "
            "If evidence does not support a stage, omit that stage rather than speculating. "
            "Return JSON only."
)
        try:
            provider = get_provider(provider_name)
            raw = provider.complete(SYSTEM, prompt, json_schema=SCHEMA)
            try:
                result = json.loads(raw)
            except json.JSONDecodeError:
                start, end = raw.find("{"), raw.rfind("}")
                result = json.loads(raw[start:end + 1])
        except requests.exceptions.RequestException as e:
            print(f"[!] Ollama request failed: {type(e).__name__}: {e}")
            print("[!] Generating evidence-grounded reconstruction via correlation engine...")
            result = build_fallback_reconstruction(case_id, events)

    os.makedirs("output", exist_ok=True)
    with open("output/investigation.json", "w") as f:
        json.dump(result, f, indent=2)
    return result


if __name__ == "__main__":
    offline_mode = "--offline" in sys.argv
    clean_args = [a for a in sys.argv[1:] if a != "--offline"]
    path = clean_args[0] if len(clean_args) > 0 else "data/samples/correlations.json"
    out = reconstruct(path, offline=offline_mode)
    print(json.dumps(out, indent=2))
    print("\n--- saved output/investigation.json ---")
