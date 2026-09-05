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
            + "\n\nReconstruct the incident stage by stage "
            "(Initial Access, Execution, Persistence, Exfiltration where they apply). "
            "Return JSON only. Each stage claim must include the artifact_ids it relies on."
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
