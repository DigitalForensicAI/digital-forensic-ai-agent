"""
render.py  —  Person 1

Turns verified.json (+ graph.png) into the final report.md.
Pure string formatting, no LLM.

Run:
    python -m src.report.render output/verified.json
Produces:
    output/report.md
"""

import json
import sys
import os


def render(verified, graph_path="graph.png"):
    lines = []
    case_id = verified.get("case_id", "unknown")

    lines.append(f"# Digital Forensic Investigation Report")
    lines.append("")
    lines.append(f"**Case:** {case_id}")
    lines.append(f"**Grounding score:** {verified.get('grounding_score', 0)} "
                 f"({verified.get('grounded_claims', 0)}/{verified.get('total_claims', 0)} "
                 f"claims backed by real evidence)")
    lines.append("")

    lines.append("## Summary")
    lines.append(verified.get("summary", "No summary produced."))
    lines.append("")

    lines.append("## Provenance graph")
    lines.append(f"![Provenance graph]({graph_path})")
    lines.append("")

    lines.append("## Attack narrative (evidence-grounded)")
    lines.append("")
    for s in verified.get("stages", []):
        mark = "OK" if s.get("grounded") else "UNSUPPORTED"
        ids = ", ".join(s.get("artifact_ids", [])) or "none"
        lines.append(f"### {s.get('stage', 'Stage')}  [{mark}]")
        lines.append(f"{s.get('claim', '')}")
        lines.append("")
        lines.append(f"- Evidence: {ids}")
        lines.append(f"- Confidence (model-reported): {s.get('confidence', 'n/a')}")
        if s.get("missing_ids"):
            lines.append(f"- WARNING: cited non-existent evidence: {', '.join(s['missing_ids'])}")
        lines.append("")

    if verified.get("unsupported_claims"):
        lines.append("## Flagged unsupported claims")
        lines.append("The following claims were NOT backed by real evidence and should not be trusted:")
        lines.append("")
        for c in verified["unsupported_claims"]:
            lines.append(f"- {c}")
        lines.append("")

    lines.append("## Limitations")
    lines.append(verified.get("limitations", "None stated."))
    lines.append("")

    return "\n".join(lines)


def run(verified_path):
    with open(verified_path) as f:
        verified = json.load(f)
    md = render(verified)
    os.makedirs("output", exist_ok=True)
    with open("output/report.md", "w") as f:
        f.write(md)
    return "output/report.md"


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "output/verified.json"
    out = run(path)
    print(f"--- saved {out} ---")
