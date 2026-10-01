"""
Render the structured report (see src/report/build.py) to Markdown.

This is the Markdown half of the three exporters (markdown / docx / pdf) that
all read the same report dict, so the three formats stay in sync.
"""
import json
import sys
import os

from src.report.build import build_report


def _table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        cells = [str(c).replace("|", "\\|").replace("\n", " ") for c in r]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def render(report, graph_path=None):
    graph_path = graph_path or report.get("graph_path", "graph.png")
    lines = []

    # --- Title & case header ---------------------------------------------
    lines.append("# Digital Forensic Investigation Report")
    lines.append("")
    lines.append(f"**Case:** {report.get('case_id', 'unknown')}  ")
    lines.append(f"**Generated:** {report.get('generated_at', '')}")
    lines.append("")

    # --- 1. Executive summary ---------------------------------------------
    lines.append("## 1. Executive Summary")
    lines.append(report.get("executive_summary", "No summary produced."))
    lines.append("")

    # --- 2. Timeline --------------------------------------------------------
    lines.append("## 2. Timeline")
    timeline = report.get("timeline", [])
    if timeline:
        rows = [
            [
                t["timestamp"], t["artifact_id"],
                "**SUSPICIOUS**" if t["suspicious"] else "",
                t["actor"], t["event_type"], t["object"], t["command"],
                t["dst_ip"], "; ".join(t["techniques"]),
            ]
            for t in timeline
        ]
        lines.append(_table(
            ["Timestamp", "Artifact ID", "Flag", "Actor", "Event Type", "Object", "Command", "Dst IP", "MITRE"],
            rows,
        ))
    else:
        lines.append("No events available.")
    lines.append("")

    # --- 3. Techniques detected ---------------------------------------------
    lines.append("## 3. Techniques Detected")
    techs = report.get("techniques_detected", [])
    if techs:
        rows = [
            [t["technique_id"], t["technique_name"], t["count"], ", ".join(t["artifact_ids"])]
            for t in techs
        ]
        lines.append(_table(["Technique ID", "Technique Name", "Event Count", "Artifact IDs"], rows))
    else:
        lines.append("No MITRE ATT&CK techniques were matched against this event set.")
    lines.append("")

    # --- 4. Attack narrative (evidence-grounded) -----------------------------
    lines.append("## 4. Attack Narrative (Evidence-Grounded)")
    lines.append("")
    if os.path.exists(graph_path) or graph_path:
        lines.append(f"![Provenance graph]({graph_path})")
        lines.append("")
    for s in report.get("narrative", []):
        mark = "OK" if s["grounded"] else "UNSUPPORTED"
        ids = ", ".join(s["artifact_ids"]) or "none"
        lines.append(f"### {s['stage']}  [{mark}]")
        lines.append(s["claim"])
        lines.append("")
        lines.append(f"- Evidence: {ids}")
        lines.append(f"- Confidence (model-reported): {s['confidence']}")
        if s["missing_ids"]:
            lines.append(f"- WARNING: cited non-existent evidence: {', '.join(s['missing_ids'])}")
        lines.append("")

    if report.get("unsupported_claims"):
        lines.append("### Flagged unsupported claims")
        lines.append("The following claims were NOT backed by real evidence and should not be trusted:")
        lines.append("")
        for c in report["unsupported_claims"]:
            lines.append(f"- {c}")
        lines.append("")

    # --- 5. Grounding score ---------------------------------------------------
    lines.append("## 5. Grounding Score")
    g = report.get("grounding", {})
    lines.append(
        f"**{g.get('score', 0)}** "
        f"({g.get('grounded_claims', 0)}/{g.get('total_claims', 0)} claims backed by cited evidence)"
    )
    lines.append("")

    # --- 6. Evidence appendix ---------------------------------------------
    lines.append("## 6. Evidence Appendix")
    appendix = report.get("evidence_appendix", [])
    if appendix:
        rows = [
            [a["artifact_id"], a["timestamp"], a["source"], a["actor"], a["event_type"],
             a["object"], a["command"], a["src_ip"], a["dst_ip"]]
            for a in appendix
        ]
        lines.append(_table(
            ["Artifact ID", "Timestamp", "Source", "Actor", "Event Type", "Object", "Command", "Src IP", "Dst IP"],
            rows,
        ))
        lines.append("")
        lines.append("<details><summary>Raw log lines</summary>")
        lines.append("")
        for a in appendix:
            lines.append(f"- `{a['artifact_id']}`: {a['raw']}")
        lines.append("")
        lines.append("</details>")
    else:
        lines.append("No events recorded.")
    lines.append("")

    # --- Limitations ---------------------------------------------------------
    lines.append("## Limitations")
    lines.append(report.get("limitations", "None stated."))
    lines.append("")

    return "\n".join(lines)


def run(verified_path, correlations_path, out_path="output/report.md"):
    with open(verified_path) as f:
        verified = json.load(f)
    with open(correlations_path) as f:
        corr = json.load(f)

    report = build_report(verified, corr.get("events", []))
    md = render(report)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as f:
        f.write(md)
    return out_path


if __name__ == "__main__":
    verified_path = sys.argv[1] if len(sys.argv) > 1 else "output/verified.json"
    correlations_path = sys.argv[2] if len(sys.argv) > 2 else "data/samples/correlations.json"
    out = run(verified_path, correlations_path)
    print(f"--- saved {out} ---")