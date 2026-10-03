import argparse
import json
import os

from src.graph.provenance import load_events, build_graph, draw
from src.hypothesis_agent import build_hypothesis
from src.verifier import verify_claims
from src.report.build import build_report
from src.report.render import render
from src.report.export_docx import export_docx
from src.report.export_pdf import export_pdf


def prepare_hypothesis_events(events):
    """
    Make the normalized events compatible with hypothesis_agent.py.
    hypothesis_agent expects raw["host"], while correlations.json stores
    raw as the original CSV-like string.
    """
    prepared = []

    for event in events:
        e = dict(event)

        raw = e.get("raw", "")

        if isinstance(raw, dict):
            e["raw"] = raw
        else:
            raw_text = str(raw)
            fields = raw_text.split(",")
            host = fields[2] if len(fields) > 2 else ""
            e["raw"] = {"host": host}

        prepared.append(e)

    return prepared


def hypothesis_to_claims(hypothesis):
    """
    Convert Review 2 deterministic hypothesis stages into the
    Review 2 verifier.py claim format.
    """
    claims = []

    for stage in hypothesis.get("stages", []):
        techniques = stage.get("techniques", [])

        technique_id = None
        if techniques:
            technique_id = techniques[0].get("technique_id")

        claims.append({
            "text": stage.get("narrative", ""),
            "cited_artifact_ids": stage.get(
                "supporting_artifact_ids", []
            ),
            "technique_id": technique_id,
        })

    return claims


def build_verified_for_report(
    case_id,
    hypothesis,
    claims,
    verification,
):
    """
    Convert verifier.py output into the structure expected by
    src/report/build.py.
    """

    verified_stages = []
    unsupported_claims = []

    results = verification.get("claims", [])

    for i, claim in enumerate(claims):
        result = results[i] if i < len(results) else {}

        hypothesis_stage = (
            hypothesis.get("stages", [])[i]
            if i < len(hypothesis.get("stages", []))
            else {}
        )

        verdict = result.get("verdict", "UNSUPPORTED")

        stage_data = {
            "stage": hypothesis_stage.get(
                "tactic",
                f"Stage {i + 1}"
            ),
            "claim": claim.get("text", ""),
            "artifact_ids": claim.get(
                "cited_artifact_ids",
                []
            ),
            "confidence": hypothesis_stage.get(
                "stage_confidence",
                "n/a"
            ),
            "grounded": verdict == "GROUNDED",
            "missing_ids": (
                claim.get("cited_artifact_ids", [])
                if verdict == "UNSUPPORTED"
                else []
            ),
            "verdict": verdict,
            "grounding": result.get("grounding", 0.0),
            "detail": result.get("detail", ""),
        }

        verified_stages.append(stage_data)

        if verdict != "GROUNDED":
            unsupported_claims.append({
                "stage": stage_data["stage"],
                "claim": stage_data["claim"],
                "artifact_ids": stage_data["artifact_ids"],
                "missing_ids": stage_data["missing_ids"],
                "status": verdict.lower(),
            })

    grounded_claims = sum(
        1
        for r in results
        if r.get("verdict") == "GROUNDED"
    )

    total_claims = len(claims)

    if total_claims:
        grounding_score = round(
            grounded_claims / total_claims,
            3
        )
    else:
        grounding_score = 0.0

    summary_lines = []

    for stage in hypothesis.get("stages", []):
        summary_lines.append(
            f"[{stage.get('tactic', 'Unknown')}] "
            f"{stage.get('narrative', '')}"
        )

    return {
        "case_id": case_id,
        "summary": "\n".join(summary_lines),
        "stages": verified_stages,
        "grounding_score": grounding_score,
        "grounded_claims": grounded_claims,
        "total_claims": total_claims,
        "unsupported_claims": unsupported_claims,
        "limitations": (
            "Review 2 hypothesis generation is deterministic and "
            "groups suspicious correlated events by MITRE ATT&CK tactic. "
            "Verification uses deterministic artifact existence and "
            "relevance checks."
        ),
    }


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--input",
        default="data/samples/correlations.json",
        help="path to correlations.json",
    )

    ap.add_argument(
        "--provider",
        default="ollama",
        help="kept for CLI compatibility",
    )

    args = ap.parse_args()

    os.makedirs("output", exist_ok=True)

    # ---------------------------------------------------------
    # 1. PROVENANCE GRAPH
    # ---------------------------------------------------------
    print("[1/4] building provenance graph...")

    case_id, events = load_events(args.input)

    g = build_graph(events)

    draw(
        g,
        "output/graph.png"
    )

    print(
        f"      {g.number_of_nodes()} nodes, "
        f"{g.number_of_edges()} edges -> output/graph.png"
    )

    # ---------------------------------------------------------
    # 2. REVIEW 2 HYPOTHESIS AGENT
    # ---------------------------------------------------------
    print("[2/4] Review 2 hypothesis reconstruction...")

    hypothesis_events = prepare_hypothesis_events(events)

    hypothesis = build_hypothesis(
        hypothesis_events
    )

    with open(
        "output/hypothesis.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            hypothesis,
            f,
            indent=2,
        )

    print(
        f"      {len(hypothesis.get('stages', []))} "
        f"stages produced -> output/hypothesis.json"
    )

    # ---------------------------------------------------------
    # 3. REVIEW 2 VERIFIER
    # ---------------------------------------------------------
    print("[3/4] verifying claims against evidence...")

    claims = hypothesis_to_claims(
        hypothesis
    )

    verification = verify_claims(
        claims,
        events,
    )

    verified = build_verified_for_report(
        case_id,
        hypothesis,
        claims,
        verification,
    )

    with open(
        "output/verified.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            verified,
            f,
            indent=2,
        )

    print(
        f"      grounding score: "
        f"{verified['grounding_score']} "
        f"({verified['grounded_claims']}/"
        f"{verified['total_claims']})"
    )

    # ---------------------------------------------------------
    # 4. REPORT
    # ---------------------------------------------------------
    print("[4/4] building report...")

    report = build_report(
        verified,
        events,
        graph_path="output/graph.png",
    )

    # Markdown
    md = render(report)

    with open(
        "output/report.md",
        "w",
        encoding="utf-8",
    ) as f:
        f.write(md)

    print("      -> output/report.md")

    # DOCX
    export_docx(
        report,
        out_path="output/report.docx",
    )

    print("      -> output/report.docx")

    # PDF
    export_pdf(
        report,
        out_path="output/report.pdf",
    )

    print("      -> output/report.pdf")

    print(
        "\nDone. Open output/report.md, "
        "output/report.docx, or output/report.pdf"
    )


if __name__ == "__main__":
    main()