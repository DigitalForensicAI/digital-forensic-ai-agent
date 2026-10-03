import argparse
import os

from src.graph.provenance import load_events, build_graph, draw

# Review 2
from src.ai.hypothesis import reconstruct
from src.ai.verify_semantic import verify

from src.report.build import build_report
from src.report.render import render
from src.report.export_docx import export_docx
from src.report.export_pdf import export_pdf


def adapt_verified_for_report(verified):
    """
    Adapt Review 2 verifier output to the exact structure expected by
    src.report.build.build_report().

    Review 2 uses:
        status = "grounded" / "weak" / "unsupported"

    The report builder expects:
        grounded = True / False
        missing_ids
        etc.
    """

    adapted = dict(verified)

    adapted["stages"] = []

    for stage in verified.get("stages", []):
        stage_copy = dict(stage)

        # build_report() expects a boolean called "grounded".
        stage_copy["grounded"] = (
            stage.get("status") == "grounded"
        )

        # verify_semantic.py already supplies missing_ids.
        stage_copy["missing_ids"] = (
            stage.get("missing_ids", []) or []
        )

        adapted["stages"].append(stage_copy)

    # build_report() expects unsupported_claims separately.
    adapted["unsupported_claims"] = [
        {
            "claim": stage.get("claim", ""),
            "artifact_ids": stage.get("artifact_ids", []) or [],
            "missing_ids": stage.get("missing_ids", []) or [],
            "status": stage.get("status", ""),
            "relevance": stage.get("relevance", 0.0),
        }
        for stage in verified.get("stages", [])
        if stage.get("status") != "grounded"
    ]

    return adapted


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
    )

    args = ap.parse_args()

    os.makedirs("output", exist_ok=True)

    # ---------------------------------------------------------------
    # [1/4] Build provenance graph
    # ---------------------------------------------------------------

    print("[1/4] building provenance graph...")

    case_id, events = load_events(args.input)

    g = build_graph(events)
    draw(g, "output/graph.png")

    print(
        f"      {g.number_of_nodes()} nodes, "
        f"{g.number_of_edges()} edges -> output/graph.png"
    )

    # ---------------------------------------------------------------
    # [2/4] Review 2 hypothesis reconstruction
    # ---------------------------------------------------------------

    print("[2/4] Review 2 hypothesis reconstruction...")

    hypothesis = reconstruct(
        args.input,
        provider_name=args.provider,
    )

    print(
        f"      {len(hypothesis.get('stages', []))} "
        f"stages produced"
    )

    # ---------------------------------------------------------------
    # [3/4] Review 2 semantic verification
    # ---------------------------------------------------------------

    print("[3/4] verifying claims against evidence...")

    verified = verify(
        hypothesis,
        events,
        relevance_threshold=0.30,
    )

    print(
        f"      grounding score: "
        f"{verified['grounding_score']} "
        f"({verified['grounded_claims']}/"
        f"{verified['total_claims']})"
    )

    # Adapt Review 2 verification result for the report builder.
    verified_for_report = adapt_verified_for_report(verified)

    # ---------------------------------------------------------------
    # [4/4] Build report
    # ---------------------------------------------------------------

    print("[4/4] building report...")

    report = build_report(
        verified_for_report,
        events,
        graph_path="output/graph.png",
    )

    md = render(report)

    with open("output/report.md", "w") as f:
        f.write(md)

    print("      -> output/report.md")

    export_docx(
        report,
        out_path="output/report.docx",
    )

    print("      -> output/report.docx")

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