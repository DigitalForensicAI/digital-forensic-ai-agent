import argparse
import os

from src.graph.provenance import load_events, build_graph, draw
from src.ai.reason import reconstruct
from src.ai.verify import verify
from src.report.build import build_report
from src.report.render import render
from src.report.export_docx import export_docx
from src.report.export_pdf import export_pdf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/samples/correlations.json",
                    help="path to correlations.json")
    ap.add_argument("--provider", default="ollama")
    args = ap.parse_args()

    os.makedirs("output", exist_ok=True)

    print("[1/4] building provenance graph...")
    case_id, events = load_events(args.input)
    g = build_graph(events)
    draw(g, "output/graph.png")
    print(f"      {g.number_of_nodes()} nodes, {g.number_of_edges()} edges -> output/graph.png")

    print("[2/4] LLM reconstruction (local model)...")
    investigation = reconstruct(args.input, provider_name=args.provider)
    print(f"      {len(investigation.get('stages', []))} stages produced")

    print("[3/4] verifying claims against evidence...")
    verified = verify(investigation, events)
    print(f"      grounding score: {verified['grounding_score']} "
          f"({verified['grounded_claims']}/{verified['total_claims']})")

    print("[4/4] building report...")
    report = build_report(verified, events, graph_path="output/graph.png")

    md = render(report)
    with open("output/report.md", "w") as f:
        f.write(md)
    print("      -> output/report.md")

    export_docx(report, out_path="output/report.docx")
    print("      -> output/report.docx")

    export_pdf(report, out_path="output/report.pdf")
    print("      -> output/report.pdf")

    print("\nDone. Open output/report.md, output/report.docx, or output/report.pdf")


if __name__ == "__main__":
    main()
