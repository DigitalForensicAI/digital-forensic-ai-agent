import argparse
import os

from src.graph.provenance import load_events, build_graph, draw
from src.ai.reason import reconstruct
from src.ai.verify import verify
from src.report.render import render


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

    print("[4/4] rendering report...")
    md = render(verified)
    with open("output/report.md", "w") as f:
        f.write(md)
    print("      -> output/report.md")

    print("\nDone. Open output/report.md")


if __name__ == "__main__":
    main()
