"""
provenance.py  —  Person 1

Builds a provenance graph from correlations.json (the deterministic half of your work).
NO LLM here. Just rules that turn events into nodes and edges.

Node types:  user, process, file, network
Edges:       user --started--> process
             process --wrote--> file
             process --connected_to--> network
             process --executed--> command

Run:
    python -m src.graph.provenance data/samples/correlations.json
Produces:
    output/graph.png
    and returns the networkx graph + a text serialization for the LLM.
"""

import json
import sys
import os
import networkx as nx
import matplotlib
matplotlib.use("Agg")  # no display needed, just save a file
import matplotlib.pyplot as plt


def load_events(path):
    with open(path) as f:
        data = json.load(f)
    return data.get("case_id", "unknown"), data.get("events", [])


def build_graph(events):
    """Turn events into a NetworkX directed graph using deterministic rules."""
    g = nx.DiGraph()

    def add_node(name, ntype, artifact_id):
        if name in ("", None):
            return None
        if g.has_node(name):
            # record that this artifact also touched the node
            g.nodes[name]["artifact_ids"].add(artifact_id)
        else:
            g.add_node(name, ntype=ntype, artifact_ids={artifact_id})
        return name

    for e in events:
        aid = e["artifact_id"]
        actor = e.get("actor", "")
        obj = e.get("object", "")
        etype = e.get("event_type", "")
        command = e.get("command", "")
        dst_ip = e.get("dst_ip", "")

        # user --started--> process
        u = add_node(actor, "user", aid)
        p = add_node(obj, "process", aid)
        if u and p and etype == "process_creation":
            g.add_edge(u, p, label="started", artifact_id=aid)

        # process --executed--> command
        if p and command:
            c = add_node(command, "command", aid)
            g.add_edge(p, c, label="executed", artifact_id=aid)

        # process --wrote--> file  (registry_write / file_write)
        if p and etype in ("registry_write", "file_write"):
            target = e.get("raw", f"file_{aid}")
            fnode = add_node(target, "file", aid)
            if fnode:
                g.add_edge(p, fnode, label="wrote", artifact_id=aid)

        # process --connected_to--> network
        if p and etype == "network_connection" and dst_ip:
            n = add_node(dst_ip, "network", aid)
            g.add_edge(p, n, label="connected_to", artifact_id=aid)

    return g


def graph_to_text(g):
    """Serialize edges as 'A --edge--> B [artifact_id]' lines for the LLM prompt."""
    lines = []
    for a, b, d in g.edges(data=True):
        lines.append(f"{a} --{d['label']}--> {b} [{d['artifact_id']}]")
    return "\n".join(lines)


def draw(g, out_path="output/graph.png"):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    colors = {"user": "#4c72b0", "process": "#dd8452",
              "file": "#55a868", "network": "#c44e52", "command": "#8172b3"}
    node_colors = [colors.get(g.nodes[n].get("ntype"), "#999999") for n in g.nodes]
    pos = nx.spring_layout(g, seed=42, k=1.2)
    plt.figure(figsize=(11, 7))
    nx.draw(g, pos, with_labels=True, node_color=node_colors,
            node_size=1600, font_size=7, font_color="white",
            edgecolors="black", linewidths=0.5, arrows=True)
    edge_labels = {(a, b): d["label"] for a, b, d in g.edges(data=True)}
    nx.draw_networkx_edge_labels(g, pos, edge_labels=edge_labels, font_size=6)
    plt.title("Provenance Graph")
    plt.tight_layout()
    plt.savefig(out_path, dpi=140)
    plt.close()
    return out_path


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/samples/correlations.json"
    case_id, events = load_events(path)
    g = build_graph(events)
    print(f"case: {case_id}")
    print(f"nodes: {g.number_of_nodes()}  edges: {g.number_of_edges()}")
    print("--- graph as text (this is what the LLM sees) ---")
    print(graph_to_text(g))
    out = draw(g)
    print(f"--- saved {out} ---")
