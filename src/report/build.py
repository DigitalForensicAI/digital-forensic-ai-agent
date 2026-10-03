"""
Build a structured forensic investigation report from the pipeline's
verified-reconstruction output and the correlated event evidence.

Input:
  - verified: output of the Review 2 verifier
  - events:   full list of correlated events for the case

Output:
  One structured report dict used by the Markdown, DOCX, and PDF exporters.
"""

import json
import sys
from datetime import datetime, timezone


def _event_techniques(event):
    """Normalize an event's MITRE tags to unique (technique_id, name) pairs.

    Supports both shapes used across this codebase:
      - event["mitre"] = [{"technique_id": .., "name": ..}, ...]
      - event["technique_id"] / event["technique_name"]
    """

    out = []
    seen = set()

    # MITRE list form
    for m in event.get("mitre", []) or []:
        tid = m.get("technique_id", "")
        name = m.get(
            "name",
            m.get("technique_name", "")
        )

        key = (tid, name)

        if (tid or name) and key not in seen:
            out.append(key)
            seen.add(key)

    # Single-technique form
    if event.get("technique_id"):
        tid = event["technique_id"]
        name = event.get("technique_name", "")

        key = (tid, name)

        if key not in seen:
            out.append(key)
            seen.add(key)

    return out


def build_timeline(events):
    """Chronological view of every event with MITRE/IOC tags attached."""

    timeline = []

    for e in sorted(
        events,
        key=lambda x: x.get("timestamp", "")
    ):
        techniques = _event_techniques(e)

        timeline.append({
            "artifact_id": e.get("artifact_id", ""),
            "timestamp": e.get("timestamp", ""),
            "actor": e.get("actor", ""),
            "event_type": e.get("event_type", ""),
            "object": e.get("object", ""),
            "command": e.get("command", ""),
            "dst_ip": e.get("dst_ip", ""),

            "techniques": [
                f"{tid} {name}".strip()
                for tid, name in techniques
            ],

            "ioc": e.get("ioc", []) or [],

            "suspicious": (
                bool(e.get("suspicious"))
                or bool(techniques)
            ),
        })

    return timeline


def build_techniques_detected(events):
    """Roll every event's MITRE tags into one row per technique.

    Each artifact ID is counted only once per technique.
    """

    rollup = {}

    for e in events:
        event_id = e.get("artifact_id", "")

        for tid, name in _event_techniques(e):
            key = tid or name

            row = rollup.setdefault(
                key,
                {
                    "technique_id": tid,
                    "technique_name": name,
                    "artifact_ids": [],
                }
            )

            # Prevent duplicate artifact IDs
            if (
                event_id
                and event_id not in row["artifact_ids"]
            ):
                row["artifact_ids"].append(event_id)

    for row in rollup.values():
        row["count"] = len(row["artifact_ids"])

    return sorted(
        rollup.values(),
        key=lambda r: (
            r["technique_id"]
            or r["technique_name"]
        )
    )


def build_evidence_appendix(events):
    """Full raw record of every event for citation-checking and audit."""

    return [
        {
            "artifact_id": e.get("artifact_id", ""),
            "timestamp": e.get("timestamp", ""),
            "source": e.get("source", ""),
            "session_id": e.get("session_id", ""),
            "actor": e.get("actor", ""),
            "event_type": e.get("event_type", ""),
            "object": e.get("object", ""),
            "command": e.get("command", ""),
            "src_ip": e.get("src_ip", ""),
            "dst_ip": e.get("dst_ip", ""),
            "raw": e.get("raw", ""),
        }
        for e in sorted(
            events,
            key=lambda x: x.get("timestamp", "")
        )
    ]


def build_narrative(verified):
    """Normalize verified stages into the report narrative format."""

    narrative = []

    for s in verified.get("stages", []):
        narrative.append({
            "stage": s.get(
                "stage",
                "Stage"
            ),

            "claim": s.get(
                "claim",
                ""
            ),

            "artifact_ids": s.get(
                "artifact_ids",
                []
            ) or [],

            "confidence": s.get(
                "confidence",
                "n/a"
            ),

            "grounded": bool(
                s.get("grounded")
            ),

            "missing_ids": s.get(
                "missing_ids",
                []
            ) or [],
        })

    return narrative


def build_executive_summary(
    verified,
    narrative,
    techniques_detected
):
    """Use the reconstruction's summary if present.

    Otherwise generate a short fallback summary.
    """

    summary = (
        verified.get("summary") or ""
    ).strip()

    if summary:
        return summary

    tech_names = ", ".join(
        (
            f"{t['technique_id']} "
            f"({t['technique_name']})"
            if t["technique_name"]
            else t["technique_id"]
        )
        for t in techniques_detected[:5]
    )

    return (
        f"Investigation of case "
        f"{verified.get('case_id', 'unknown')} "
        f"reconstructed "
        f"{len(narrative)} attack stage(s) "
        f"spanning "
        f"{len(techniques_detected)} distinct "
        f"MITRE ATT&CK technique(s)"
        f"{': ' + tech_names if tech_names else ''}. "
        f"{verified.get('grounded_claims', 0)}/"
        f"{verified.get('total_claims', 0)} "
        f"stage claims are directly backed "
        f"by cited evidence."
    )


def build_report(
    verified,
    events,
    graph_path="graph.png"
):
    """Build the complete structured forensic report."""

    narrative = build_narrative(
        verified
    )

    techniques_detected = build_techniques_detected(
        events
    )

    return {
        "case_id": verified.get(
            "case_id",
            "unknown"
        ),

        "generated_at": datetime.now(
            timezone.utc
        ).strftime(
            "%Y-%m-%d %H:%M UTC"
        ),

        "executive_summary": build_executive_summary(
            verified,
            narrative,
            techniques_detected
        ),

        "grounding": {
            "score": verified.get(
                "grounding_score",
                0
            ),

            "grounded_claims": verified.get(
                "grounded_claims",
                0
            ),

            "total_claims": verified.get(
                "total_claims",
                0
            ),
        },

        "graph_path": graph_path,

        "timeline": build_timeline(
            events
        ),

        "techniques_detected": techniques_detected,

        "narrative": narrative,

        "unsupported_claims": verified.get(
            "unsupported_claims",
            []
        ) or [],

        "evidence_appendix": build_evidence_appendix(
            events
        ),

        "limitations": verified.get(
            "limitations",
            "None stated."
        ),
    }


def run(
    verified_path,
    correlations_path,
    out_path="output/report.json"
):
    """Build report from JSON files."""

    with open(
        verified_path,
        encoding="utf-8"
    ) as f:
        verified = json.load(f)

    with open(
        correlations_path,
        encoding="utf-8"
    ) as f:
        corr = json.load(f)

    report = build_report(
        verified,
        corr.get("events", [])
    )

    import os

    os.makedirs(
        os.path.dirname(
            os.path.abspath(out_path)
        ),
        exist_ok=True
    )

    with open(
        out_path,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            report,
            f,
            indent=2
        )

    return report


if __name__ == "__main__":
    verified_path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "output/verified.json"
    )

    correlations_path = (
        sys.argv[2]
        if len(sys.argv) > 2
        else "data/samples/correlations.json"
    )

    report = run(
        verified_path,
        correlations_path
    )

    print(
        f"--- built report for case "
        f"{report['case_id']} "
        f"-> output/report.json ---"
    )