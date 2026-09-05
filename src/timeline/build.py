import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from src.common.canonical import CanonicalEvent, CanonicalCase
from src.common.db import get_timeline, insert_events


def parse_iso(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def group_sessions(events: List[CanonicalEvent], max_gap_seconds: int = 600) -> List[CanonicalEvent]:
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: (e.timestamp, e.artifact_id))
    session_num = 1
    prev_time = None

    for ev in sorted_events:
        curr_time = parse_iso(ev.timestamp)
        if prev_time is not None:
            gap = (curr_time - prev_time).total_seconds()
            if gap > max_gap_seconds:
                session_num += 1

        if not ev.session_id or ev.session_id == "s1":
            ev.session_id = f"s{session_num}"

        prev_time = curr_time

    return sorted_events


def build_timeline(case_id: str = "incident_01", db_path: str = "output/forensics.db", out_path: str = "output/canonical_events.json") -> CanonicalCase:
    events = get_timeline(case_id, db_path=db_path)
    grouped = group_sessions(events)
    insert_events(case_id, grouped, db_path=db_path)

    canonical_case = CanonicalCase(case_id=case_id, events=grouped)
    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(canonical_case.to_json(indent=2))

    return canonical_case


def main():
    parser = argparse.ArgumentParser(description="Build chronological timeline and group sessions.")
    parser.add_argument("--case-id", default="incident_01", help="Case identifier")
    parser.add_argument("--db", default="output/forensics.db", help="Path to SQLite database")
    parser.add_argument("--out", default="output/canonical_events.json", help="Path to output canonical JSON file")

    args = parser.parse_args()
    case = build_timeline(case_id=args.case_id, db_path=args.db, out_path=args.out)
    print(f"[+] Reconstructed timeline with {len(case.events)} events grouped into sessions.")
    print(f"[+] Exported to {args.out}")


if __name__ == "__main__":
    main()
