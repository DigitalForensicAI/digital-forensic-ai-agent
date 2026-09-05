import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import List, Tuple

from src.common.canonical import CanonicalEvent, CanonicalCase, normalize_timestamp
from src.common.db import insert_events, get_timeline


ACTION_MAP = {
    "processcreate": "process_creation",
    "networkconnect": "network_connection",
    "filecreate": "file_write",
    "filewrite": "file_write",
    "filedelete": "file_delete",
    "registrywrite": "registry_write",
    "registrycreate": "registry_write",
    "processaccess": "process_access",
    "processaccessgranted": "process_access",
    "directoryreplicationrequest": "directory_replication",
    "logonsuccess": "logon_success",
    "connectionallowed": "network_connection",
    "processterminate": "process_terminate",
}


def parse_csv_log(file_path: str, default_source: str = "sysmon", default_session: str = "s1") -> List[CanonicalEvent]:
    events: List[CanonicalEvent] = []
    
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        sample = f.readline()
        f.seek(0)
        
        has_header = False
        sample_lower = sample.lower()
        if any(h in sample_lower for h in ["timestamp", "actor", "event_type", "object", "command", "user", "action", "process_name"]):
            has_header = True

        reader = csv.reader(f)
        if has_header:
            header = [h.strip().lower() for h in next(reader)]
            col_map = {col: i for i, col in enumerate(header)}
        else:
            col_map = {
                "timestamp": 0,
                "actor": 1,
                "event_type": 2,
                "object": 3,
                "command": 4,
                "src_ip": 5,
                "dst_ip": 6,
            }

        idx = 1
        for row in reader:
            if not row or all(c.strip() == "" for c in row):
                continue

            def get_val(names: List[str], fallback_idx: int = -1, default: str = "") -> str:
                for name in names:
                    if name in col_map and col_map[name] < len(row):
                        val = row[col_map[name]].strip()
                        if val:
                            return val
                if 0 <= fallback_idx < len(row):
                    val = row[fallback_idx].strip()
                    if val:
                        return val
                return default

            raw_line = ",".join(row)
            
            # Artifact ID
            event_id_val = get_val(["artifact_id", "event_id"])
            if event_id_val:
                try:
                    artifact_id = f"evt_{int(event_id_val):05d}"
                except ValueError:
                    artifact_id = event_id_val if event_id_val.startswith("evt_") else f"evt_{event_id_val}"
            else:
                artifact_id = f"evt_{idx:05d}"

            ts = get_val(["timestamp", "time"], 0)
            actor = get_val(["actor", "user"], 1)
            
            # Event type & normalization
            raw_action = get_val(["event_type", "action"], 2).lower().replace("_", "").replace("-", "")
            event_type = ACTION_MAP.get(raw_action, get_val(["event_type", "action"], 2).lower())
            
            # Object
            obj = get_val(["object", "process_name", "target_object", "target"], 3)
            cmd = get_val(["command", "command_line", "cmd"], 4)
            src_ip = get_val(["src_ip", "network_src_ip", "source_ip"], 5)
            dst_ip = get_val(["dst_ip", "network_dest_ip", "destination_ip"], 6)
            source = get_val(["source", "log_source"], -1, default_source)
            session_id = get_val(["session_id"], -1, default_session)
            raw = get_val(["raw"], -1, raw_line)

            event = CanonicalEvent(
                artifact_id=artifact_id,
                timestamp=ts,
                event_type=event_type,
                actor=actor,
                object=obj,
                command=cmd,
                src_ip=src_ip,
                dst_ip=dst_ip,
                raw=raw,
                source=source,
                session_id=session_id,
            )
            events.append(event)
            idx += 1

    return events


def process_logs(
    log_path: str,
    case_id: str = "incident_01",
    db_path: str = "output/forensics.db",
    out_json: str = "output/canonical_events.json",
) -> CanonicalCase:
    events = parse_csv_log(log_path)
    insert_events(case_id, events, db_path=db_path)
    sorted_events = get_timeline(case_id, db_path=db_path)
    canonical_case = CanonicalCase(case_id=case_id, events=sorted_events)
    
    if out_json:
        os.makedirs(os.path.dirname(os.path.abspath(out_json)), exist_ok=True)
        with open(out_json, "w", encoding="utf-8") as f:
            f.write(canonical_case.to_json(indent=2))

    return canonical_case


def main():
    parser = argparse.ArgumentParser(description="Forensic log parser and SQLite database loader.")
    parser.add_argument("log_path", help="Path to input raw CSV or log file")
    parser.add_argument("--case-id", default="incident_01", help="Case identifier (default: incident_01)")
    parser.add_argument("--db", default="output/forensics.db", help="Path to SQLite database")
    parser.add_argument("--out", default="output/canonical_events.json", help="Path to output canonical JSON file")

    args = parser.parse_args()

    print(f"[*] Ingesting {args.log_path} for case {args.case_id}...")
    case = process_logs(args.log_path, case_id=args.case_id, db_path=args.db, out_json=args.out)
    print(f"[+] Loaded {len(case.events)} canonical events into database.")


if __name__ == "__main__":
    main()
