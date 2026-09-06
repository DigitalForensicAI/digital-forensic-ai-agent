import argparse
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_MITRE_PATH = Path(__file__).parent.parent.parent / "data" / "mitre_map.json"
DEFAULT_IOC_PATH = Path(__file__).parent.parent.parent / "data" / "ioc_list.json"


def is_external_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False


def load_rules(mitre_path: Optional[str] = None, ioc_path: Optional[str] = None) -> Dict[str, Any]:
    m_path = Path(mitre_path) if mitre_path else DEFAULT_MITRE_PATH
    i_path = Path(ioc_path) if ioc_path else DEFAULT_IOC_PATH

    techniques = []
    if m_path.exists():
        with open(m_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            techniques = data.get("techniques", []) if isinstance(data, dict) else data

    known_iocs = {"ips": [], "domains": [], "hashes": []}
    if i_path.exists():
        with open(i_path, "r", encoding="utf-8") as f:
            known_iocs = json.load(f)

    return {"techniques": techniques, "known_iocs": known_iocs}


def evaluate_mitre(event: Dict[str, Any], techniques: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    matches: List[Dict[str, str]] = []
    
    event_type = event.get("event_type", "").lower()
    obj = event.get("object", "").lower()
    cmd = event.get("command", "").lower()
    dst_ip = event.get("dst_ip", "")

    for tech in techniques:
        cond = tech.get("conditions", tech.get("match", {}))
        matched = True

        req_types = cond.get("event_types") or ([cond["event_type"]] if "event_type" in cond else None)
        if req_types and event_type not in [t.lower() for t in req_types]:
            matched = False

        obj_contains = cond.get("object_contains") or ([cond["object"]] if "object" in cond else None)
        if obj_contains and not any(sub.lower() in obj for sub in obj_contains):
            matched = False

        cmd_contains = cond.get("command_contains") or ([cond["command"]] if "command" in cond else None)
        if cmd_contains and not any(sub.lower() in cmd for sub in cmd_contains):
            matched = False

        if cond.get("external_dst_ip") or cond.get("needs_ioc"):
            if not is_external_ip(dst_ip):
                matched = False

        if matched:
            matches.append({
                "technique_id": tech["technique_id"],
                "name": tech["name"],
                "tactic": tech.get("tactic", ""),
            })

    return matches


def evaluate_iocs(event: Dict[str, Any], known_iocs: Dict[str, List[str]]) -> List[str]:
    found_iocs: List[str] = []
    
    dst_ip = event.get("dst_ip", "").strip()
    src_ip = event.get("src_ip", "").strip()
    known_ips = set(known_iocs.get("ips", []))
    
    if dst_ip and dst_ip in known_ips and dst_ip not in found_iocs:
        found_iocs.append(dst_ip)
    if src_ip and src_ip in known_ips and src_ip not in found_iocs:
        found_iocs.append(src_ip)

    cmd = event.get("command", "")
    raw = event.get("raw", "")
    search_space = f"{cmd} {raw}"

    for domain in known_iocs.get("domains", []):
        if domain and domain in search_space and domain not in found_iocs:
            found_iocs.append(domain)

    for file_hash in known_iocs.get("hashes", []):
        if file_hash and file_hash in search_space and file_hash not in found_iocs:
            found_iocs.append(file_hash)

    return found_iocs


def correlate_events(case_id: str, events: List[Dict[str, Any]], rules: Dict[str, Any]) -> Dict[str, Any]:
    techniques = rules.get("techniques", [])
    known_iocs = rules.get("known_iocs", {})
    
    correlated_events = []
    for ev in events:
        event_dict = dict(ev)
        mitre_tags = evaluate_mitre(event_dict, techniques)
        ioc_tags = evaluate_iocs(event_dict, known_iocs)

        event_dict["mitre"] = mitre_tags
        event_dict["ioc"] = ioc_tags

        if mitre_tags or ioc_tags:
            event_dict["suspicious"] = True
            if mitre_tags:
                event_dict["technique_id"] = mitre_tags[0]["technique_id"]
                event_dict["technique_name"] = mitre_tags[0]["name"]
                event_dict["reason"] = f"Detected {mitre_tags[0]['name']} ({mitre_tags[0]['technique_id']})"
            elif ioc_tags:
                event_dict["reason"] = f"Matched known IOC: {', '.join(ioc_tags)}"

        ordered_keys = [
            "timestamp", "source", "event_type", "actor", "object",
            "command", "src_ip", "dst_ip", "raw", "artifact_id",
            "session_id", "mitre", "ioc", "suspicious", "technique_id",
            "technique_name", "reason"
        ]
        clean_event = {k: event_dict[k] for k in ordered_keys if k in event_dict}
        for k, v in event_dict.items():
            if k not in clean_event:
                clean_event[k] = v

        correlated_events.append(clean_event)

    return {
        "case_id": case_id,
        "events": correlated_events,
    }


def correlate_from_file(input_path: str, mitre_path: Optional[str] = None, ioc_path: Optional[str] = None) -> Dict[str, Any]:
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    case_id = data.get("case_id", "incident_01")
    events = data.get("events", [])
    rules = load_rules(mitre_path, ioc_path)
    return correlate_events(case_id, events, rules)


def main():
    parser = argparse.ArgumentParser(description="Correlate forensic events with MITRE ATT&CK techniques and IOCs.")
    parser.add_argument("input_path", help="Path to input canonical events JSON")
    parser.add_argument("--mitre", default=None, help="Path to mitre_map.json (optional)")
    parser.add_argument("--ioc", default=None, help="Path to ioc_list.json (optional)")
    parser.add_argument("--out", default="output/correlations.json", help="Output path for correlated events JSON")

    args = parser.parse_args()

    result = correlate_from_file(args.input_path, mitre_path=args.mitre, ioc_path=args.ioc)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Saved correlation output to {args.out}")


if __name__ == "__main__":
    main()
