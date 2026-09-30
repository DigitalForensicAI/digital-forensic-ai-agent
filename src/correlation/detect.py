import argparse
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

DEFAULT_RULES_PATH = Path(__file__).parent.parent.parent / "data" / "mitre_map.json"
DEFAULT_IOC_PATH = Path(__file__).parent.parent.parent / "data" / "ioc_list.json"
LOCAL_RULES_PATH = Path(__file__).parent.parent / "detect" / "mitre_map.json"

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
]


def is_external_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    raw_ip = ip_str.split(":")[0].strip()
    try:
        ip = ipaddress.ip_address(raw_ip)
        return not any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def load_rules(rules_path: Optional[str] = None, ioc_path: Optional[str] = None) -> Dict[str, Any]:
    target_rule_path = None
    if rules_path and Path(rules_path).exists():
        target_rule_path = Path(rules_path)
    elif DEFAULT_RULES_PATH.exists():
        target_rule_path = DEFAULT_RULES_PATH
    elif LOCAL_RULES_PATH.exists():
        target_rule_path = LOCAL_RULES_PATH

    techniques = []
    if target_rule_path and target_rule_path.exists():
        with open(target_rule_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            techniques = data.get("techniques", []) if isinstance(data, dict) else data

    target_ioc_path = Path(ioc_path) if ioc_path else DEFAULT_IOC_PATH
    known_iocs = {"ips": [], "domains": [], "hashes": []}
    if target_ioc_path.exists():
        with open(target_ioc_path, "r", encoding="utf-8") as f:
            known_iocs = json.load(f)

    return {"techniques": techniques, "known_iocs": known_iocs}


def evaluate_mitre(event: Dict[str, Any], techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []

    event_type = str(event.get("event_type", "")).strip().lower()
    actor = str(event.get("actor", "")).strip().lower()
    obj = str(event.get("object", "")).strip().lower()
    cmd = str(event.get("command", "")).strip().lower()
    dst_ip = str(event.get("dst_ip", "")).strip()
    raw_str = str(event.get("raw", "")).lower()

    for tech in techniques:
        cond = tech.get("conditions", tech.get("match", {}))
        is_matched = True

        req_types = cond.get("event_types") or ([cond["event_type"]] if "event_type" in cond else None)
        if req_types:
            normalized_types = [t.lower().replace("_", "") for t in req_types]
            if event_type.replace("_", "") not in normalized_types:
                is_matched = False

        actor_contains = cond.get("actor_contains") or ([cond["actor"]] if "actor" in cond else None)
        if actor_contains and not any(sub.lower() in actor for sub in actor_contains):
            is_matched = False

        obj_contains = cond.get("object_contains") or ([cond["object"]] if "object" in cond else None)
        if obj_contains and not any(sub.lower() in obj or sub.lower() in raw_str for sub in obj_contains):
            is_matched = False

        cmd_contains = cond.get("command_contains") or ([cond["command"]] if "command" in cond else None)
        if cmd_contains and not any(sub.lower() in cmd or sub.lower() in raw_str for sub in cmd_contains):
            is_matched = False

        if cond.get("external_dst_ip"):
            if not (is_external_ip(dst_ip) or is_external_ip(obj)):
                is_matched = False

        if is_matched:
            matches.append({
                "technique_id": tech["technique_id"],
                "name": tech["name"],
                "tactic": tech.get("tactic", ""),
                "confidence": tech.get("confidence", 0.75),
            })

    return matches


def evaluate_iocs(event: Dict[str, Any], known_iocs: Dict[str, List[str]]) -> List[str]:
    found_iocs: List[str] = []

    dst_ip = str(event.get("dst_ip", "")).split(":")[0].strip()
    src_ip = str(event.get("src_ip", "")).split(":")[0].strip()
    obj = str(event.get("object", ""))
    cmd = str(event.get("command", ""))
    raw = str(event.get("raw", ""))

    known_ips = set(known_iocs.get("ips", []))
    if dst_ip and dst_ip in known_ips and dst_ip not in found_iocs:
        found_iocs.append(dst_ip)
    if src_ip and src_ip in known_ips and src_ip not in found_iocs:
        found_iocs.append(src_ip)

    search_space = f"{obj} {cmd} {raw}"
    for ip in known_ips:
        if ip and ip in search_space and ip not in found_iocs:
            found_iocs.append(ip)

    for domain in known_iocs.get("domains", []):
        if domain and domain in search_space and domain not in found_iocs:
            found_iocs.append(domain)

    for file_hash in known_iocs.get("hashes", []):
        if file_hash and file_hash in search_space and file_hash not in found_iocs:
            found_iocs.append(file_hash)

    return found_iocs


def correlate_event(event: Dict[str, Any], rules: Dict[str, Any]) -> Dict[str, Any]:
    techniques = rules.get("techniques", [])
    known_iocs = rules.get("known_iocs", {})

    mitre_matches = evaluate_mitre(event, techniques)
    ioc_matches = evaluate_iocs(event, known_iocs)

    output = {
        "artifact_id": str(event.get("artifact_id", "")),
        "timestamp": str(event.get("timestamp", "")),
        "event_type": str(event.get("event_type", "")),
        "actor": str(event.get("actor", "")),
        "object": str(event.get("object", "")),
        "command": str(event.get("command", "")),
        "src_ip": str(event.get("src_ip", "")),
        "dst_ip": str(event.get("dst_ip", "")),
        "raw": event.get("raw", ""),
        "suspicious": False,
        "technique_id": "",
        "technique_name": "",
        "reason": "",
        "confidence": 0.0,
        "mitre": mitre_matches,
        "ioc": ioc_matches,
    }

    if mitre_matches or ioc_matches:
        output["suspicious"] = True
        if mitre_matches:
            primary = mitre_matches[0]
            output["technique_id"] = primary["technique_id"]
            output["technique_name"] = primary["name"]
            output["reason"] = f"Detected {primary['name']} ({primary['technique_id']})"
            output["confidence"] = primary.get("confidence", 0.75)
            if ioc_matches:
                output["reason"] += f"; Matched IOC: {', '.join(ioc_matches)}"
                output["confidence"] = min(1.0, output["confidence"] + 0.1)
        elif ioc_matches:
            output["reason"] = f"Matched known IOC: {', '.join(ioc_matches)}"
            output["confidence"] = 0.85

    for k, v in event.items():
        if k not in output:
            output[k] = v

    return output


def correlate_events(case_id: str, events: List[Dict[str, Any]], rules: Dict[str, Any]) -> Dict[str, Any]:
    correlated = [correlate_event(ev, rules) for ev in events]
    return {
        "case_id": case_id,
        "events": correlated,
    }


def correlate_from_file(input_path: str, rules_path: Optional[str] = None, ioc_path: Optional[str] = None) -> Dict[str, Any]:
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rules = load_rules(rules_path=rules_path, ioc_path=ioc_path)

    if isinstance(data, list):
        case_id = "incident_01"
        events = data
    elif isinstance(data, dict):
        case_id = data.get("case_id", "incident_01")
        events = data.get("events", [])
    else:
        case_id = "unknown"
        events = []

    return correlate_events(case_id, events, rules)


def process_correlations(input_path: str, output_path: str, rules_path: Optional[str] = None, ioc_path: Optional[str] = None) -> List[Dict[str, Any]]:
    result = correlate_from_file(input_path, rules_path=rules_path, ioc_path=ioc_path)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result["events"], f, indent=2)
    return result["events"]


def main():
    parser = argparse.ArgumentParser(description="Correlate forensic events with MITRE ATT&CK techniques and IOCs.")
    parser.add_argument("input_path", help="Path to input canonical events JSON")
    parser.add_argument("--rules", default=None, help="Path to mitre_map.json (optional)")
    parser.add_argument("--iocs", default=None, help="Path to ioc_list.json (optional)")
    parser.add_argument("--out", default="output/correlations.json", help="Output path for correlated events JSON")
    parser.add_argument("--list-format", action="store_true", help="Save output directly as a JSON array of events")

    args = parser.parse_args()

    result = correlate_from_file(args.input_path, rules_path=args.rules, ioc_path=args.iocs)
    payload = result["events"] if args.list_format else result

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"[+] Saved correlation output to {args.out}")


if __name__ == "__main__":
    main()
