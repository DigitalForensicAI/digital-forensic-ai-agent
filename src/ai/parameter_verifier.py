"""
parameter_verifier.py

Deterministic Parameter & Factual Consistency Verifier.
Component: Digital Forensic AI Agent (ADME)

Addresses the B3 Overclaim / Scope Inflation weakness:
Even when a cited artifact_id exists and the claim is lexically/topically
relevant, the claim must be rejected if it asserts specific factual parameters
(numbers, quantities, file counts, byte volumes, IP addresses, ports,
protocols, file names, or unevidenced scope modifiers) not supported by the evidence.

Pipeline Position:
Claim -> Artifact Existence -> Lexical Relevance -> Parameter Consistency -> Verdict
"""

import re
from typing import Dict, List, Set, Any, Union, Optional


def normalize_text(text: Any) -> str:
    """Safely converts input to lowercase string."""
    return str(text).lower() if text is not None else ""


def extract_ips(text: str) -> List[str]:
    """Extracts valid IPv4 addresses from text."""
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    valid_ips = []
    for ip in candidates:
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            valid_ips.append(ip)
    return valid_ips


def extract_ports(text: str) -> Set[str]:
    """
    Extracts port numbers explicitly identified in text.
    Handles 'port 443', 'port: 443', 'on port 443', '443/tcp', '443/udp'.
    """
    ports = set()
    patterns = [
        r"\b(?:port\s*[:=]?\s*(\d{1,5}))\b",
        r"\bon port\s+(\d{1,5})\b",
        r"\b(\d{1,5})\s*/(?:tcp|udp)\b",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            p = m.group(1)
            if 1 <= int(p) <= 65535:
                ports.add(p)
    return ports


def extract_volumes(text: str) -> List[Dict[str, Any]]:
    """
    Extracts data volume and byte size assertions from text.
    Examples: '2 GB', '500GB', '1024 bytes', '10 MB'.
    """
    units = {
        "b": 1, "byte": 1, "bytes": 1,
        "kb": 1024, "kib": 1024,
        "mb": 1024**2, "mib": 1024**2,
        "gb": 1024**3, "gib": 1024**3,
        "tb": 1024**4, "tib": 1024**4,
    }
    volumes = []
    pattern = r"\b(\d+(?:\.\d+)?)\s*(bytes?|b|kb|kib|mb|mib|gb|gib|tb|tib)\b"
    for m in re.finditer(pattern, text, re.IGNORECASE):
        val = float(m.group(1))
        unit = m.group(2).lower()
        multiplier = units.get(unit, 1)
        bytes_val = int(val * multiplier)
        volumes.append({
            "text": m.group(0),
            "val": val,
            "unit": unit,
            "bytes": bytes_val,
        })
    return volumes


def extract_quantities(text: str) -> List[Dict[str, Any]]:
    """
    Extracts quantities and entity counts.
    Examples: '500 files', 'over 500 files', '500 confidential files', '10 records'.
    """
    quantities = []
    pattern = (
        r"\b(?:(?:over|more than|approximately|at least|about)\s+)?"
        r"(\d+)\s+(?:([a-zA-Z_-]+)\s+)?"
        r"(files?|records?|endpoints?|hosts?|machines?|servers?|accounts?|"
        r"credentials?|users?|passwords?|hashes?|documents?|folders?|directories?|"
        r"connections?|packets?)\b"
    )
    for m in re.finditer(pattern, text, re.IGNORECASE):
        count = int(m.group(1))
        modifier = m.group(2)
        noun = m.group(3).lower()
        quantities.append({
            "text": m.group(0),
            "count": count,
            "modifier": modifier.lower() if modifier else None,
            "noun": noun,
        })
    return quantities


def extract_files(text: str) -> List[str]:
    """Extracts explicit file names with extensions (e.g. m.exe, creds_dump.txt, out.zip)."""
    pattern = r"\b([a-zA-Z0-9_\-]+\.(?:exe|dll|txt|zip|ps1|bat|vbs|csv|json|docx|pdf|log|sys|bin))\b"
    return [m.lower() for m in re.findall(pattern, text, re.IGNORECASE)]


def extract_evidence_data(evidence: Union[Dict[str, Any], List[Any], str]) -> Dict[str, Any]:
    """
    Parses single/multiple evidence records or raw text into structured factual fields.
    """
    if isinstance(evidence, str):
        full_text = evidence
        events = [{"raw": evidence}]
    elif isinstance(evidence, list):
        events = evidence
        parts = []
        for e in events:
            if isinstance(e, str):
                parts.append(e)
            elif isinstance(e, dict):
                parts.extend([
                    str(e.get("raw", "")),
                    str(e.get("command", "")),
                    str(e.get("object", "")),
                    str(e.get("actor", "")),
                    str(e.get("event_type", "")),
                    str(e.get("src_ip", "")),
                    str(e.get("dst_ip", "")),
                    str(e.get("technique_name", "")),
                    str(e.get("technique_id", "")),
                    str(e.get("reason", "")),
                    str(e.get("source", "")),
                ])
                if isinstance(e.get("ioc"), list):
                    parts.extend(str(i) for i in e["ioc"])
        full_text = " ".join(parts)
    elif isinstance(evidence, dict):
        events = [evidence]
        parts = [
            str(evidence.get("raw", "")),
            str(evidence.get("command", "")),
            str(evidence.get("object", "")),
            str(evidence.get("actor", "")),
            str(evidence.get("event_type", "")),
            str(evidence.get("src_ip", "")),
            str(evidence.get("dst_ip", "")),
            str(evidence.get("technique_name", "")),
            str(evidence.get("technique_id", "")),
            str(evidence.get("reason", "")),
            str(evidence.get("source", "")),
        ]
        if isinstance(evidence.get("ioc"), list):
            parts.extend(str(i) for i in evidence["ioc"])
        full_text = " ".join(parts)
    else:
        full_text = str(evidence)
        events = []

    text_lower = full_text.lower()

    # Collect IPs
    ips = set(extract_ips(full_text))
    for e in events:
        if isinstance(e, dict):
            if e.get("src_ip"):
                ips.add(e["src_ip"].strip())
            if e.get("dst_ip"):
                ips.add(e["dst_ip"].strip())
            if isinstance(e.get("ioc"), list):
                for item in e["ioc"]:
                    item_str = str(item).strip()
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", item_str):
                        ips.add(item_str)

    # Collect Ports
    ports = set(extract_ports(full_text))
    # Extract ports from standard CSV/log columns (e.g. Zeek ',443,' or '10.0.0.10,135,')
    for m in re.finditer(r"[,:\s](\d{1,5})[,:\s]", full_text):
        p = m.group(1)
        if 1 <= int(p) <= 65535:
            ports.add(p)

    for e in events:
        if isinstance(e, dict):
            for k in ["port", "dst_port", "src_port"]:
                if val := e.get(k):
                    ports.add(str(val).strip())

    # Protocol knowledge mapping
    proto_map = {
        "https": {"443", "https", "web protocols", "t1071.001"},
        "http": {"80", "8080", "http", "web protocols", "t1071.001"},
        "smb": {"445", "139", "smb", "t1021.002"},
        "rdp": {"3389", "rdp", "t1021.001"},
        "dns": {"53", "dns", "t1071.004"},
        "ssh": {"22", "ssh", "t1021.004"},
        "kerberos": {"88", "kerberos", "t1558", "t1003.006"},
    }
    supported_protocols = set()
    for proto, indicators in proto_map.items():
        if any(ind in text_lower or ind in ports for ind in indicators):
            supported_protocols.add(proto)

    volumes = extract_volumes(full_text)
    quantities = extract_quantities(full_text)
    files = set(extract_files(full_text))

    return {
        "full_text": full_text,
        "text_lower": text_lower,
        "ips": ips,
        "ports": ports,
        "supported_protocols": supported_protocols,
        "volumes": volumes,
        "quantities": quantities,
        "files": files,
        "events": events,
    }


def check_parameter_consistency(
    claim_text: str,
    evidence: Union[Dict[str, Any], List[Any], str],
) -> Dict[str, Any]:
    """
    Deterministically verifies whether specific factual parameters asserted in
    claim_text are supported by or derivable from the cited evidence.

    Checks:
      1. IP addresses (exact presence)
      2. Ports (exact presence or port mapping)
      3. Protocols (supported directly or via known port/technique mapping)
      4. Data volumes / byte sizes (unsupported quantities/scales)
      5. Numerical quantities & file counts (B3 overclaim detection)
      6. Specific high-impact scope modifiers ('confidential', 'classified')
      7. File names (asserted binaries/documents must appear in evidence)

    Returns:
      {
        "passed": bool,
        "unsupported_parameters": List[str],
        "supported_parameters": List[str],
        "details": str
      }
    """
    ev_data = extract_evidence_data(evidence)
    ev_text_lower = ev_data["text_lower"]

    unsupported: List[str] = []
    supported: List[str] = []

    # 1. IP Addresses
    claim_ips = extract_ips(claim_text)
    for ip in claim_ips:
        if ip in ev_data["ips"] or ip in ev_text_lower:
            supported.append(f"IP: {ip}")
        else:
            unsupported.append(f"IP address '{ip}'")

    # 2. Ports
    claim_ports = extract_ports(claim_text)
    for port in claim_ports:
        if port in ev_data["ports"] or port in ev_text_lower:
            supported.append(f"Port: {port}")
        else:
            unsupported.append(f"Port '{port}'")

    # 3. Protocols
    for proto in ["https", "http", "smb", "rdp", "dns", "ssh", "kerberos"]:
        if re.search(rf"\b{proto}\b", claim_text, re.IGNORECASE):
            if proto in ev_data["supported_protocols"] or proto in ev_text_lower:
                supported.append(f"Protocol: {proto.upper()}")
            else:
                unsupported.append(f"Protocol '{proto.upper()}'")

    # 4. Data Volumes / Byte Sizes
    claim_volumes = extract_volumes(claim_text)
    for vol in claim_volumes:
        # Check if matching volume text is in evidence
        if vol["text"].lower() in ev_text_lower:
            supported.append(f"Volume: {vol['text']}")
            continue
        # Check numerical byte equivalence
        matched_vol = False
        for ev_v in ev_data["volumes"]:
            if ev_v["bytes"] == vol["bytes"]:
                matched_vol = True
                break
        if matched_vol:
            supported.append(f"Volume: {vol['text']}")
        else:
            unsupported.append(f"{vol['text']} data volume")

    # 5. Quantities & Counts (e.g. '500 files', '500 confidential files')
    claim_quantities = extract_quantities(claim_text)
    for q in claim_quantities:
        count = q["count"]
        noun = q["noun"]
        modifier = q["modifier"]

        # Scope modifier (e.g. 'confidential')
        if modifier:
            if modifier in ev_text_lower:
                supported.append(f"Scope attribute: {modifier}")
            else:
                unsupported.append(f"{modifier}")

        # Count check
        if count == 1:
            # 1 connection or 1 file is supported if the underlying event relates to that noun
            supported.append(f"Quantity: {q['text']}")
        else:
            # count > 1 (e.g. 500 files)
            # Must be explicitly supported in evidence
            count_str = str(count)
            count_supported = False
            if count_str in ev_text_lower:
                count_supported = True

            if count_supported:
                supported.append(f"Quantity: {q['text']}")
            else:
                unsupported.append(f"{count} {noun}")

    # 6. Specific Sensitive Scope Modifiers without evidence
    for qual in ["confidential", "classified"]:
        if re.search(rf"\b{qual}\b", claim_text, re.IGNORECASE):
            if qual not in ev_text_lower and qual not in unsupported:
                unsupported.append(qual)

    # 7. File Names
    claim_files = extract_files(claim_text)
    for fn in claim_files:
        if fn in ev_data["files"] or fn in ev_text_lower:
            supported.append(f"File: {fn}")
        else:
            unsupported.append(f"File '{fn}'")

    passed = len(unsupported) == 0
    return {
        "passed": passed,
        "unsupported_parameters": unsupported,
        "supported_parameters": supported,
        "details": (
            "All factual parameters verified against evidence"
            if passed
            else f"Unsupported parameters: {', '.join(unsupported)}"
        ),
    }
