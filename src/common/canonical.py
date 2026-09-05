from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional


def normalize_timestamp(ts: Any) -> str:
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    ts_str = str(ts).strip()
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue

    return ts_str


@dataclass
class CanonicalEvent:
    artifact_id: str
    timestamp: str
    event_type: str
    actor: str = ""
    object: str = ""
    command: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    raw: str = ""
    source: str = ""
    session_id: str = ""

    def __post_init__(self):
        self.artifact_id = str(self.artifact_id).strip()
        self.timestamp = normalize_timestamp(self.timestamp)
        self.event_type = str(self.event_type).strip().lower()
        self.actor = str(self.actor or "").strip()
        self.object = str(self.object or "").strip()
        self.command = str(self.command or "").strip()
        self.src_ip = str(self.src_ip or "").strip()
        self.dst_ip = str(self.dst_ip or "").strip()
        self.raw = str(self.raw or "").strip()
        self.source = str(self.source or "").strip()
        self.session_id = str(self.session_id or "").strip()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalEvent":
        return cls(
            artifact_id=data.get("artifact_id", ""),
            timestamp=data.get("timestamp", ""),
            event_type=data.get("event_type", ""),
            actor=data.get("actor", ""),
            object=data.get("object", ""),
            command=data.get("command", ""),
            src_ip=data.get("src_ip", ""),
            dst_ip=data.get("dst_ip", ""),
            raw=data.get("raw", ""),
            source=data.get("source", ""),
            session_id=data.get("session_id", ""),
        )


@dataclass
class CanonicalCase:
    case_id: str
    events: List[CanonicalEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "events": [e.to_dict() for e in self.events],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalCase":
        case_id = data.get("case_id", "case_unknown")
        raw_events = data.get("events", [])
        events = [CanonicalEvent.from_dict(e) for e in raw_events]
        return cls(case_id=case_id, events=events)

    @classmethod
    def from_json(cls, json_str: str) -> "CanonicalCase":
        return cls.from_dict(json.loads(json_str))
