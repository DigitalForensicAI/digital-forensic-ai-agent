import os
import sqlite3
from pathlib import Path
from typing import List, Optional, Dict, Any

from .canonical import CanonicalEvent, CanonicalCase

DEFAULT_SCHEMA_PATH = Path(__file__).parent.parent.parent / "schema.sql"
DEFAULT_DB_PATH = "output/forensics.db"


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH, schema_path: Optional[str] = None) -> None:
    schema_file = Path(schema_path) if schema_path else DEFAULT_SCHEMA_PATH
    if not schema_file.exists():
        schema_file = Path(__file__).parent.parent / "parser" / "schema.sql"
    with open(schema_file, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    with get_connection(db_path) as conn:
        conn.executescript(schema_sql)


def insert_events(case_id: str, events: List[CanonicalEvent], db_path: str = DEFAULT_DB_PATH) -> int:
    init_db(db_path)

    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO cases (case_id) VALUES (?)
            ON CONFLICT(case_id) DO NOTHING
            """,
            (case_id,),
        )

        records = [
            (
                e.artifact_id,
                case_id,
                e.timestamp,
                e.event_type,
                e.actor,
                e.object,
                e.command,
                e.src_ip,
                e.dst_ip,
                e.raw,
                e.source,
                e.session_id,
            )
            for e in events
        ]

        conn.executemany(
            """
            INSERT INTO events (
                artifact_id, case_id, timestamp, event_type,
                actor, object, command, src_ip, dst_ip,
                raw, source, session_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
                case_id=excluded.case_id,
                timestamp=excluded.timestamp,
                event_type=excluded.event_type,
                actor=excluded.actor,
                object=excluded.object,
                command=excluded.command,
                src_ip=excluded.src_ip,
                dst_ip=excluded.dst_ip,
                raw=excluded.raw,
                source=excluded.source,
                session_id=excluded.session_id
            """,
            records,
        )
        conn.commit()

    return len(events)


def get_timeline(case_id: str, db_path: str = DEFAULT_DB_PATH, reverse: bool = False) -> List[CanonicalEvent]:
    direction = "DESC" if reverse else "ASC"
    query = f"""
        SELECT artifact_id, timestamp, event_type, actor, object,
               command, src_ip, dst_ip, raw, source, session_id
        FROM events
        WHERE case_id = ?
        ORDER BY timestamp {direction}, artifact_id ASC
    """
    with get_connection(db_path) as conn:
        cursor = conn.execute(query, (case_id,))
        rows = cursor.fetchall()

    return [CanonicalEvent.from_dict(dict(row)) for row in rows]


def get_events_by_case(case_id: str, db_path: str = DEFAULT_DB_PATH) -> CanonicalCase:
    events = get_timeline(case_id, db_path=db_path, reverse=False)
    return CanonicalCase(case_id=case_id, events=events)


def get_event_by_id(artifact_id: str, db_path: str = DEFAULT_DB_PATH) -> Optional[CanonicalEvent]:
    query = """
        SELECT artifact_id, timestamp, event_type, actor, object,
               command, src_ip, dst_ip, raw, source, session_id
        FROM events
        WHERE artifact_id = ?
    """
    with get_connection(db_path) as conn:
        cursor = conn.execute(query, (artifact_id,))
        row = cursor.fetchone()
        if row:
            return CanonicalEvent.from_dict(dict(row))
    return None


def get_cases(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    init_db(db_path)
    query = """
        SELECT c.case_id, c.created_at, c.description, COUNT(e.artifact_id) as event_count
        FROM cases c
        LEFT JOIN events e ON c.case_id = e.case_id
        GROUP BY c.case_id, c.created_at, c.description
        ORDER BY c.created_at DESC
    """
    with get_connection(db_path) as conn:
        cursor = conn.execute(query)
        return [dict(r) for r in cursor.fetchall()]
