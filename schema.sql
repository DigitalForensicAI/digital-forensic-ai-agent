CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    created_at TEXT DEFAULT (datetime('now', 'utc')),
    description TEXT
);

CREATE TABLE IF NOT EXISTS events (
    artifact_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT DEFAULT '',
    object TEXT DEFAULT '',
    command TEXT DEFAULT '',
    src_ip TEXT DEFAULT '',
    dst_ip TEXT DEFAULT '',
    raw TEXT DEFAULT '',
    source TEXT DEFAULT '',
    session_id TEXT DEFAULT '',
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_case_timestamp ON events(case_id, timestamp ASC);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor);
