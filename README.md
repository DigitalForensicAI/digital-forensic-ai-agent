# Digital Forensic AI Agent

Autonomous AI Agent for Digital Forensic Ingestion, Incident Reconstruction, and Provenance Graph Analysis.

## Architecture & Pipeline

```
Raw Logs (CSV) ──> Parser & SQLite (P2) ──> MITRE & IOC Detection (P3) ──> Provenance Graph & AI Reasoning (P1)
```

1. **Ingestion & Canonical Storage**: Normalizes raw forensic logs into canonical event representations and persists them in SQLite for timeline analysis.
2. **Detection & Correlation**: Maps canonical events against MITRE ATT&CK techniques and correlates known Indicators of Compromise (IOCs).
3. **Provenance Graph Generation**: Builds a deterministic directed graph tracing attack vectors across users, processes, files, and network nodes.
4. **AI Reasoning Agent**: Synthesizes evidence, timeline, and provenance edges into grounded investigation findings citing artifact IDs.

---

## Project Structure

```
digital-forensic-ai-agent/
├── data/
│   └── samples/
│       ├── raw_logs.csv             # Sample raw security log events
│       ├── canonical_events.json    # Canonical parsed events fixture
│       └── correlations.json        # MITRE and IOC correlated events fixture
├── src/
│   ├── parser/
│   │   ├── canonical.py             # Event data models and normalization
│   │   ├── db.py                    # SQLite database interface and timeline queries
│   │   ├── parse.py                 # CSV log parser and CLI runner
│   │   └── schema.sql               # Database schema and indexes
│   ├── detect/
│   │   ├── detect.py                # MITRE technique and IOC correlation engine
│   │   └── mitre_map.json           # MITRE ATT&CK techniques and IOC rules
│   ├── graph/
│   │   └── provenance.py            # NetworkX provenance graph generator
│   └── ai/
│       ├── llm/
│       │   ├── base.py              # LLM provider interface
│       │   ├── ollama_provider.py   # Local Ollama runner
│       │   └── api_provider.py      # Cloud API provider stub
│       └── reason.py                # AI incident reconstruction
├── tests/
│   └── test_pipeline.py             # Unit test suite
├── output/                          # Generated databases, JSONs, and graphs
└── requirements.txt
```

---

## Quick Start & Verification

### 1. Run Unit Tests
```bash
python3 -m unittest tests/test_pipeline.py
```

### 2. Parse Raw Logs into SQLite and Canonical Events
```bash
python3 -m src.parser.parse data/samples/raw_logs.csv --case-id incident_01 --db output/forensics.db --out output/canonical_events.json
```

### 3. Run Detection & MITRE ATT&CK Correlation
```bash
python3 -m src.detect.detect output/canonical_events.json --out output/correlations.json
```

### 4. Build Provenance Graph
```bash
python3 -m src.graph.provenance output/correlations.json
```
The graph visualization will be exported to `output/graph.png`.

### 5. Run AI Forensic Investigation (Requires Ollama)
```bash
python3 -m src.ai.reason output/correlations.json
```
The investigation findings will be saved to `output/investigation.json`.