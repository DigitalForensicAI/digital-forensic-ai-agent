"""
Tests for P2 (Parser, Canonical Events, SQLite DB, Timeline)
and P3 (MITRE ATT&CK Mapping and IOC Detection).
"""

import os
import json
import sqlite3
import tempfile
import unittest

from src.parser.canonical import CanonicalEvent, CanonicalCase, normalize_timestamp
from src.parser.db import init_db, insert_events, get_timeline, get_cases, get_event_by_id
from src.parser.parse import parse_csv_log, process_logs
from src.detect.detect import evaluate_mitre, evaluate_iocs, correlate_events, load_rules, correlate_from_file


class TestP2(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_forensics.db")
        self.csv_path = "data/samples/raw_logs.csv"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_canonical_event_normalization(self):
        ev = CanonicalEvent(
            artifact_id="evt_01",
            timestamp="2024-01-15 09:30:00",
            event_type="PROCESS_CREATION",
            actor=" admin ",
            object="powershell.exe",
        )
        self.assertEqual(ev.event_type, "process_creation")
        self.assertEqual(ev.actor, "admin")
        self.assertTrue(ev.timestamp.endswith("Z"))

    def test_parse_sample_csv(self):
        events = parse_csv_log(self.csv_path)
        self.assertEqual(len(events), 6)
        self.assertEqual(events[0].artifact_id, "evt_00001")
        self.assertEqual(events[0].object, "powershell.exe")
        self.assertEqual(events[1].src_ip, "10.0.0.5")
        self.assertEqual(events[1].dst_ip, "185.23.44.9")

    def test_db_insert_and_timeline_query(self):
        events = parse_csv_log(self.csv_path)
        inserted = insert_events("incident_test", events, db_path=self.db_path)
        self.assertEqual(inserted, 6)

        cases = get_cases(db_path=self.db_path)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["case_id"], "incident_test")
        self.assertEqual(cases[0]["event_count"], 6)

        # Verify sorted timeline
        timeline = get_timeline("incident_test", db_path=self.db_path)
        self.assertEqual(len(timeline), 6)
        timestamps = [e.timestamp for e in timeline]
        self.assertEqual(timestamps, sorted(timestamps))

        # Test single event lookup
        evt1 = get_event_by_id("evt_00001", db_path=self.db_path)
        self.assertIsNotNone(evt1)
        self.assertEqual(evt1.object, "powershell.exe")


class TestP3(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules()
        self.canonical_fixture = "data/samples/canonical_events.json"

    def test_rules_catalogue_size(self):
        techniques = self.rules.get("techniques", [])
        self.assertGreaterEqual(len(techniques), 15, "Expected at least 15 MITRE techniques")

    def test_mitre_mapping_on_fixture(self):
        result = correlate_from_file(self.canonical_fixture)
        self.assertEqual(result["case_id"], "incident_01")
        events = result["events"]
        self.assertEqual(len(events), 6)

        # Event 1: PowerShell
        ev1_tech_ids = [t["technique_id"] for t in events[0]["mitre"]]
        self.assertIn("T1059.001", ev1_tech_ids)

        # Event 2: Exfiltration over C2 & IOC
        ev2_tech_ids = [t["technique_id"] for t in events[1]["mitre"]]
        self.assertIn("T1041", ev2_tech_ids)
        self.assertIn("185.23.44.9", events[1]["ioc"])

        # Event 3: File write (no technique)
        self.assertEqual(len(events[2]["mitre"]), 0)

        # Event 4: Registry Run Keys
        ev4_tech_ids = [t["technique_id"] for t in events[3]["mitre"]]
        self.assertIn("T1547.001", ev4_tech_ids)

        # Event 5: Cmd & Whoami
        ev5_tech_ids = [t["technique_id"] for t in events[4]["mitre"]]
        self.assertIn("T1059.003", ev5_tech_ids)
        self.assertIn("T1033", ev5_tech_ids)

        # Event 6: Exfiltration over C2 & IOC
        ev6_tech_ids = [t["technique_id"] for t in events[5]["mitre"]]
        self.assertIn("T1041", ev6_tech_ids)
        self.assertIn("185.23.44.9", events[5]["ioc"])


if __name__ == "__main__":
    unittest.main()
