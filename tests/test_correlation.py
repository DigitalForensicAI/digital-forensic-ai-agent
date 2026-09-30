import json
import os
import tempfile
import unittest
from pathlib import Path

from src.detect.detect import (
    is_external_ip,
    load_rules,
    evaluate_mitre,
    evaluate_iocs,
    correlate_event,
    correlate_events,
    correlate_from_file,
)


class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules()

    def test_is_external_ip(self):
        self.assertFalse(is_external_ip("127.0.0.1"))
        self.assertFalse(is_external_ip("10.0.0.5"))
        self.assertFalse(is_external_ip("192.168.1.1"))
        self.assertFalse(is_external_ip("172.16.0.1"))
        self.assertTrue(is_external_ip("185.23.44.9"))
        self.assertTrue(is_external_ip("203.0.113.55:443"))

    def test_benign_event_contract(self):
        benign_event = {
            "artifact_id": "evt_00099",
            "timestamp": "2020-05-01T18:00:00Z",
            "event_type": "process_creation",
            "actor": "user",
            "object": "notepad.exe",
            "command": "notepad.exe file.txt",
            "src_ip": "10.0.0.5",
            "dst_ip": "",
            "raw": "",
        }
        res = correlate_event(benign_event, self.rules)
        self.assertEqual(res["artifact_id"], "evt_00099")
        self.assertFalse(res["suspicious"])
        self.assertEqual(res["technique_id"], "")
        self.assertEqual(res["technique_name"], "")
        self.assertEqual(res["confidence"], 0.0)

    def test_mimikatz_detection(self):
        ev = {
            "artifact_id": "evt_00003",
            "timestamp": "2020-05-01T18:32:15Z",
            "event_type": "ProcessCreate",
            "actor": "m.exe",
            "object": "",
            "command": "m.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"",
            "src_ip": "10.1.2.50",
            "dst_ip": "",
            "raw": "",
        }
        res = correlate_event(ev, self.rules)
        self.assertTrue(res["suspicious"])
        self.assertEqual(res["technique_id"], "T1003.001")
        self.assertGreaterEqual(res["confidence"], 0.9)

    def test_dcsync_detection(self):
        ev = {
            "artifact_id": "evt_00008",
            "timestamp": "2020-05-01T18:32:48Z",
            "event_type": "DirectoryReplicationRequest",
            "actor": "lsass.exe",
            "object": "DRSGetNCChanges",
            "command": "",
            "src_ip": "",
            "dst_ip": "",
            "raw": "",
        }
        res = correlate_event(ev, self.rules)
        self.assertTrue(res["suspicious"])
        self.assertEqual(res["technique_id"], "T1003.006")

    def test_ioc_matching(self):
        ev = {
            "artifact_id": "evt_00012",
            "timestamp": "2020-05-01T18:34:02Z",
            "event_type": "NetworkConnect",
            "actor": "powershell.exe",
            "object": "203.0.113.55:443",
            "command": "",
            "src_ip": "10.1.2.50",
            "dst_ip": "203.0.113.55",
            "raw": "",
        }
        res = correlate_event(ev, self.rules)
        self.assertTrue(res["suspicious"])
        self.assertIn("203.0.113.55", res["ioc"])
        self.assertIn("T1041", [m["technique_id"] for m in res["mitre"]])


if __name__ == "__main__":
    unittest.main()
