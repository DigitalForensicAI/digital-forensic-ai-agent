"""
test_parameter_verifier.py

Automated tests for the Parameter / Factual Consistency Verifier (B3 Overclaim fix).
Covers TEST 1 through TEST 8 specified in requirements:
  TEST 1 - Valid claim (GROUNDED)
  TEST 2 - Fabricated artifact (UNSUPPORTED)
  TEST 3 - Mismatched evidence (MISMATCHED)
  TEST 4 - B3 overclaim / scope inflation (NOT GROUNDED, identifies unsupported scope/quantity)
  TEST 5 - Supported quantity (GROUNDED)
  TEST 6 - Unsupported data volume (NOT GROUNDED)
  TEST 7 - Supported IP (parameter check passes)
  TEST 8 - Wrong IP (NOT GROUNDED)
"""

import unittest
from src.ai.parameter_verifier import check_parameter_consistency
from src.verifier import verify_claim, load_event_index


class TestParameterVerifier(unittest.TestCase):

    def test_1_valid_claim(self):
        """TEST 1: Valid claim with matching IP, port, and protocol."""
        event = {
            "artifact_id": "evt_001",
            "event_type": "network_connection",
            "dst_ip": "203.0.113.55",
            "port": "443",
            "command": "",
            "object": "",
            "raw": "Connection to 203.0.113.55 over HTTPS port 443.",
            "technique_name": "Web Protocols",
        }
        event_index = {"evt_001": event}
        claim = {
            "text": "An HTTPS connection was made to 203.0.113.55 on port 443.",
            "cited_artifact_ids": ["evt_001"],
            "technique_id": None,
        }
        result = verify_claim(claim, event_index)
        self.assertEqual(result["verdict"], "GROUNDED")
        self.assertEqual(result["grounding"], 1.0)
        self.assertTrue(result["artifact_exists"])
        self.assertTrue(result["parameter_check"]["passed"])
        self.assertEqual(len(result["parameter_check"]["unsupported_parameters"]), 0)

    def test_2_fabricated_artifact(self):
        """TEST 2: Claim cites evt_999 which does not exist."""
        event_index = {
            "evt_001": {
                "artifact_id": "evt_001",
                "raw": "Valid event.",
            }
        }
        claim = {
            "text": "Attacker performed exfiltration to external server.",
            "cited_artifact_ids": ["evt_999"],
            "technique_id": None,
        }
        result = verify_claim(claim, event_index)
        self.assertEqual(result["verdict"], "UNSUPPORTED")
        self.assertEqual(result["grounding"], 0.0)
        self.assertFalse(result["artifact_exists"])
        self.assertFalse(result["parameter_check"]["passed"])

    def test_3_mismatched_evidence(self):
        """TEST 3: Evidence describes downloading m.exe, claim asserts ransomware encryption."""
        event = {
            "artifact_id": "evt_002",
            "event_type": "file_write",
            "object": "C:\\Temp\\m.exe",
            "command": "",
            "raw": "FileCreate C:\\Temp\\m.exe Ingress Tool Transfer",
            "technique_name": "Ingress Tool Transfer",
            "technique_id": "T1105",
        }
        event_index = {"evt_002": event}
        claim = {
            "text": "Ransomware encrypted the workstation.",
            "cited_artifact_ids": ["evt_002"],
            "technique_id": "T1486",
        }
        result = verify_claim(claim, event_index)
        self.assertNotEqual(result["verdict"], "GROUNDED")
        self.assertEqual(result["grounding"], 0.0)
        self.assertEqual(result["verdict"], "MISMATCHED")

    def test_4_b3_overclaim_scope_inflation(self):
        """
        TEST 4: B3 overclaim.
        Evidence: 'One connection to 203.0.113.55 over HTTPS.'
        Claim: '500 confidential files were exfiltrated to 203.0.113.55.'
        Expected: NOT GROUNDED; specifically identifies '500 files' and 'confidential'.
        """
        event = {
            "artifact_id": "evt_013",
            "event_type": "network_connection",
            "dst_ip": "203.0.113.55",
            "raw": "One connection to 203.0.113.55 over HTTPS.",
            "technique_name": "Exfiltration Over C2 Channel",
            "technique_id": "T1041",
        }
        event_index = {"evt_013": event}
        claim = {
            "text": "500 confidential files were exfiltrated to 203.0.113.55.",
            "cited_artifact_ids": ["evt_013"],
            "technique_id": "T1041",
        }
        result = verify_claim(claim, event_index)
        self.assertNotEqual(result["verdict"], "GROUNDED")
        self.assertEqual(result["grounding"], 0.0)
        self.assertTrue(result["artifact_exists"])
        self.assertFalse(result["parameter_check"]["passed"])

        unsupported = result["parameter_check"]["unsupported_parameters"]
        # Specifically identify unsupported scope / quantity
        self.assertTrue(any("500 files" in u for u in unsupported), f"Expected '500 files' in {unsupported}")
        self.assertTrue(any("confidential" in u for u in unsupported), f"Expected 'confidential' in {unsupported}")

    def test_5_supported_quantity(self):
        """
        TEST 5: Supported quantity.
        Evidence explicitly states: '500 files were transferred.'
        Claim: '500 files were exfiltrated.'
        Expected: GROUNDED.
        """
        event = {
            "artifact_id": "evt_020",
            "event_type": "network_transfer",
            "raw": "500 files were transferred to remote host.",
            "technique_name": "Exfiltration Over C2 Channel",
            "technique_id": "T1041",
        }
        event_index = {"evt_020": event}
        claim = {
            "text": "500 files were exfiltrated.",
            "cited_artifact_ids": ["evt_020"],
            "technique_id": "T1041",
        }
        result = verify_claim(claim, event_index)
        self.assertEqual(result["verdict"], "GROUNDED")
        self.assertEqual(result["grounding"], 1.0)
        self.assertTrue(result["parameter_check"]["passed"])

    def test_6_unsupported_data_volume(self):
        """
        TEST 6: Unsupported data volume.
        Evidence: '1024 bytes transferred.'
        Claim: '2 GB of data was exfiltrated.'
        Expected: NOT GROUNDED.
        """
        event = {
            "artifact_id": "evt_021",
            "event_type": "network_transfer",
            "raw": "1024 bytes transferred.",
            "technique_name": "Exfiltration",
            "technique_id": "T1041",
        }
        event_index = {"evt_021": event}
        claim = {
            "text": "2 GB of data was exfiltrated.",
            "cited_artifact_ids": ["evt_021"],
            "technique_id": "T1041",
        }
        result = verify_claim(claim, event_index)
        self.assertNotEqual(result["verdict"], "GROUNDED")
        self.assertEqual(result["grounding"], 0.0)
        self.assertFalse(result["parameter_check"]["passed"])
        unsupported = result["parameter_check"]["unsupported_parameters"]
        self.assertTrue(any("2 gb" in u.lower() for u in unsupported))

    def test_7_supported_ip(self):
        """
        TEST 7: Supported IP.
        Evidence contains 203.0.113.55, Claim contains 203.0.113.55.
        Expected: Parameter check passes.
        """
        evidence_text = "Connection observed to 203.0.113.55 on port 443."
        claim_text = "Traffic was sent to 203.0.113.55."
        res = check_parameter_consistency(claim_text, evidence_text)
        self.assertTrue(res["passed"])
        self.assertTrue(any("203.0.113.55" in s for s in res["supported_parameters"]))

    def test_8_wrong_ip(self):
        """
        TEST 8: Wrong IP.
        Evidence contains 203.0.113.55, Claim says 198.51.100.10.
        Expected: NOT GROUNDED.
        """
        event = {
            "artifact_id": "evt_022",
            "dst_ip": "203.0.113.55",
            "raw": "Connection to 203.0.113.55 established.",
            "technique_name": "Web Protocols",
        }
        event_index = {"evt_022": event}
        claim = {
            "text": "Connection was made to 198.51.100.10.",
            "cited_artifact_ids": ["evt_022"],
            "technique_id": None,
        }
        result = verify_claim(claim, event_index)
        self.assertNotEqual(result["verdict"], "GROUNDED")
        self.assertEqual(result["grounding"], 0.0)
        self.assertFalse(result["parameter_check"]["passed"])
        unsupported = result["parameter_check"]["unsupported_parameters"]
        self.assertTrue(any("198.51.100.10" in u for u in unsupported))


if __name__ == "__main__":
    unittest.main()
