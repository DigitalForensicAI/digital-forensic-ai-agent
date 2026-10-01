"""
Unit tests for Dev's Evaluation and Metrics module (Review 2).
"""

import unittest
from src.evaluation.metrics import (
    compute_grounding_metrics,
    compute_mitre_metrics,
    compute_adversarial_metrics,
)


class TestEvaluationMetrics(unittest.TestCase):
    def test_grounding_metrics_perfect(self):
        sample_verified = {
            "case_id": "test_case",
            "stages": [
                {
                    "stage": "Execution",
                    "claim": "Executed PowerShell",
                    "artifact_ids": ["evt_1"],
                    "status": "grounded",
                    "missing_ids": [],
                },
                {
                    "stage": "Persistence",
                    "claim": "Run key added",
                    "artifact_ids": ["evt_2"],
                    "status": "grounded",
                    "missing_ids": [],
                },
            ],
        }
        res = compute_grounding_metrics(sample_verified)
        self.assertEqual(res["total_claims"], 2)
        self.assertEqual(res["grounded_claims"], 2)
        self.assertEqual(res["unsupported_claims"], 0)
        self.assertEqual(res["grounding_score"], 1.0)
        self.assertEqual(res["citation_validity_rate"], 1.0)
        self.assertEqual(len(res["flagged_claims"]), 0)

    def test_grounding_metrics_with_hallucinations(self):
        sample_verified = {
            "case_id": "test_case",
            "stages": [
                {
                    "stage": "Execution",
                    "claim": "Executed PowerShell",
                    "artifact_ids": ["evt_1"],
                    "status": "grounded",
                    "missing_ids": [],
                },
                {
                    "stage": "Exfiltration",
                    "claim": "Fabricated ransomware exfiltration",
                    "artifact_ids": ["evt_99"],
                    "status": "unsupported",
                    "missing_ids": ["evt_99"],
                },
                {
                    "stage": "Discovery",
                    "claim": "Partial discovery",
                    "artifact_ids": ["evt_2"],
                    "status": "weak",
                    "missing_ids": [],
                },
            ],
        }
        res = compute_grounding_metrics(sample_verified)
        self.assertEqual(res["total_claims"], 3)
        self.assertEqual(res["grounded_claims"], 1)
        self.assertEqual(res["weak_claims"], 1)
        self.assertEqual(res["unsupported_claims"], 1)
        self.assertAlmostEqual(res["grounding_score"], 0.333, places=2)
        self.assertEqual(len(res["flagged_claims"]), 2)
        self.assertAlmostEqual(res["citation_validity_rate"], 0.667, places=2)

    def test_mitre_metrics_calculation(self):
        detected = ["T1059.001", "T1041", "T1082"]  # 1082 is FP
        expected = ["T1059.001", "T1041", "T1547.001"]  # 1547.001 is FN

        res = compute_mitre_metrics(detected, expected)
        self.assertEqual(res["true_positives"], 2)
        self.assertEqual(res["false_positives"], 1)
        self.assertEqual(res["false_negatives"], 1)
        # Precision = 2 / (2 + 1) = 0.667
        self.assertAlmostEqual(res["precision"], 0.667, places=2)
        # Recall = 2 / (2 + 1) = 0.667
        self.assertAlmostEqual(res["recall"], 0.667, places=2)
        self.assertAlmostEqual(res["f1_score"], 0.667, places=2)

    def test_adversarial_metrics_summary(self):
        mock_cases = [
            {
                "case": "case1.json",
                "plain_model_invented": True,
                "grounded_score": 0.0,
                "grounded_flagged_claims": ["Ransomware claim"],
                "grounded_caught_something": True,
            },
            {
                "case": "case2.json",
                "plain_model_invented": True,
                "grounded_score": 0.5,
                "grounded_flagged_claims": ["False persistence"],
                "grounded_caught_something": True,
            },
        ]
        res = compute_adversarial_metrics(mock_cases)
        self.assertEqual(res["total_cases"], 2)
        self.assertEqual(res["verifier_catch_count"], 2)
        self.assertEqual(res["verifier_catch_rate"], 1.0)
        self.assertEqual(res["mean_grounded_score"], 0.25)


if __name__ == "__main__":
    unittest.main()
