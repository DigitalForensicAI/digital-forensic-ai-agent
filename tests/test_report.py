"""


Covers: build_report() section structure, the markdown renderer, and both
the DOCX and PDF exporters, run against the existing sample correlations.json
fixture (verify.py's fallback/offline reconstruction, so no LLM is required).
"""
import os
import tempfile
import unittest

from src.graph.provenance import load_events
from src.ai.reason import reconstruct
from src.ai.verify import verify
from src.report.build import build_report
from src.report.render import render
from src.report.export_docx import export_docx
from src.report.export_pdf import export_pdf


class TestReportBuild(unittest.TestCase):
    def setUp(self):
        self.path = "data/samples/correlations.json"
        self.case_id, self.events = load_events(self.path)
        investigation = reconstruct(self.path, offline=True)
        self.verified = verify(investigation, self.events)
        self.report = build_report(self.verified, self.events, graph_path="output/graph.png")

    def test_top_level_sections_present(self):
        required = {
            "case_id", "generated_at", "executive_summary", "grounding",
            "timeline", "techniques_detected", "narrative",
            "unsupported_claims", "evidence_appendix", "limitations",
        }
        self.assertTrue(required.issubset(self.report.keys()))

    def test_case_id_matches_input(self):
        self.assertEqual(self.report["case_id"], self.case_id)

    def test_timeline_covers_every_event_chronologically(self):
        timeline = self.report["timeline"]
        self.assertEqual(len(timeline), len(self.events))
        timestamps = [t["timestamp"] for t in timeline]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_techniques_detected_rolls_up_mitre_tags(self):
        techs = self.report["techniques_detected"]
        ids = {t["technique_id"] for t in techs}
        # from data/samples/correlations.json
        self.assertIn("T1059.001", ids)
        self.assertIn("T1041", ids)
        t1041 = next(t for t in techs if t["technique_id"] == "T1041")
        self.assertEqual(t1041["count"], 2)
        self.assertIn("evt_00002", t1041["artifact_ids"])
        self.assertIn("evt_00006", t1041["artifact_ids"])

    def test_evidence_appendix_preserves_raw_and_ids(self):
        appendix = self.report["evidence_appendix"]
        self.assertEqual(len(appendix), len(self.events))
        ids = {a["artifact_id"] for a in appendix}
        self.assertEqual(ids, {e["artifact_id"] for e in self.events})
        for a in appendix:
            self.assertTrue(a["raw"])  # nothing from the source is lost

    def test_narrative_flags_missing_citations(self):
        # every narrative entry should carry a grounded flag computed from verify()
        for stage in self.report["narrative"]:
            self.assertIn("grounded", stage)
            self.assertIsInstance(stage["artifact_ids"], list)

    def test_grounding_section_matches_verify_output(self):
        g = self.report["grounding"]
        self.assertEqual(g["score"], self.verified["grounding_score"])
        self.assertEqual(g["grounded_claims"], self.verified["grounded_claims"])
        self.assertEqual(g["total_claims"], self.verified["total_claims"])


class TestReportRenderMarkdown(unittest.TestCase):
    def setUp(self):
        path = "data/samples/correlations.json"
        case_id, events = load_events(path)
        investigation = reconstruct(path, offline=True)
        verified = verify(investigation, events)
        self.report = build_report(verified, events, graph_path="output/graph.png")

    def test_markdown_contains_all_required_sections(self):
        md = render(self.report)
        for heading in [
            "# Digital Forensic Investigation Report",
            "## 1. Executive Summary",
            "## 2. Timeline",
            "## 3. Techniques Detected",
            "## 4. Attack Narrative (Evidence-Grounded)",
            "## 5. Grounding Score",
            "## 6. Evidence Appendix",
            "## Limitations",
        ]:
            self.assertIn(heading, md)

    def test_markdown_cites_every_artifact_id(self):
        md = render(self.report)
        for e in self.report["evidence_appendix"]:
            self.assertIn(e["artifact_id"], md)


class TestReportExporters(unittest.TestCase):
    def setUp(self):
        path = "data/samples/correlations.json"
        case_id, events = load_events(path)
        investigation = reconstruct(path, offline=True)
        verified = verify(investigation, events)
        self.report = build_report(verified, events, graph_path="output/graph.png")
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_docx_export_produces_nonempty_file(self):
        out = os.path.join(self.tmpdir.name, "report.docx")
        export_docx(self.report, out_path=out)
        self.assertTrue(os.path.exists(out))
        self.assertGreater(os.path.getsize(out), 0)

    def test_pdf_export_produces_nonempty_file(self):
        out = os.path.join(self.tmpdir.name, "report.pdf")
        export_pdf(self.report, out_path=out)
        self.assertTrue(os.path.exists(out))
        self.assertGreater(os.path.getsize(out), 0)

    def test_exporters_handle_empty_events_without_crashing(self):
        empty_report = {
            "case_id": "empty_case",
            "generated_at": "n/a",
            "executive_summary": "No events.",
            "grounding": {"score": 0, "grounded_claims": 0, "total_claims": 0},
            "graph_path": "no_such_file.png",
            "timeline": [],
            "techniques_detected": [],
            "narrative": [],
            "unsupported_claims": [],
            "evidence_appendix": [],
            "limitations": "None stated.",
        }
        docx_out = os.path.join(self.tmpdir.name, "empty.docx")
        pdf_out = os.path.join(self.tmpdir.name, "empty.pdf")
        export_docx(empty_report, out_path=docx_out)
        export_pdf(empty_report, out_path=pdf_out)
        self.assertTrue(os.path.exists(docx_out))
        self.assertTrue(os.path.exists(pdf_out))


if __name__ == "__main__":
    unittest.main()