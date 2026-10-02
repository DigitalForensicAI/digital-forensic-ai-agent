"""
Export the structured report (see src/report/build.py) to a PDF document.

Uses reportlab/platypus (pure Python, no external binary like wkhtmltopdf or
pandoc required) so this runs anywhere the rest of the project does.
"""
import json
import os
import sys

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, ListFlowable, ListItem,
)

from src.report.build import build_report

GROUNDED = colors.HexColor("#1A7F37")
UNGROUNDED = colors.HexColor("#B3261E")


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("H1", parent=styles["Heading1"], spaceBefore=14, spaceAfter=6))
    styles.add(ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=10, spaceAfter=4))
    styles.add(ParagraphStyle("Body", parent=styles["BodyText"], spaceAfter=6, leading=13))
    styles.add(ParagraphStyle("Small", parent=styles["BodyText"], fontSize=7.5, leading=9))
    styles.add(ParagraphStyle("SmallHdr", parent=styles["BodyText"], fontSize=7.5, leading=9,
                               textColor=colors.white, fontName="Helvetica-Bold"))
    return styles


def _cell(text, style):
    text = "-" if text in (None, "") else str(text)
    return Paragraph(text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), style)


def _wrapped_table(headers, rows, col_widths, styles):
    header_row = [_cell(h, styles["SmallHdr"]) for h in headers]
    data = [header_row] + [[_cell(c, styles["Small"]) for c in row] for row in rows]
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
    ]))
    return t


def export_pdf(report, out_path="output/report.pdf", graph_path=None):
    graph_path = graph_path or report.get("graph_path", "graph.png")
    styles = _styles()
    story = []

    story.append(Paragraph("Digital Forensic Investigation Report", styles["Title"]))
    story.append(Paragraph(
        f"<b>Case:</b> {report.get('case_id', 'unknown')} &nbsp;&nbsp; "
        f"<b>Generated:</b> {report.get('generated_at', '')}", styles["Body"]))
    story.append(Spacer(1, 10))

    # --- 1. Executive summary ------------------------------------------------
    story.append(Paragraph("1. Executive Summary", styles["H1"]))
    story.append(Paragraph(report.get("executive_summary", "No summary produced."), styles["Body"]))

    # --- 2. Timeline -----------------------------------------------------------
    story.append(Paragraph("2. Timeline", styles["H1"]))
    timeline = report.get("timeline", [])
    if timeline:
        rows = [
            [t["timestamp"], t["artifact_id"], "SUSPICIOUS" if t["suspicious"] else "",
             t["actor"], t["event_type"], t["object"], t["command"], t["dst_ip"],
             "; ".join(t["techniques"])]
            for t in timeline
        ]
        widths = [0.85, 0.5, 0.55, 0.6, 0.7, 0.75, 1.0, 0.65, 0.9]
        widths = [w * inch for w in widths]
        story.append(_wrapped_table(
            ["Time", "Artifact", "Flag", "Actor", "Event Type", "Object", "Command", "Dst IP", "MITRE"],
            rows, widths, styles,
        ))
    else:
        story.append(Paragraph("No events available.", styles["Body"]))

    # --- 3. Techniques detected -------------------------------------------------
    story.append(Paragraph("3. Techniques Detected", styles["H1"]))
    techs = report.get("techniques_detected", [])
    if techs:
        rows = [
            [t["technique_id"], t["technique_name"], t["count"], ", ".join(t["artifact_ids"])]
            for t in techs
        ]
        widths = [1.0 * inch, 2.3 * inch, 0.8 * inch, 2.3 * inch]
        story.append(_wrapped_table(["Technique ID", "Technique Name", "Count", "Artifact IDs"],
                                     rows, widths, styles))
    else:
        story.append(Paragraph("No MITRE ATT&CK techniques were matched against this event set.", styles["Body"]))

    # --- 4. Attack narrative -----------------------------------------------------
    story.append(Paragraph("4. Attack Narrative (Evidence-Grounded)", styles["H1"]))
    if graph_path and os.path.exists(graph_path):
        try:
            story.append(Image(graph_path, width=6 * inch, height=3.8 * inch))
            story.append(Spacer(1, 8))
        except Exception:
            pass

    for s in report.get("narrative", []):
        mark_color = "#1A7F37" if s["grounded"] else "#B3261E"
        mark = "OK" if s["grounded"] else "UNSUPPORTED"
        story.append(Paragraph(
            f"{s['stage']} &nbsp; <font color='{mark_color}'><b>[{mark}]</b></font>", styles["H2"]))
        story.append(Paragraph(s["claim"], styles["Body"]))
        ids = ", ".join(s["artifact_ids"]) or "none"
        story.append(Paragraph(f"<b>Evidence:</b> {ids}", styles["Body"]))
        story.append(Paragraph(f"<b>Confidence (model-reported):</b> {s['confidence']}", styles["Body"]))
        if s["missing_ids"]:
            story.append(Paragraph(
                f"<font color='#B3261E'><b>WARNING:</b> cited non-existent evidence: "
                f"{', '.join(s['missing_ids'])}</font>", styles["Body"]))

    if report.get("unsupported_claims"):
        story.append(Paragraph("Flagged unsupported claims", styles["H2"]))
        story.append(Paragraph("The following claims were NOT backed by real evidence and should not be trusted:",
                                styles["Body"]))
        items = [ListItem(Paragraph(c, styles["Body"])) for c in report["unsupported_claims"]]
        story.append(ListFlowable(items, bulletType="bullet"))

    # --- 5. Grounding score -------------------------------------------------------
    story.append(Paragraph("5. Grounding Score", styles["H1"]))
    g = report.get("grounding", {})
    story.append(Paragraph(
        f"<b>{g.get('score', 0)}</b> ({g.get('grounded_claims', 0)}/{g.get('total_claims', 0)} "
        f"claims backed by cited evidence)", styles["Body"]))

    # --- 6. Evidence appendix ------------------------------------------------------
    story.append(Paragraph("6. Evidence Appendix", styles["H1"]))
    appendix = report.get("evidence_appendix", [])
    if appendix:
        rows = [
            [a["artifact_id"], a["timestamp"], a["source"], a["actor"], a["event_type"],
             a["object"], a["command"], a["src_ip"], a["dst_ip"]]
            for a in appendix
        ]
        widths = [0.6, 0.85, 0.6, 0.55, 0.75, 0.85, 1.3, 0.55, 0.55]
        widths = [w * inch for w in widths]
        story.append(_wrapped_table(
            ["Artifact", "Time", "Source", "Actor", "Event Type", "Object", "Command", "Src IP", "Dst IP"],
            rows, widths, styles,
        ))
    else:
        story.append(Paragraph("No events recorded.", styles["Body"]))

    # --- Limitations -----------------------------------------------------------------
    story.append(Paragraph("Limitations", styles["H1"]))
    story.append(Paragraph(report.get("limitations", "None stated."), styles["Body"]))

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    doc = SimpleDocTemplate(out_path, pagesize=LETTER,
                             leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                             topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    doc.build(story)
    return out_path


def run(verified_path, correlations_path, out_path="output/report.pdf"):
    with open(verified_path) as f:
        verified = json.load(f)
    with open(correlations_path) as f:
        corr = json.load(f)
    report = build_report(verified, corr.get("events", []))
    return export_pdf(report, out_path=out_path)


if __name__ == "__main__":
    verified_path = sys.argv[1] if len(sys.argv) > 1 else "output/verified.json"
    correlations_path = sys.argv[2] if len(sys.argv) > 2 else "data/samples/correlations.json"
    out = run(verified_path, correlations_path)
    print(f"--- saved {out} ---")