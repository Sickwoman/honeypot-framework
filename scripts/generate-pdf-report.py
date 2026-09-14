#!/usr/bin/env python3

################################################################################
# PDF Report Generator
# Renders recent honeypot activity as a PDF via reportlab.
#
# The Elasticsearch aggregations live in honeypot_stats.py, shared with
# generate-reports.py and generate-analytics-report.py.
################################################################################

import argparse
import sys
from datetime import datetime
from typing import Any, Dict, List
from xml.sax.saxutils import escape

from honeypot_stats import HoneypotStats
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ACCENT = colors.HexColor("#23303a")

TABLE_STYLE = TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, 0), 10),
    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
    ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
])


class PDFReportGenerator:
    def __init__(self, stats: HoneypotStats = None):
        self.stats = stats or HoneypotStats()
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            "CustomTitle", parent=self.styles["Heading1"],
            fontSize=22, textColor=ACCENT, spaceAfter=26, alignment=TA_CENTER,
        )
        self.heading_style = ParagraphStyle(
            "CustomHeading", parent=self.styles["Heading2"],
            fontSize=13, textColor=ACCENT, spaceAfter=10, spaceBefore=10,
        )

    def _table(self, rows: List[List[str]], widths, empty: str):
        """A styled table, or an italic note when there is nothing to show.

        Cells carry attacker-chosen strings (source IPs, service names), and
        reportlab's Paragraph/Table markup would otherwise interpret `<` and
        `&` as markup, so everything is escaped on the way in.
        """
        if len(rows) <= 1:
            return Paragraph(f"<i>{escape(empty)}</i>", self.styles["Normal"])
        safe = [[escape(str(cell)) for cell in row] for row in rows]
        table = Table(safe, colWidths=widths)
        table.setStyle(TABLE_STYLE)
        return table

    def build(self, data: Dict[str, Any], days: int) -> List[Any]:
        story: List[Any] = [Spacer(1, 1.4 * inch), Paragraph("Honeypot security report", self.title_style)]

        story.append(Paragraph(
            f"<b>Generated:</b> {datetime.now():%Y-%m-%d %H:%M:%S}<br/>"
            f"<b>Period:</b> last {days} day(s)",
            self.styles["Normal"],
        ))
        story.append(PageBreak())

        story.append(Paragraph("Executive summary", self.heading_style))
        story.append(Paragraph(
            f"Over the last {days} day(s) the honeypots recorded "
            f"<b>{data['total_events']:,}</b> events from "
            f"<b>{data['unique_source_ips']}</b> source addresses, across "
            f"<b>{len(data['services'])}</b> services. "
            f"<b>{data['credentials_captured']:,}</b> credential submissions and "
            f"<b>{data['failed_logins']:,}</b> failed logins were captured.",
            self.styles["Normal"],
        ))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Key statistics", self.heading_style))
        story.append(self._table([
            ["Metric", "Value"],
            ["Total events", f"{data['total_events']:,}"],
            ["Source addresses", str(data["unique_source_ips"])],
            ["Credentials captured", f"{data['credentials_captured']:,}"],
            ["Failed logins", f"{data['failed_logins']:,}"],
            ["Services targeted", str(len(data["services"]))],
            ["Top source country", data["top_country"]],
        ], [3 * inch, 2 * inch], "No data"))
        story.append(Spacer(1, 0.25 * inch))

        story.append(Paragraph("Top source addresses", self.heading_style))
        story.append(self._table(
            [["Rank", "IP address", "Events"]] +
            [[str(i), entry["ip"], f"{entry['count']:,}"] for i, entry in enumerate(data["top_ips"], 1)],
            [0.8 * inch, 2.7 * inch, 1.5 * inch],
            "No source addresses recorded in this period.",
        ))
        story.append(Spacer(1, 0.25 * inch))

        story.append(Paragraph("Targeted services", self.heading_style))
        story.append(self._table(
            [["Service", "Events", "Share"]] +
            [[entry["name"], f"{entry['count']:,}", f"{entry['percentage']}%"]
             for entry in data["service_breakdown"][:10]],
            [2.2 * inch, 1.4 * inch, 1.4 * inch],
            "No service activity recorded in this period.",
        ))
        story.append(Spacer(1, 0.25 * inch))

        story.append(Paragraph("Recommendations", self.heading_style))
        for text in [
            "Review the top source addresses and consider network-level filtering.",
            "Confirm the response playbooks fired for any HIGH or CRITICAL alerts.",
            "Check whether newly targeted services indicate a change in attacker interest.",
            "Verify threat-intelligence enrichment is reaching the alert pipeline.",
            "Archive logs older than the retention window.",
        ]:
            story.append(Paragraph(f"• {escape(text)}", self.styles["Normal"]))
            story.append(Spacer(1, 0.08 * inch))

        return story

    def generate_pdf(self, filename: str, days: int = 1) -> None:
        data = self.stats.summary(f"{days}d")
        SimpleDocTemplate(filename, pagesize=letter).build(self.build(data, days))
        print(f"✓ Wrote {filename}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a PDF honeypot report")
    parser.add_argument("--output", default="honeypot-report.pdf", help="Output filename")
    parser.add_argument("--days", type=int, default=1, help="How many days back to analyse")
    args = parser.parse_args()

    PDFReportGenerator().generate_pdf(args.output, args.days)
    return 0


if __name__ == "__main__":
    sys.exit(main())
