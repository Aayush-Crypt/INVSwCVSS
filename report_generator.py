"""
PDF Report Generator Module
"""

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    PageBreak
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from reportlab.platypus.flowables import HRFlowable

import os
from datetime import datetime


class PDFReportGenerator:

    def __init__(self, filename):
        self.filename = filename
        self.styles = getSampleStyleSheet()

    def generate_report(
        self,
        target,
        open_ports,
        vulnerabilities,
        charts,
        mitigation_data
    ):
        """
        Generate PDF vulnerability assessment report.
        """

        doc = SimpleDocTemplate(
            self.filename,
            pagesize=letter
        )

        elements = []

        title = Paragraph(
            "<b>Intelligent Network Vulnerability Scanner Report</b>",
            self.styles['Title']
        )

        elements.append(title)
        elements.append(Spacer(1, 12))

        scan_info = f"""
        <b>Target:</b> {target}<br/>
        <b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        """

        elements.append(
            Paragraph(scan_info, self.styles['BodyText'])
        )

        elements.append(Spacer(1, 12))
        elements.append(HRFlowable(width="100%"))
        elements.append(Spacer(1, 12))

        # Open ports table
        elements.append(
            Paragraph("<b>Open Ports & Services</b>", self.styles['Heading2'])
        )

        port_data = [["Port", "Service", "Version"]]

        for item in open_ports:
            port_data.append([
                str(item['port']),
                item['service'],
                item['version']
            ])

        port_table = Table(port_data)

        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ]))

        elements.append(port_table)
        elements.append(Spacer(1, 20))

        # Vulnerability table
        elements.append(
            Paragraph(
                "<b>Detected Vulnerabilities</b>",
                self.styles['Heading2']
            )
        )

        vuln_data = [[
            "Port",
            "CVE",
            "CVSS",
            "Severity"
        ]]

        for vuln in vulnerabilities:
            vuln_data.append([
                str(vuln['port']),
                vuln['cve_id'],
                str(vuln['cvss_score']),
                vuln['severity']
            ])

        vuln_table = Table(vuln_data)

        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ]))

        elements.append(vuln_table)
        elements.append(Spacer(1, 20))

        # Charts
        elements.append(
            Paragraph("<b>Visual Analysis</b>", self.styles['Heading2'])
        )

        for chart in charts:
            if chart and os.path.exists(chart):
                elements.append(Image(chart, width=400, height=250))
                elements.append(Spacer(1, 15))

        # Mitigation Suggestions
        elements.append(PageBreak())

        elements.append(
            Paragraph("<b>Mitigation Suggestions</b>", self.styles['Heading2'])
        )

        for item in mitigation_data:

            content = f"""
            <b>Service:</b> {item['service']}<br/>
            <b>Severity:</b> {item['severity']}<br/>
            <b>Suggestions:</b><br/>
            """

            for suggestion in item['suggestions']:
                content += f"• {suggestion}<br/>"

            elements.append(
                Paragraph(content, self.styles['BodyText'])
            )

            elements.append(Spacer(1, 10))

        # Final Summary
        elements.append(Spacer(1, 20))

        summary = """
        <b>Final Risk Summary</b><br/>
        This assessment identifies open ports, vulnerable services,
        and associated CVEs with CVSS-based prioritization.
        Immediate attention is recommended for HIGH and CRITICAL
        vulnerabilities.
        """

        elements.append(
            Paragraph(summary, self.styles['BodyText'])
        )

        doc.build(elements)