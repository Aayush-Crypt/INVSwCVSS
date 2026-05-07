"""
Main Vulnerability Scanner
"""

import nmap
import sys
import os
import json
import logging
import pandas as pd

from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel

from vulnerability_lookup import (
    VulnerabilityLookup,
    mitigation_suggestions
)

from dangerous_ports import get_port_warning
from visualization import Visualization
from report_generator import PDFReportGenerator

# Create required directories
os.makedirs("exports", exist_ok=True)
os.makedirs("reports", exist_ok=True)
os.makedirs("charts", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# Logging setup
logging.basicConfig(
    filename="logs/scanner.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

console = Console()


class IntelligentScanner:

    def __init__(self, target):

        self.target = target

        self.scanner = nmap.PortScanner()

        self.vuln_lookup = VulnerabilityLookup()

        self.open_ports = []
        self.vulnerabilities = []
        self.mitigation_data = []

    def run_scan(self):
        """
        Run Nmap scan.
        """

        console.print(
            Panel.fit(
                f"Starting Scan on: {self.target}",
                style="bold cyan"
            )
        )

        logger.info(f"Scan started on target: {self.target}")

        try:

            with Progress() as progress:

                task = progress.add_task(
                    "[green]Scanning Target...",
                    total=100
                )

                self.scanner.scan(
                    hosts=self.target,
                    arguments="-sS -sV"
                )

                progress.update(task, advance=100)

            for host in self.scanner.all_hosts():

                console.print(
                    f"\n[bold green]Host:[/bold green] {host}"
                )

                console.print(
                    f"[bold blue]State:[/bold blue] "
                    f"{self.scanner[host].state()}"
                )

                for proto in self.scanner[host].all_protocols():

                    ports = self.scanner[host][proto].keys()

                    for port in ports:

                        service_data = self.scanner[host][proto][port]

                        if service_data['state'] == 'open':

                            service_name = service_data.get(
                                'name',
                                'unknown'
                            )

                            version = service_data.get(
                                'version',
                                ''
                            )

                            self.open_ports.append({
                                "port": port,
                                "service": service_name,
                                "version": version
                            })

                            logger.info(
                                f"Open port found: {port} "
                                f"({service_name} {version})"
                            )

                            self.check_vulnerabilities(
                                port,
                                service_name,
                                version
                            )

        except Exception as error:
            console.print(
                f"[red]Scan failed:[/red] {error}"
            )
            logger.error(f"Scan failed: {error}")

    def check_vulnerabilities(
        self,
        port,
        service_name,
        version
    ):
        """
        Fetch vulnerabilities from NVD.
        """

        console.print(
            f"[yellow]Checking vulnerabilities for "
            f"{service_name} {version}[/yellow]"
        )

        vulnerabilities = self.vuln_lookup.search_vulnerabilities(
            service_name,
            version
        )

        for vuln in vulnerabilities:

            vuln_record = {
                "port": port,
                "service": service_name,
                "version": version,
                "cve_id": vuln['cve_id'],
                "cvss_score": vuln['cvss_score'],
                "severity": vuln['severity'],
                "description": vuln['description']
            }

            self.vulnerabilities.append(vuln_record)

            suggestions = mitigation_suggestions(
                service_name,
                vuln['severity']
            )

            self.mitigation_data.append({
                "service": service_name,
                "severity": vuln['severity'],
                "suggestions": suggestions
            })

    def display_dashboard(self):
        """
        Display rich dashboard.
        """

        console.print(
            Panel.fit(
                "Vulnerability Assessment Dashboard",
                style="bold magenta"
            )
        )

        # Open ports table
        port_table = Table(title="Open Ports & Services")

        port_table.add_column("Port", style="cyan")
        port_table.add_column("Service", style="green")
        port_table.add_column("Version", style="yellow")

        for item in self.open_ports:

            port_table.add_row(
                str(item['port']),
                item['service'],
                item['version']
            )

        console.print(port_table)

        # Vulnerability table
        vuln_table = Table(title="Detected Vulnerabilities")

        vuln_table.add_column("Port", style="cyan")
        vuln_table.add_column("Service", style="green")
        vuln_table.add_column("CVE ID", style="red")
        vuln_table.add_column("CVSS", style="yellow")
        vuln_table.add_column("Severity")

        for vuln in self.vulnerabilities:

            severity_style = {
                "LOW": "green",
                "MEDIUM": "yellow",
                "HIGH": "orange1",
                "CRITICAL": "red"
            }.get(vuln['severity'], "white")

            vuln_table.add_row(
                str(vuln['port']),
                vuln['service'],
                vuln['cve_id'],
                str(vuln['cvss_score']),
                f"[{severity_style}]"
                f"{vuln['severity']}"
                f"[/{severity_style}]"
            )

        console.print(vuln_table)

        # Dangerous port warnings
        for item in self.open_ports:

            warning = get_port_warning(item['port'])

            if warning:

                console.print(
                    f"[bold red]WARNING:[/bold red] "
                    f"Port {item['port']} "
                    f"({warning['service']}) - "
                    f"{warning['risk']}"
                )

        # Mitigation suggestions
        console.print(
            Panel.fit(
                "Mitigation Suggestions",
                style="bold green"
            )
        )

        for mitigation in self.mitigation_data:

            console.print(
                f"\n[cyan]{mitigation['service']}[/cyan] "
                f"({mitigation['severity']})"
            )

            for suggestion in mitigation['suggestions']:
                console.print(f" • {suggestion}")

    def export_data(self):
        """
        Export results to CSV and JSON.
        """

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        csv_path = f"exports/scan_results_{timestamp}.csv"
        json_path = f"exports/scan_results_{timestamp}.json"

        df = pd.DataFrame(self.vulnerabilities)

        if not df.empty:

            df.to_csv(csv_path, index=False)

            with open(json_path, "w") as file:
                json.dump(
                    self.vulnerabilities,
                    file,
                    indent=4
                )

            console.print(
                f"[green]CSV exported:[/green] {csv_path}"
            )

            console.print(
                f"[green]JSON exported:[/green] {json_path}"
            )

            logger.info(f"Data exported to {csv_path} and {json_path}")

        else:
            console.print(
                "[yellow]No vulnerabilities to export.[/yellow]"
            )
            logger.warning("Export skipped — no vulnerabilities found.")

    def generate_visualizations(self):
        """
        Generate vulnerability charts.
        """

        visualization = Visualization()

        pie_chart = visualization.severity_pie_chart(
            self.vulnerabilities
        )

        bar_chart = visualization.vulnerability_bar_chart(
            self.vulnerabilities
        )

        console.print(
            "[green]Charts generated successfully.[/green]"
        )

        return [pie_chart, bar_chart]

    def generate_report(self, charts):
        """
        Generate PDF report.
        """

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        report_path = (
            f"reports/vulnerability_report_{timestamp}.pdf"
        )

        report = PDFReportGenerator(report_path)

        report.generate_report(
            self.target,
            self.open_ports,
            self.vulnerabilities,
            charts,
            self.mitigation_data
        )

        console.print(
            f"[bold green]PDF Report Generated:"
            f"[/bold green] {report_path}"
        )


# Main execution
if __name__ == "__main__":

    if len(sys.argv) < 2:

        console.print(
            "[red]Usage:[/red] python scanner.py <target>"
        )

        sys.exit(1)

    target = sys.argv[1]

    scanner = IntelligentScanner(target)

    scanner.run_scan()

    scanner.display_dashboard()

    charts = scanner.generate_visualizations()

    scanner.export_data()

    scanner.generate_report(charts)

    console.print(
        Panel.fit(
            "Scan Completed Successfully",
            style="bold green"
        )
    )