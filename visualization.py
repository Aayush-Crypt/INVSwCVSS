"""
Visualization Module
Creates charts using matplotlib.
"""

import matplotlib.pyplot as plt
from collections import Counter
import os


class Visualization:

    def __init__(self):
        os.makedirs("charts", exist_ok=True)

    def severity_pie_chart(self, vulnerabilities):
        """
        Create severity distribution pie chart.
        """

        severities = [v["severity"] for v in vulnerabilities]

        counts = Counter(severities)

        labels = list(counts.keys())
        sizes = list(counts.values())

        if not sizes:
            return None

        plt.figure(figsize=(6, 6))

        plt.pie(
            sizes,
            labels=labels,
            autopct="%1.1f%%"
        )

        plt.title("Severity Distribution")

        chart_path = "charts/severity_pie_chart.png"

        plt.savefig(chart_path)

        plt.close()

        return chart_path

    def vulnerability_bar_chart(self, vulnerabilities):
        """
        Create vulnerability count bar graph.
        """

        severities = [v["severity"] for v in vulnerabilities]

        counts = Counter(severities)

        labels = list(counts.keys())
        values = list(counts.values())

        if not values:
            return None

        plt.figure(figsize=(8, 5))

        plt.bar(labels, values)

        plt.xlabel("Severity")
        plt.ylabel("Count")
        plt.title("Vulnerability Count by Severity")

        chart_path = "charts/vulnerability_bar_chart.png"

        plt.savefig(chart_path)

        plt.close()

        return chart_path