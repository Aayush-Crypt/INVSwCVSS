"""
Interactive Streamlit Dashboard
Runs scans directly from browser input.
"""

import streamlit as st
import pandas as pd
import os
import glob

from scanner import IntelligentScanner

st.set_page_config(
    page_title="Intelligent Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide"
)

# Page Title
st.title("🛡️ Intelligent Network Vulnerability Scanner")

st.markdown(
    """
    Perform real-time vulnerability scanning with:

    - Port & Service Detection
    - CVE Lookup
    - CVSS Risk Analysis
    - PDF Reporting
    - Interactive Visual Analytics
    """
)

# Sidebar
st.sidebar.header("Scan Configuration")

scan_target = st.sidebar.text_input(
    "Enter Target IP or Website",
    placeholder="Example: 127.0.0.1 or scanme.nmap.org"
)

scan_button = st.sidebar.button("🚀 Start Scan")

# Information Cards
col1, col2, col3 = st.columns(3)

with col1:
    st.info("✔ Port Scanning")

with col2:
    st.warning("✔ CVE Detection")

with col3:
    st.success("✔ PDF Report Generation")

# Start Scan
if scan_button:

    if not scan_target:

        st.error("Please enter a valid target.")

    else:

        st.subheader(f"🔍 Scanning Target: {scan_target}")

        progress_bar = st.progress(0)

        status_text = st.empty()

        try:

            # Initialize scanner
            scanner = IntelligentScanner(scan_target)

            status_text.text("Starting Nmap Scan...")
            progress_bar.progress(20)

            # Run scan
            scanner.run_scan()

            progress_bar.progress(50)

            status_text.text(
                "Fetching Vulnerabilities from NVD..."
            )

            progress_bar.progress(70)

            status_text.text(
                "Generating Charts and Reports..."
            )

            # Generate charts
            charts = scanner.generate_visualizations()

            # Export files
            scanner.export_data()

            # Generate PDF report
            scanner.generate_report(charts)

            progress_bar.progress(100)

            status_text.text(
                "Scan Completed Successfully"
            )

            st.success(
                "Vulnerability Assessment Completed"
            )

            # Open Ports Section
            st.subheader("📡 Open Ports & Services")

            if scanner.open_ports:

                open_ports_df = pd.DataFrame(
                    scanner.open_ports
                )

                st.dataframe(
                    open_ports_df,
                    use_container_width=True
                )

            else:
                st.info("No open ports detected.")

            # Vulnerability Section
            st.subheader("🚨 Detected Vulnerabilities")

            if scanner.vulnerabilities:

                vuln_df = pd.DataFrame(
                    scanner.vulnerabilities
                )

                st.dataframe(
                    vuln_df,
                    use_container_width=True
                )

                # Metrics
                total_vulns = len(vuln_df)

                critical_count = len(
                    vuln_df[
                        vuln_df['severity'] == 'CRITICAL'
                    ]
                )

                high_count = len(
                    vuln_df[
                        vuln_df['severity'] == 'HIGH'
                    ]
                )

                medium_count = len(
                    vuln_df[
                        vuln_df['severity'] == 'MEDIUM'
                    ]
                )

                metric1, metric2, metric3, metric4 = st.columns(4)

                metric1.metric("Total", total_vulns)
                metric2.metric("Critical", critical_count)
                metric3.metric("High", high_count)
                metric4.metric("Medium", medium_count)

            else:
                st.success("No vulnerabilities found.")

            # Visualization Section
            st.subheader("📊 Visual Analytics")

            chart_col1, chart_col2 = st.columns(2)

            pie_chart = "charts/severity_pie_chart.png"
            bar_chart = "charts/vulnerability_bar_chart.png"

            with chart_col1:

                if os.path.exists(pie_chart):

                    st.image(
                        pie_chart,
                        caption="Severity Distribution"
                    )

            with chart_col2:

                if os.path.exists(bar_chart):

                    st.image(
                        bar_chart,
                        caption="Vulnerability Count"
                    )

            # Mitigation Suggestions
            st.subheader("🛠️ Mitigation Suggestions")

            if scanner.mitigation_data:

                for mitigation in scanner.mitigation_data:

                    with st.expander(
                        f"{mitigation['service']} "
                        f"({mitigation['severity']})"
                    ):

                        for suggestion in mitigation['suggestions']:
                            st.write(f"• {suggestion}")

            # Download Latest PDF Report
            st.subheader("📄 Download Report")

            pdf_reports = glob.glob("reports/*.pdf")

            if pdf_reports:

                latest_report = max(
                    pdf_reports,
                    key=os.path.getctime
                )

                with open(latest_report, "rb") as file:

                    st.download_button(
                        label="Download PDF Report",
                        data=file,
                        file_name=os.path.basename(
                            latest_report
                        ),
                        mime="application/pdf"
                    )

        except Exception as error:
            st.error(f"Scan failed: {error}")

# Footer
st.markdown("---")

st.markdown(
    "Built for Ethical Cybersecurity Testing, "
    "Learning, and Academic Demonstration"
)