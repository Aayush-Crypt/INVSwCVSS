# 🛡️ INVS — Intelligent Network Vulnerability Scanner

A Python-based network vulnerability scanner that combines **Nmap port scanning**, **NVD CVE lookup**, **CVSS v3.1 risk classification**, and an interactive **Streamlit dashboard** — built for ethical cybersecurity testing and academic demonstration.

---

## 📸 Features

- 🔍 **Port & Service Detection** — SYN + version scan via `python-nmap`
- 🗄️ **NVD CVE Lookup** — Fetches real CVE data from the National Vulnerability Database API
- 📊 **CVSS v3.1 Scoring** — Classifies findings as LOW / MEDIUM / HIGH / CRITICAL
- ⚠️ **Dangerous Port Warnings** — Flags known risky ports (FTP, Telnet, SMB, RDP, etc.)
- 🧠 **Mitigation Engine** — Generates contextual remediation suggestions per service
- 📈 **Visualizations** — Pie chart and bar chart breakdowns of severity distribution
- 📄 **PDF Report Generator** — Professional vulnerability report via ReportLab
- 💾 **Data Export** — Results saved as CSV and JSON
- 🖥️ **Streamlit Dashboard** — Dark-themed, real-time interactive web UI

---

## 🗂️ Project Structure

```
invs/
├── scanner.py               # Main scanner — orchestrates the full pipeline
├── streamlit_dashboard.py   # Streamlit web UI
├── vulnerability_lookup.py  # NVD API client + mitigation engine
├── risk_classifier.py       # CVSS score → severity classification
├── dangerous_ports.py       # Known risky port definitions
├── visualization.py         # Matplotlib chart generation
├── report_generator.py      # PDF report builder (ReportLab)
├── requirements.txt         # Python dependencies
├── exports/                 # Auto-created: CSV & JSON scan results
├── reports/                 # Auto-created: PDF vulnerability reports
└── charts/                  # Auto-created: Generated chart images
```

---

## ⚙️ Installation

### Prerequisites

- Python 3.8+
- **Nmap** installed on your system

```bash
# macOS
brew install nmap

# Ubuntu / Debian
sudo apt install nmap

# Windows
# Download from https://nmap.org/download.html
```

### Setup

```bash
git clone https://github.com/Aayush-Crypt/INVSwCVSS.git
cd invs

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

---

## 🚀 Usage

### CLI Mode

Run a scan directly from the terminal:

```bash
# Requires root/admin for SYN scan (-sS)
sudo python scanner.py <target>

# Examples
sudo python scanner.py 127.0.0.1
sudo python scanner.py scanme.nmap.org
sudo python scanner.py 192.168.1.0/24
```

The CLI will:
1. Run the Nmap scan
2. Fetch CVEs from NVD for each open service
3. Display a rich dashboard in the terminal
4. Export results to `exports/` (CSV + JSON)
5. Generate charts in `charts/`
6. Save a PDF report to `reports/`

---

### Streamlit Dashboard

Launch the interactive web UI:

```bash
streamlit run streamlit_dashboard.py
```

Then open `http://localhost:8501` in your browser. Enter a target IP or hostname in the sidebar and click **Run Scan**.

**Dashboard panels include:**
- Live metric cards (open ports, critical/high counts, avg CVSS)
- Active findings table with severity badges
- Risk distribution bar chart
- CVSS score histogram
- Severity breakdown donut chart
- Dangerous port warning strips
- Expandable mitigation suggestions
- Full vulnerability detail table
- Scan log with timestamped entries
- PDF report download button

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `python-nmap` | Nmap wrapper for port/service scanning |
| `requests` | NVD API HTTP client |
| `pandas` | Data handling and CSV export |
| `matplotlib` | Static chart generation |
| `plotly` | Interactive charts in Streamlit |
| `rich` | Styled terminal output |
| `reportlab` | PDF report generation |
| `streamlit` | Web dashboard framework |

Install all at once:

```bash
pip install -r requirements.txt
```

---

## 🔧 Module Overview

### `scanner.py`
The main entry point. `IntelligentScanner` runs the Nmap scan, calls the vulnerability lookup, builds visualizations, exports data, and generates the PDF report.

### `vulnerability_lookup.py`
Queries the [NVD REST API v2.0](https://nvd.nist.gov/developers/vulnerabilities) using the service name and version as keywords. Returns up to 5 CVEs per service, including CVSS score and description. Also contains the `mitigation_suggestions()` function.

### `risk_classifier.py`
Maps a CVSS base score to a severity label:

| Score | Severity |
|---|---|
| 0.0 – 3.9 | LOW |
| 4.0 – 6.9 | MEDIUM |
| 7.0 – 8.9 | HIGH |
| 9.0 – 10.0 | CRITICAL |

### `dangerous_ports.py`
Defines 13 well-known risky ports (21, 23, 25, 53, 135, 139, 143, 445, 3306, 3389, 5432, 5900) with service names and risk descriptions. Used for warning overlays in both the CLI and dashboard.

### `visualization.py`
Generates and saves two matplotlib charts to `charts/`:
- `severity_pie_chart.png` — severity distribution
- `vulnerability_bar_chart.png` — count by severity

### `report_generator.py`
Builds a multi-page PDF using ReportLab with: scan metadata, open ports table, vulnerabilities table, embedded charts, and per-service mitigation suggestions.

---

## 📁 Output Files

| Location | Format | Contents |
|---|---|---|
| `exports/scan_results_<timestamp>.csv` | CSV | All vulnerabilities with port, service, CVE, CVSS, severity |
| `exports/scan_results_<timestamp>.json` | JSON | Same data in structured JSON |
| `reports/vulnerability_report_<timestamp>.pdf` | PDF | Full formatted report with charts |
| `charts/severity_pie_chart.png` | PNG | Severity distribution pie chart |
| `charts/vulnerability_bar_chart.png` | PNG | Vulnerability count bar chart |

---

## ⚠️ Legal & Ethical Notice

> **This tool is intended for ethical cybersecurity testing and academic demonstration only.**
>
> - Only scan systems you own or have explicit written permission to test.
> - Unauthorized scanning may violate local laws (e.g., the Computer Fraud and Abuse Act in the US).
> - The authors are not responsible for any misuse of this software.

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.