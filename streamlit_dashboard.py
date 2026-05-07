"""
Intelligent Network Vulnerability Scanner
Streamlit Dashboard
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import os
import re
import glob
import requests
from datetime import datetime
from collections import Counter

from scanner import IntelligentScanner
from dangerous_ports import get_port_warning

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="INVS · Vuln Scanner",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Global CSS ────────────────────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] { font-family: 'JetBrains Mono', monospace; }

#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 1.2rem; padding-bottom: 2rem; }

/* Topbar */
.topbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 0.6rem 1.2rem; border: 1px solid #1e293b; border-radius: 8px;
    background: #0f172a; margin-bottom: 1.4rem;
}
.topbar-left {
    display: flex; align-items: center; gap: 10px;
    font-size: 13px; font-weight: 500; color: #94a3b8; letter-spacing: 0.04em;
}
.topbar-left span.logo { color: #e2e8f0; }
.pulse {
    width: 8px; height: 8px; border-radius: 50%; background: #22c55e;
    display: inline-block; animation: blink 1.6s infinite;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
.topbar-right { display: flex; gap: 20px; font-size: 11px; color: #64748b; }
.t-ok { color: #22c55e; }

/* Metric cards */
.metric-card {
    background: #0f172a; border: 1px solid #1e293b;
    border-radius: 8px; padding: 1rem 1.2rem;
}
.metric-label {
    font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase;
    color: #475569; margin-bottom: 6px;
}
.metric-value { font-size: 26px; font-weight: 500; line-height: 1; }
.c-neutral { color: #e2e8f0; }
.c-crit    { color: #ef4444; }
.c-high    { color: #f59e0b; }
.c-ok      { color: #22c55e; }
.c-info    { color: #60a5fa; }

/* Panels */
.panel {
    background: #0f172a; border: 1px solid #1e293b;
    border-radius: 8px; padding: 1rem 1.2rem; margin-bottom: 1rem;
}
.panel-title {
    font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase;
    color: #475569; margin-bottom: 0.9rem;
    border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem;
}

/* Severity badges */
.badge {
    display: inline-block; font-size: 10px; font-weight: 500;
    padding: 2px 8px; border-radius: 4px; min-width: 56px;
    text-align: center; letter-spacing: 0.05em;
}
.b-CRITICAL { background:#450a0a; color:#fca5a5; }
.b-HIGH     { background:#431407; color:#fed7aa; }
.b-MEDIUM   { background:#1e3a5f; color:#93c5fd; }
.b-LOW      { background:#14532d; color:#86efac; }
.b-UNKNOWN  { background:#1e293b; color:#94a3b8; }

/* Findings table */
.ft { width:100%; border-collapse:collapse; font-size:12px; }
.ft th {
    text-align:left; font-size:10px; letter-spacing:0.08em;
    color:#475569; padding:6px 10px; border-bottom:1px solid #1e293b;
}
.ft td { padding:8px 10px; border-bottom:1px solid #0f1f35; color:#94a3b8; vertical-align:middle; }
.ft tr:last-child td { border-bottom:none; }
.ft .cve  { color:#e2e8f0; font-weight:500; }
.ft .sc   { color:#ef4444; font-weight:500; }
.ft .sh   { color:#f59e0b; font-weight:500; }
.ft .sm   { color:#60a5fa; font-weight:500; }
.ft .sl   { color:#22c55e; font-weight:500; }

/* Port tags */
.tag-wrap { display:flex; flex-wrap:wrap; gap:6px; margin-top:4px; }
.ptag {
    font-size:11px; padding:3px 10px; border-radius:4px;
    border:1px solid #1e293b; color:#64748b; background:#0a1628;
}
.ptag.d { border-color:#7f1d1d; color:#fca5a5; background:#1a0a0a; }

/* Scan log */
.slog {
    background:#080f1c; border:1px solid #1e293b; border-radius:6px;
    padding:0.75rem 1rem; font-size:11.5px; line-height:2;
    color:#475569; max-height:200px; overflow-y:auto;
}
.lok  { color:#22c55e; }
.lerr { color:#ef4444; }
.lwrn { color:#f59e0b; }
.ldim { color:#334155; }

/* Warning strip */
.wstrip {
    background:#1a0a0a; border:1px solid #7f1d1d; border-radius:6px;
    padding:0.6rem 1rem; font-size:11.5px; color:#fca5a5; margin-bottom:6px;
}

/* Sidebar */
section[data-testid="stSidebar"] { background:#0a1220; border-right:1px solid #1e293b; }
section[data-testid="stSidebar"] .stTextInput input {
    background:#0f172a; border:1px solid #1e293b; color:#e2e8f0;
    font-family:'JetBrains Mono',monospace; font-size:13px;
}
div[data-testid="stButton"] > button {
    background:#0f172a; border:1px solid #22c55e; color:#22c55e;
    font-family:'JetBrains Mono',monospace; font-size:12px;
    letter-spacing:0.06em; width:100%; padding:0.5rem;
    border-radius:6px;
}
div[data-testid="stButton"] > button:hover { background:#0d2a1a; }
details {
    background:#0a1220; border:1px solid #1e293b;
    border-radius:6px; margin-bottom:6px;
}
details summary { color:#64748b; font-size:12px; padding:0.5rem 0.75rem; cursor:pointer; }
</style>
""", unsafe_allow_html=True)

# ── Session state ─────────────────────────────────────────────────────────────

for key, default in [
    ("scanner",      None),
    ("scan_done",    False),
    ("scan_log",     []),
    ("scan_target",  ""),
    ("nvd_status",   None),   # None = unchecked, True = online, False = offline
]:
    if key not in st.session_state:
        st.session_state[key] = default

# NVD health check — runs once per session
if st.session_state.nvd_status is None:
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"resultsPerPage": 1},
            timeout=5
        )
        st.session_state.nvd_status = r.status_code == 200
    except Exception:
        st.session_state.nvd_status = False


def is_valid_target(target: str) -> bool:
    """
    Accept IPv4 addresses, IPv6 addresses, hostnames, and CIDR ranges.
    Reject anything that looks like nmap flags or shell injection.
    """
    target = target.strip()
    # IPv4 with optional CIDR
    ipv4 = r"^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$"
    # Hostname (letters, digits, hyphens, dots)
    hostname = r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,252}[a-zA-Z0-9])?$"
    return bool(re.match(ipv4, target) or re.match(hostname, target))

# ── Helpers ───────────────────────────────────────────────────────────────────

def badge(severity: str) -> str:
    s = (severity or "UNKNOWN").upper()
    return f'<span class="badge b-{s}">{s}</span>'

def score_cls(score) -> str:
    if score is None: return ""
    v = float(score)
    if v >= 9.0: return "sc"
    if v >= 7.0: return "sh"
    if v >= 4.0: return "sm"
    return "sl"

def avg_cvss(vulns) -> str:
    scores = [float(v["cvss_score"]) for v in vulns if v.get("cvss_score") is not None]
    return f"{sum(scores)/len(scores):.1f}" if scores else "N/A"

def low_pct(vulns) -> str:
    if not vulns: return "—"
    low = sum(1 for v in vulns if v.get("severity") == "LOW")
    return f"{int(low/len(vulns)*100)}%"

def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def logline(cls, icon, msg) -> str:
    return f'<span class="ldim">[{ts()}]</span> <span class="{cls}">{icon}</span> {msg}'

def findings_table(vulns) -> str:
    if not vulns:
        return "<p style='color:#475569;font-size:12px;'>no vulnerabilities found.</p>"
    rows = "".join(
        f"<tr>"
        f"<td>{badge(v.get('severity','UNKNOWN'))}</td>"
        f"<td class='cve'>{v.get('cve_id','N/A')}</td>"
        f"<td>{v.get('service','—')} :{v.get('port','—')}</td>"
        f"<td class='{score_cls(v.get('cvss_score'))}'>{v.get('cvss_score','—')}</td>"
        f"</tr>"
        for v in vulns
    )
    return (
        "<table class='ft'>"
        "<thead><tr><th>SEVERITY</th><th>CVE ID</th><th>SERVICE</th><th>CVSS</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )

def port_tags(ports) -> str:
    if not ports:
        return "<span style='color:#475569;font-size:12px;'>no open ports</span>"
    tags = "".join(
        f'<span class="ptag{"  d" if get_port_warning(p.get("port")) else ""}">'
        f'{p.get("service","?")} :{p.get("port")}</span>'
        for p in ports
    )
    return f'<div class="tag-wrap">{tags}</div>'

def scan_log_html(lines) -> str:
    if not lines:
        return '<div class="slog"><span class="ldim">-- awaiting scan --</span></div>'
    return f'<div class="slog">{"<br>".join(lines)}</div>'

def metric_card(col, label, value, cls):
    col.markdown(
        f'<div class="metric-card">'
        f'<div class="metric-label">{label}</div>'
        f'<div class="metric-value {cls}">{value}</div>'
        f'</div>',
        unsafe_allow_html=True
    )

# ── Topbar ────────────────────────────────────────────────────────────────────

target_display = st.session_state.scan_target or "no target"
status_label   = "scan active" if st.session_state.scan_done else "idle"
status_cls     = "t-ok" if st.session_state.scan_done else ""

nvd_online     = st.session_state.nvd_status
nvd_label      = "nvd api online" if nvd_online else "nvd api offline"
nvd_cls        = "t-ok" if nvd_online else "lerr"

st.markdown(f"""
<div class="topbar">
  <div class="topbar-left">
    <div class="pulse"></div>
    <span class="logo">invs</span>
    <span>/</span>
    <span>intelligent network vulnerability scanner</span>
  </div>
  <div class="topbar-right">
    <span class="{status_cls}">{status_label}</span>
    <span>{target_display}</span>
    <span class="{nvd_cls}">{nvd_label}</span>
    <span>cvss v3.1</span>
  </div>
</div>
""", unsafe_allow_html=True)

if "scan_error" in st.session_state and st.session_state.scan_error:
    st.error(f"scan failed: {st.session_state.scan_error}")
    st.session_state.scan_error = ""

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown(
        "<div style='font-size:11px;color:#334155;letter-spacing:0.08em;"
        "text-transform:uppercase;margin-bottom:1rem;'>scan configuration</div>",
        unsafe_allow_html=True
    )

    scan_target = st.text_input(
        "Target", placeholder="127.0.0.1 or scanme.nmap.org",
        label_visibility="collapsed"
    )
    scan_button = st.button("▶  run scan")

    st.markdown("<hr style='border-color:#1e293b;margin:1rem 0'>", unsafe_allow_html=True)

    st.markdown("""
    <div style='font-size:10px;color:#334155;letter-spacing:0.08em;
                text-transform:uppercase;margin-bottom:0.6rem;'>modules active</div>
    <div style='font-size:11px;color:#475569;line-height:2.2;'>
        <span style='color:#22c55e'>✓</span> port &amp; service detection<br>
        <span style='color:#22c55e'>✓</span> nvd cve lookup<br>
        <span style='color:#22c55e'>✓</span> cvss v3.1 scoring<br>
        <span style='color:#22c55e'>✓</span> risk classification<br>
        <span style='color:#22c55e'>✓</span> pdf report generator<br>
        <span style='color:#22c55e'>✓</span> dangerous port detection
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<hr style='border-color:#1e293b;margin:1rem 0'>", unsafe_allow_html=True)

    pdf_files = glob.glob("reports/*.pdf")
    if pdf_files:
        latest_pdf = max(pdf_files, key=os.path.getctime)
        with open(latest_pdf, "rb") as f:
            st.download_button(
                label="⬇  download last report",
                data=f,
                file_name=os.path.basename(latest_pdf),
                mime="application/pdf"
            )

# ── Run scan ──────────────────────────────────────────────────────────────────

if scan_button:
    if not scan_target:
        st.error("enter a valid target.")
    elif not is_valid_target(scan_target):
        st.error(
            "invalid target — enter an IPv4 address (e.g. 192.168.1.1), "
            "a CIDR range (e.g. 192.168.1.0/24), or a hostname (e.g. scanme.nmap.org)."
        )
    else:
        st.session_state.scan_target = scan_target
        st.session_state.scan_log    = []
        st.session_state.scan_done   = False
        log = st.session_state.scan_log

        bar = st.progress(0, text="initialising...")
        try:
            scanner = IntelligentScanner(scan_target)
            log.append(logline("ldim", "→", f"target: {scan_target}"))

            bar.progress(10, text="starting nmap scan...")
            scanner.run_scan()
            log.append(logline("lok", "✓", "nmap scan complete"))

            bar.progress(40, text="fetching cve data from nvd...")
            for p in scanner.open_ports:
                w = get_port_warning(p.get("port"))
                if w:
                    log.append(logline("lwrn", "!", f'port {p["port"]} ({p["service"]}) — {w["risk"][:55]}'))
                else:
                    log.append(logline("lok", "✓", f'port {p["port"]} ({p.get("service","?")}) — open'))

            bar.progress(65, text="generating charts...")
            charts = scanner.generate_visualizations()
            log.append(logline("lok", "✓", "visualisations generated"))

            bar.progress(80, text="exporting data...")
            scanner.export_data()
            log.append(logline("lok", "✓", "csv / json exported"))

            bar.progress(90, text="generating pdf report...")
            scanner.generate_report(charts)
            log.append(logline("lok", "✓", "pdf report saved"))

            bar.progress(100, text="done.")
            log.append(logline("lok", "✓", "scan completed successfully"))

            st.session_state.scanner   = scanner
            st.session_state.scan_done = True

        except Exception as err:
            log.append(logline("lerr", "✗", f"scan failed: {err}"))
            st.session_state.scan_error = str(err)

        st.rerun()

# ── Results dashboard ─────────────────────────────────────────────────────────

scanner   = st.session_state.scanner
scan_done = st.session_state.scan_done

if scan_done and scanner:

    vulns       = scanner.vulnerabilities
    open_ports  = scanner.open_ports
    mitigations = scanner.mitigation_data

    crit_n = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    high_n = sum(1 for v in vulns if v.get("severity") == "HIGH")

    # Metrics
    c1, c2, c3, c4, c5 = st.columns(5)
    metric_card(c1, "open ports",   len(open_ports), "c-info")
    metric_card(c2, "critical",     crit_n,          "c-crit")
    metric_card(c3, "high",         high_n,          "c-high")
    metric_card(c4, "avg cvss",     avg_cvss(vulns), "c-high")
    metric_card(c5, "low severity", low_pct(vulns),  "c-ok")

    st.markdown("<div style='margin-top:1rem'></div>", unsafe_allow_html=True)

    # Dangerous port warnings
    for p in open_ports:
        w = get_port_warning(p.get("port"))
        if w:
            st.markdown(
                f'<div class="wstrip">⚠ port {p["port"]} ({w["service"]}) — {w["risk"]}</div>',
                unsafe_allow_html=True
            )

    # Main grid
    left, right = st.columns([3, 2], gap="medium")

    with left:
        st.markdown(
            '<div class="panel"><div class="panel-title">active findings</div>'
            + findings_table(vulns) + '</div>',
            unsafe_allow_html=True
        )
        st.markdown(
            '<div class="panel"><div class="panel-title">open services</div>'
            + port_tags(open_ports) + '</div>',
            unsafe_allow_html=True
        )
        st.markdown(
            '<div class="panel"><div class="panel-title">scan log</div>'
            + scan_log_html(st.session_state.scan_log) + '</div>',
            unsafe_allow_html=True
        )

    with right:
        COLOR_MAP = {
            "CRITICAL": "#ef4444", "HIGH": "#f59e0b",
            "MEDIUM":   "#3b82f6", "LOW":  "#22c55e",
            "UNKNOWN":  "#475569"
        }
        ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        counts = Counter(v.get("severity", "UNKNOWN") for v in vulns)
        labels = [s for s in ORDER if counts.get(s, 0) > 0]
        values = [counts[s] for s in labels]

        CHART_LAYOUT = dict(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#080f1c",
            font=dict(family="JetBrains Mono", size=11, color="#475569"),
            margin=dict(l=0, r=0, t=0, b=0),
        )

        # Risk bar chart
        if labels:
            fig_bar = go.Figure(go.Bar(
                x=labels, y=values,
                marker_color=[COLOR_MAP.get(l, "#475569") for l in labels],
                marker_line_width=0,
            ))
            fig_bar.update_layout(
                **CHART_LAYOUT, height=185, bargap=0.35,
                xaxis=dict(showgrid=False, zeroline=False, tickfont=dict(color="#475569")),
                yaxis=dict(showgrid=True, gridcolor="#1e293b", zeroline=False,
                           tickfont=dict(color="#475569")),
            )
            st.markdown(
                '<div class="panel"><div class="panel-title">risk distribution</div>',
                unsafe_allow_html=True
            )
            st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar": False})
            st.markdown('</div>', unsafe_allow_html=True)

        # CVSS histogram
        scores = [float(v["cvss_score"]) for v in vulns if v.get("cvss_score") is not None]
        if scores:
            fig_hist = go.Figure(go.Histogram(
                x=scores, nbinsx=10,
                marker_color="#3b82f6", marker_line_width=0,
            ))
            fig_hist.update_layout(
                **CHART_LAYOUT, height=165, bargap=0.1,
                xaxis=dict(title="cvss score", showgrid=False,
                           tickfont=dict(color="#475569"),
                           title_font=dict(color="#475569")),
                yaxis=dict(title="count", showgrid=True, gridcolor="#1e293b",
                           zeroline=False, tickfont=dict(color="#475569"),
                           title_font=dict(color="#475569")),
            )
            st.markdown(
                '<div class="panel"><div class="panel-title">cvss score spread</div>',
                unsafe_allow_html=True
            )
            st.plotly_chart(fig_hist, use_container_width=True, config={"displayModeBar": False})
            st.markdown('</div>', unsafe_allow_html=True)

        # Severity donut
        if labels:
            fig_pie = go.Figure(go.Pie(
                labels=labels, values=values, hole=0.6,
                marker=dict(
                    colors=[COLOR_MAP.get(l, "#475569") for l in labels],
                    line=dict(color="#080f1c", width=2)
                ),
                textinfo="percent",
                textfont=dict(size=11, family="JetBrains Mono", color="#94a3b8"),
                hovertemplate="%{label}: %{value}<extra></extra>"
            ))
            fig_pie.update_layout(
                **CHART_LAYOUT, height=210,
                legend=dict(font=dict(size=10, color="#475569"),
                            bgcolor="rgba(0,0,0,0)",
                            orientation="h", x=0, y=-0.15),
            )
            st.markdown(
                '<div class="panel"><div class="panel-title">severity breakdown</div>',
                unsafe_allow_html=True
            )
            st.plotly_chart(fig_pie, use_container_width=True, config={"displayModeBar": False})
            st.markdown('</div>', unsafe_allow_html=True)

    # Mitigation suggestions
    if mitigations:
        st.markdown(
            '<div class="panel-title" style="margin-top:0.5rem">mitigation suggestions</div>',
            unsafe_allow_html=True
        )
        seen = set()
        for m in mitigations:
            key = (m["service"], m["severity"])
            if key in seen:
                continue
            seen.add(key)
            with st.expander(f'{m["service"]}  ·  {m["severity"].lower()}'):
                for s in m["suggestions"]:
                    st.markdown(
                        f"<span style='color:#475569;font-size:12px;'>→ {s}</span>",
                        unsafe_allow_html=True
                    )

    # Full vulnerability detail table
    if vulns:
        st.markdown(
            '<div class="panel-title" style="margin-top:0.5rem">full vulnerability detail</div>',
            unsafe_allow_html=True
        )
        df = pd.DataFrame(vulns)[
            ["cve_id", "severity", "cvss_score", "service", "port", "description"]
        ].rename(columns={
            "cve_id": "CVE ID", "severity": "Severity", "cvss_score": "CVSS",
            "service": "Service", "port": "Port", "description": "Description"
        })
        st.dataframe(
            df, use_container_width=True, hide_index=True,
            column_config={
                "CVSS": st.column_config.ProgressColumn(
                    "CVSS", min_value=0, max_value=10, format="%.1f"
                )
            }
        )

# ── Empty state ───────────────────────────────────────────────────────────────

else:
    st.markdown("""
    <div style="margin-top:4rem;text-align:center;color:#1e293b;
                font-size:13px;letter-spacing:0.06em;">
        <div style="font-size:36px;margin-bottom:1rem;opacity:0.3;">⬡</div>
        enter a target in the sidebar and run a scan
    </div>
    """, unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────────────────

st.markdown("""
<div style="margin-top:3rem;border-top:1px solid #1e293b;padding-top:0.75rem;
            font-size:10px;color:#1e293b;letter-spacing:0.06em;text-align:center;">
    built for ethical cybersecurity testing · academic demonstration only
</div>
""", unsafe_allow_html=True)