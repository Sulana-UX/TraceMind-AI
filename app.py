"""
TraceMind AI - Digital Evidence Story Builder
Streamlit Web Dashboard for Defensive Cybersecurity & Digital Forensics.
"""

import os
import io
import time
import base64
from pathlib import Path
import streamlit as st
import pandas as pd
try:
    import plotly.express as px
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    px = None
    go = None
    HAS_PLOTLY = False

from src.parsers import stream_lanl_file, stream_generic_json, detect_lanl_file_type
from src.normalizer import normalize_record, events_to_dataframe, NormalizedEvent
from src.correlation_engine import CorrelationEngine
from src.anomaly_detector import EntityAnomalyDetector
from src.evidence_graph import EvidenceGraphBuilder
from src.story_builder import StoryBuilder
from src.integrity import compute_file_sha256, generate_provenance_record
from src.export import safe_dataframe_to_csv, export_report_to_json, generate_html_forensic_report, generate_pdf_forensic_report
from data.synthetic_generator import generate_synthetic_dataset

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="TraceMind AI — Digital Evidence Story Builder",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling: Executive Cyber Defense & SOC Investigation Theme
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
    }

    code, pre, .mono {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Background and containers */
    .stApp {
        background-color: #050811;
        background-image: 
            radial-gradient(circle at 10% 10%, rgba(14, 165, 233, 0.08) 0%, transparent 40%),
            radial-gradient(circle at 90% 90%, rgba(99, 102, 241, 0.06) 0%, transparent 40%),
            radial-gradient(circle at 50% 50%, rgba(15, 23, 42, 0.5) 0%, transparent 70%);
        color: #f1f5f9;
    }

    /* Top Live Status Banner */
    .soc-live-banner {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: linear-gradient(90deg, rgba(13, 20, 36, 0.85) 0%, rgba(8, 13, 24, 0.95) 100%);
        border: 1px solid rgba(56, 189, 248, 0.18);
        backdrop-filter: blur(14px);
        padding: 9px 20px;
        border-radius: 8px;
        margin-bottom: 22px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .soc-status-pulse {
        display: inline-block;
        width: 8px;
        height: 8px;
        background-color: #10b981;
        border-radius: 50%;
        margin-right: 8px;
        box-shadow: 0 0 10px #10b981;
        animation: socPulse 2s infinite ease-in-out;
    }
    @keyframes socPulse {
        0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { box-shadow: 0 0 0 7px rgba(16, 185, 129, 0); }
        100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }
    .soc-status-tag {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.76rem;
        font-weight: 700;
        color: #10b981;
        letter-spacing: 0.06em;
    }
    .soc-status-text {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.74rem;
        color: #94a3b8;
    }
    .soc-status-divider {
        color: #334155;
        margin: 0 8px;
    }
    .soc-status-badge {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.74rem;
        font-weight: 600;
        color: #38bdf8;
        background: rgba(56, 189, 248, 0.08);
        border: 1px solid rgba(56, 189, 248, 0.2);
        padding: 3px 10px;
        border-radius: 4px;
        letter-spacing: 0.04em;
    }

    /* Section Kickers & Titles */
    .soc-kicker {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        margin-bottom: 4px;
    }
    .main-title {
        font-weight: 800;
        font-size: 2.15rem;
        background: linear-gradient(135deg, #ffffff 40%, #38bdf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.25rem;
        letter-spacing: -0.02em;
    }
    .subtitle {
        color: #94a3b8;
        font-size: 0.98rem;
        margin-bottom: 1.6rem;
        font-weight: 400;
    }
    .section-header {
        font-size: 1.25rem;
        font-weight: 700;
        color: #f8fafc;
        margin-top: 1.2rem;
        margin-bottom: 0.6rem;
        letter-spacing: -0.01em;
        border-bottom: 1px solid rgba(56, 189, 248, 0.12);
        padding-bottom: 6px;
    }

    /* Sidebar Brand Box */
    .soc-brand-box {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(8, 13, 24, 0.95) 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 10px;
        padding: 14px 16px;
        margin-bottom: 18px;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    }
    .soc-logo-icon {
        width: 38px;
        height: 38px;
        border-radius: 8px;
        background: rgba(56, 189, 248, 0.1);
        border: 1px solid rgba(56, 189, 248, 0.25);
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .soc-brand-title {
        font-weight: 800;
        font-size: 1.2rem;
        color: #f8fafc;
        letter-spacing: -0.02em;
        line-height: 1.2;
    }
    .soc-brand-title .glow-cyan {
        color: #38bdf8;
        text-shadow: 0 0 12px rgba(56, 189, 248, 0.5);
    }
    .soc-brand-sub {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
        font-weight: 600;
        color: #64748b;
        letter-spacing: 0.05em;
    }

    /* Sidebar Telemetry HUD */
    .soc-telemetry-box {
        background: rgba(13, 20, 36, 0.6);
        border: 1px solid rgba(56, 189, 248, 0.12);
        border-radius: 8px;
        padding: 12px;
        margin: 12px 0;
    }
    .soc-telemetry-header {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        color: #94a3b8;
        font-weight: 700;
        letter-spacing: 0.08em;
        margin-bottom: 8px;
        text-transform: uppercase;
    }
    .soc-telemetry-row {
        display: flex;
        justify-content: space-between;
        font-size: 0.8rem;
        padding: 3px 0;
        color: #cbd5e1;
    }
    .mono-cyan {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        color: #38bdf8;
    }
    .mono-amber {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        color: #fb923c;
    }

    /* Sidebar Airgap Card */
    .soc-airgap-box {
        background: rgba(13, 20, 36, 0.4);
        border: 1px solid rgba(100, 116, 139, 0.2);
        border-radius: 8px;
        padding: 10px 12px;
        font-size: 0.74rem;
        color: #64748b;
    }
    .soc-airgap-title {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        color: #94a3b8;
        margin-bottom: 2px;
        letter-spacing: 0.04em;
    }

    /* Hero Metric Cards */
    .stMetric {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.75) 0%, rgba(9, 14, 28, 0.85) 100%) !important;
        border: 1px solid rgba(56, 189, 248, 0.14) !important;
        border-radius: 10px !important;
        padding: 14px 18px !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3) !important;
        position: relative;
        overflow: hidden;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .stMetric:hover {
        border-color: rgba(56, 189, 248, 0.35) !important;
        transform: translateY(-2px);
    }
    .stMetric::before {
        content: "";
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, #0284c7 0%, #38bdf8 50%, #818cf8 100%);
    }
    .stMetric label {
        color: #94a3b8 !important;
        font-size: 0.76rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }
    .stMetric [data-testid="stMetricValue"] {
        color: #f8fafc !important;
        font-weight: 700 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 1.65rem !important;
    }

    /* Severity Badges */
    .badge-critical {
        background: rgba(244, 63, 94, 0.12);
        color: #fb7185;
        border: 1px solid rgba(244, 63, 94, 0.35);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.74rem;
        letter-spacing: 0.06em;
    }
    .badge-high {
        background: rgba(249, 115, 22, 0.12);
        color: #fb923c;
        border: 1px solid rgba(249, 115, 22, 0.35);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.74rem;
        letter-spacing: 0.06em;
    }
    .badge-medium {
        background: rgba(234, 179, 8, 0.12);
        color: #facc15;
        border: 1px solid rgba(234, 179, 8, 0.35);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.74rem;
        letter-spacing: 0.06em;
    }
    .badge-low {
        background: rgba(56, 189, 248, 0.12);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.35);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.74rem;
        letter-spacing: 0.06em;
    }

    /* Buttons & Links */
    .stButton > button, .soc-download-btn {
        background: linear-gradient(135deg, #131d31 0%, #0c1424 100%);
        color: #38bdf8 !important;
        border: 1px solid rgba(56, 189, 248, 0.28) !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        font-size: 0.86rem !important;
        letter-spacing: 0.02em;
        transition: all 0.2s ease-in-out;
    }
    .stButton > button:hover, .soc-download-btn:hover {
        background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
        color: #ffffff !important;
        border-color: #38bdf8 !important;
        box-shadow: 0 0 16px rgba(56, 189, 248, 0.35);
        transform: translateY(-1px);
        text-decoration: none !important;
    }
    .soc-download-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 100%;
        min-height: 42px;
        padding: 8px 12px;
        text-decoration: none !important;
        box-sizing: border-box;
        text-align: center;
        cursor: pointer;
    }

    /* Expanders & Cards */
    .streamlit-expanderHeader {
        background-color: rgba(13, 20, 36, 0.6) !important;
        border: 1px solid rgba(56, 189, 248, 0.12) !important;
        border-radius: 6px !important;
        color: #f1f5f9 !important;
        font-weight: 600 !important;
    }
    .stAlert {
        background: rgba(13, 20, 36, 0.8) !important;
        border: 1px solid rgba(56, 189, 248, 0.2) !important;
        border-radius: 8px !important;
        backdrop-filter: blur(8px);
    }

    /* Sidebar Overrides */
    [data-testid="stSidebar"] {
        background-color: #040711 !important;
        border-right: 1px solid rgba(56, 189, 248, 0.1) !important;
    }
    [data-testid="stSidebar"] hr {
        border-color: rgba(56, 189, 248, 0.1) !important;
    }

    /* Dataframe Overrides */
    [data-testid="stDataFrame"] {
        border: 1px solid rgba(56, 189, 248, 0.12) !important;
        border-radius: 8px;
    }

    /* Tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        border-bottom: 1px solid rgba(56, 189, 248, 0.15);
    }
    .stTabs [data-baseweb="tab"] {
        height: 40px;
        white-space: pre-wrap;
        background-color: transparent;
        border-radius: 4px 4px 0px 0px;
        color: #94a3b8;
        font-weight: 600;
        font-size: 0.88rem;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(56, 189, 248, 0.1) !important;
        color: #38bdf8 !important;
        border-bottom: 2px solid #38bdf8 !important;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Session State
if "events" not in st.session_state:
    st.session_state.events = []
if "findings" not in st.session_state:
    st.session_state.findings = []
if "provenance" not in st.session_state:
    st.session_state.provenance = []
if "sampling_applied" not in st.session_state:
    st.session_state.sampling_applied = False
if "sampling_note" not in st.session_state:
    st.session_state.sampling_note = ""
if "time_window" not in st.session_state:
    st.session_state.time_window = 300


# Sidebar Navigation
with st.sidebar:
    st.markdown("""
    <div class="soc-brand-box">
        <div style="display: flex; align-items: center; gap: 12px;">
            <div class="soc-logo-icon">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="m9 12 2 2 4-4"/>
                </svg>
            </div>
            <div>
                <div class="soc-brand-title">TraceMind <span class="glow-cyan">AI</span></div>
                <div class="soc-brand-sub">DEFENSIVE FORENSICS &bull; SOC v1.0</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    page = st.radio(
        "NAVIGATION CONSOLE",
        [
            "Overview",
            "Upload & Data Sources",
            "Incident Timeline",
            "Evidence Graph",
            "Anomaly Analysis",
            "Investigation Story",
            "Settings & Dataset Guide",
        ],
        index=0,
    )

    st.markdown("---")
    num_events = len(st.session_state.events)
    num_findings = len(st.session_state.findings)
    st.markdown(f"""
    <div class="soc-telemetry-box">
        <div class="soc-telemetry-header">SYSTEM TELEMETRY</div>
        <div class="soc-telemetry-row"><span>Indexed Records</span> <span class="mono-cyan">{num_events:,}</span></div>
        <div class="soc-telemetry-row"><span>Active Findings</span> <span class="mono-amber">{num_findings}</span></div>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.sampling_applied:
        st.caption(f"Sampling active: {st.session_state.sampling_note}")

    st.markdown("""
    <div class="soc-airgap-box">
        <div class="soc-airgap-title">AIRGAP ISOLATION</div>
        8 GB Memory Guard &bull; Local Execution &bull; Zero External Telemetry
    </div>
    """, unsafe_allow_html=True)


# Persistent Top Live Status Banner across all views
st.markdown("""
<div class="soc-live-banner">
    <div>
        <span class="soc-status-pulse"></span>
        <span class="soc-status-tag">ACTIVE SOC RADAR</span>
        <span class="soc-status-divider">|</span>
        <span class="soc-status-text">LOCAL FORENSIC ISOLATION &bull; IMMUTABLE AUDIT LOG</span>
    </div>
    <div class="soc-status-badge">
        RAM GUARD: 8.0 GB ENFORCED
    </div>
</div>
""", unsafe_allow_html=True)


# ---------------- PAGE 1: OVERVIEW ----------------
if page == "Overview":
    st.markdown("<div class='soc-kicker'>ANALYTICS & METRICS DASHBOARD</div>", unsafe_allow_html=True)
    st.markdown("<div class='main-title'>TraceMind AI &bull; Digital Evidence Overview</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='subtitle'>Evidence-grounded multi-source event correlation and incident timeline reconstruction.</div>",
        unsafe_allow_html=True,
    )

    if not st.session_state.events:
        st.info("Welcome to TraceMind AI. No evidence logs are currently indexed in memory. Navigate to 'Upload & Data Sources' or click below to initialize a synthetic multi-source test scenario.")
        col_btn1, col_btn2 = st.columns([1.2, 2])
        with col_btn1:
            if st.button("Load Synthetic Test Scenario", type="primary", use_container_width=True):
                with st.spinner("Generating synthetic LANL scenarios..."):
                    data_dir = Path("data/synthetic")
                    gen_files = generate_synthetic_dataset(str(data_dir))
                    loaded = []
                    provs = []
                    for name, fp in gen_files.items():
                        ftype = detect_lanl_file_type(name)
                        if ftype:
                            records = list(stream_lanl_file(fp, file_type=ftype, max_rows=5000))
                            norm = [normalize_record(r) for r in records if r]
                            loaded.extend([e for e in norm if e])
                            provs.append(generate_provenance_record(fp, len(records), 0, {"max_rows": 5000}, is_synthetic=True))

                    st.session_state.events = loaded
                    st.session_state.provenance = provs
                    engine = CorrelationEngine(time_window_seconds=st.session_state.time_window)
                    st.session_state.findings = engine.correlate(loaded)
                    st.session_state.sampling_applied = False
                    st.rerun()

    else:
        events = st.session_state.events
        findings = st.session_state.findings
        timestamps = [e.timestamp for e in events if e.timestamp is not None]
        min_t = min(timestamps) if timestamps else 0
        max_t = max(timestamps) if timestamps else 0
        users = {e.user for e in events if e.user}
        hosts = {e.src_host for e in events if e.src_host} | {e.dst_host for e in events if e.dst_host}
        ev_types = {e.event_type for e in events}

        # Key Metrics Row
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Processed Records", f"{len(events):,}")
        m2.metric("Relative Time Span", f"{max_t - min_t:,}s", help="Relative seconds between first and last event")
        m3.metric("Unique Users", len(users))
        m4.metric("Unique Hosts", len(hosts))
        m5.metric("Event Categories", len(ev_types))
        m6.metric("Correlated Findings", len(findings))

        st.markdown("---")

        col_left, col_right = st.columns([1.5, 1])

        with col_left:
            st.markdown("<div class='section-header'>Ingested Event Distribution</div>", unsafe_allow_html=True)
            df_ev = events_to_dataframe(events)
            if HAS_PLOTLY and px:
                fig_types = px.histogram(
                    df_ev,
                    x="event_type",
                    color="action",
                    barmode="stack",
                    title="Event Volume by Category & Action",
                    color_discrete_sequence=px.colors.qualitative.Prism,
                )
                fig_types.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="#090d16",
                    plot_bgcolor="#090d16",
                    font=dict(color="#94a3b8"),
                    margin=dict(l=20, r=20, t=40, b=20),
                    height=320,
                )
                st.plotly_chart(fig_types, use_container_width=True)
            else:
                st.bar_chart(df_ev["event_type"].value_counts())

        with col_right:
            st.markdown("<div class='section-header'>Threat Severity Ratio</div>", unsafe_allow_html=True)
            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

            df_sev = pd.DataFrame([{"Severity": k, "Count": v} for k, v in sev_counts.items()])
            if HAS_PLOTLY and px:
                fig_pie = px.pie(
                    df_sev,
                    names="Severity",
                    values="Count",
                    color="Severity",
                    color_discrete_map={
                        "CRITICAL": "#f43f5e",
                        "HIGH": "#f97316",
                        "MEDIUM": "#eab308",
                        "LOW": "#38bdf8",
                    },
                    hole=0.55,
                )
                fig_pie.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="#090d16",
                    font=dict(color="#94a3b8"),
                    margin=dict(l=20, r=20, t=30, b=20),
                    height=320,
                )
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.dataframe(df_sev, use_container_width=True)

        st.markdown("<div class='section-header'>High-Priority Forensic Detections</div>", unsafe_allow_html=True)
        if not findings:
            st.success("No multi-event suspicious correlation patterns detected in the current log window.")
        else:
            for f in findings:
                badge_class = f"badge-{f.severity.lower()}"
                with st.expander(f"[{f.severity}] {f.title} (Time: t={f.start_time} - {f.end_time})"):
                    st.markdown(f"<span class='{badge_class}'>{f.severity}</span> &nbsp; <b>Confidence:</b> <code>{f.confidence_level}</code> &nbsp; <b>Category:</b> {f.category}", unsafe_allow_html=True)
                    st.write(f"**Reasoning:** {f.reason}")
                    st.write(f"**Involved Entities:** Hosts: `{', '.join(f.involved_hosts) or 'None'}` | Users: `{', '.join(f.involved_users) or 'None'}`")
                    st.write(f"**Defensive Recommendation:** {f.recommendation}")
                    st.caption(f"Evidence references: {len(f.evidence_sources)} log record(s)")


# ---------------- PAGE 2: UPLOAD & DATA SOURCES ----------------
elif page == "Upload & Data Sources":
    st.markdown("<div class='soc-kicker'>DATA INGESTION PIPELINE</div>", unsafe_allow_html=True)
    st.markdown("<div class='main-title'>Ingestion & Data Source Manager</div>", unsafe_allow_html=True)
    st.markdown("<div class='subtitle'>Memory-safe, streaming ingestion supporting official LANL gzip files, CSV, and JSON.</div>", unsafe_allow_html=True)

    tab_local, tab_synth, tab_upload = st.tabs(["Local Files & LANL Datasets", "Synthetic Incident Generator", "Custom Ingestion (CSV / JSON)"])

    # Ingestion Controls
    st.sidebar.markdown("<div class='soc-telemetry-header'>INGESTION LIMITS</div>", unsafe_allow_html=True)
    max_rows = st.sidebar.number_input("Max records per file", min_value=500, max_value=100000, value=10000, step=1000, help="Prevents RAM exhaustion on 8 GB laptops")
    sample_step = st.sidebar.slider("Sampling Rate (1 in N)", min_value=1, max_value=20, value=1, help="1 = keep all rows. 5 = read 1 row every 5 rows")
    time_filter_active = st.sidebar.checkbox("Filter by Relative Time Window")
    t_min = st.sidebar.number_input("Min relative time (s)", value=0) if time_filter_active else None
    t_max = st.sidebar.number_input("Max relative time (s)", value=500000) if time_filter_active else None

    with tab_local:
        st.subheader("Process Local LANL Files")
        st.markdown(
            "Point to local LANL `.txt.gz` or `.txt` files on disk (e.g. `redteam.txt.gz`, `auth.txt.gz`, etc.)."
        )

        default_path = "redteam.txt.gz" if os.path.exists("redteam.txt.gz") else ""
        file_path_input = st.text_input("Enter local file path or relative name:", value=default_path)

        col_p1, col_p2 = st.columns([1, 1])
        with col_p1:
            forced_type = st.selectbox("LANL File Schema Type", ["Auto-detect", "auth", "proc", "flows", "dns", "redteam"])
        with col_p2:
            append_mode = st.checkbox("Append to existing events", value=False, help="Merge with currently loaded events instead of replacing")

        if st.button("Ingest Local File", type="primary"):
            if not file_path_input or not os.path.exists(file_path_input):
                st.error(f"File not found: '{file_path_input}'. Verify the file exists.")
            else:
                try:
                    with st.spinner(f"Streaming and normalizing {file_path_input}..."):
                        t_start = time.time()
                        ftype = None if forced_type == "Auto-detect" else forced_type
                        records = list(stream_lanl_file(
                            file_path_input,
                            file_type=ftype,
                            max_rows=max_rows,
                            sample_step=sample_step,
                            time_min=t_min,
                            time_max=t_max,
                        ))

                        normalized = [normalize_record(r) for r in records if r]
                        valid_events = [e for e in normalized if e is not None]

                        prov = generate_provenance_record(
                            file_path_input,
                            record_count=len(valid_events),
                            malformed_count=len(records) - len(valid_events),
                            settings={"max_rows": max_rows, "sample_step": sample_step, "time_min": t_min, "time_max": t_max},
                            is_synthetic=False
                        )

                        if append_mode:
                            st.session_state.events.extend(valid_events)
                            st.session_state.provenance.append(prov)
                        else:
                            st.session_state.events = valid_events
                            st.session_state.provenance = [prov]

                        # Apply correlation
                        engine = CorrelationEngine(time_window_seconds=st.session_state.time_window)
                        st.session_state.findings = engine.correlate(st.session_state.events)

                        # Set sampling note
                        if sample_step > 1 or len(valid_events) >= max_rows:
                            st.session_state.sampling_applied = True
                            st.session_state.sampling_note = f"Capped at {max_rows} rows (Sampling 1-in-{sample_step})"
                        else:
                            st.session_state.sampling_applied = False
                            st.session_state.sampling_note = ""

                        elapsed = time.time() - t_start
                        st.success(f"Successfully processed {len(valid_events):,} events from `{file_path_input}` in {elapsed:.2f}s!")
                        st.rerun()

                except Exception as ex:
                    st.error(f"Error parsing file: {str(ex)}")

    with tab_synth:
        st.markdown("<div class='section-header'>Generate & Ingest Synthetic Security Telemetry</div>", unsafe_allow_html=True)
        st.markdown(
            "Creates artificial, schema-accurate LANL logs with realistic attack scenarios (Brute Force, Reconnaissance, Data Exfiltration, and Red Team Ground Truth)."
        )
        if st.button("Generate All 5 Synthetic Log Files & Load", type="primary"):
            with st.spinner("Generating synthetic data in `data/synthetic/`..."):
                syn_dir = Path("data/synthetic")
                files_created = generate_synthetic_dataset(str(syn_dir))
                all_norm = []
                all_provs = []

                for fname, fpath in files_created.items():
                    ft = detect_lanl_file_type(fname)
                    recs = list(stream_lanl_file(fpath, file_type=ft, max_rows=max_rows))
                    norm = [normalize_record(r) for r in recs if r]
                    v_ev = [e for e in norm if e]
                    all_norm.extend(v_ev)
                    all_provs.append(generate_provenance_record(fpath, len(v_ev), 0, {"max_rows": max_rows}, is_synthetic=True))

                st.session_state.events = all_norm
                st.session_state.provenance = all_provs
                engine = CorrelationEngine(time_window_seconds=st.session_state.time_window)
                st.session_state.findings = engine.correlate(all_norm)
                st.session_state.sampling_applied = False
                st.success(f"Generated and loaded {len(all_norm)} synthetic events across 5 log sources!")
                st.rerun()

    with tab_upload:
        st.markdown("<div class='section-header'>Upload Custom CSV or JSON Lines</div>", unsafe_allow_html=True)
        uploaded_file = st.file_uploader("Upload a CSV or JSON file", type=["csv", "json"])
        if uploaded_file is not None:
            if st.button("Parse Uploaded File", type="primary"):
                temp_dir = Path("data/uploads")
                temp_dir.mkdir(parents=True, exist_ok=True)
                save_path = temp_dir / uploaded_file.name
                with open(save_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())

                st.success(f"Uploaded `{uploaded_file.name}`. Ingesting...")
                # Stream file
                if uploaded_file.name.endswith(".json"):
                    recs = list(stream_generic_json(str(save_path), max_rows=max_rows))
                else:
                    ft = detect_lanl_file_type(uploaded_file.name) or "auth"
                    recs = list(stream_lanl_file(str(save_path), file_type=ft, max_rows=max_rows))

                v_events = [normalize_record(r) for r in recs if r]
                v_events = [e for e in v_events if e]
                st.session_state.events.extend(v_events)
                engine = CorrelationEngine(time_window_seconds=st.session_state.time_window)
                st.session_state.findings = engine.correlate(st.session_state.events)
                st.success(f"Ingested {len(v_events)} records from uploaded file!")
                st.rerun()

    st.markdown("---")
    st.markdown("<div class='section-header'>Cryptographic Evidence Chain of Custody</div>", unsafe_allow_html=True)
    if not st.session_state.provenance:
        st.caption("No source files recorded in the current session.")
    else:
        df_prov = pd.DataFrame(st.session_state.provenance)
        st.dataframe(
            df_prov[["filename", "sha256_hash", "record_count", "malformed_count", "is_synthetic", "file_size_bytes"]],
            use_container_width=True
        )


# ---------------- PAGE 3: INCIDENT TIMELINE ----------------
elif page == "Incident Timeline":
    st.markdown("<div class='soc-kicker'>CHRONOLOGICAL RECONSTRUCTION</div>", unsafe_allow_html=True)
    st.markdown("<div class='main-title'>Incident Event Timeline</div>", unsafe_allow_html=True)
    st.markdown("<div class='subtitle'>Chronological reconstruction of normalized events with exact evidence traceability.</div>", unsafe_allow_html=True)

    if not st.session_state.events:
        st.warning("No events loaded. Ingest data from the 'Upload & Data Sources' page.")
    else:
        events = st.session_state.events
        df_ev = events_to_dataframe(events)

        # Timeline Filters
        col_f1, col_f2, col_f3, col_f4 = st.columns(4)
        with col_f1:
            sel_types = st.multiselect("Event Type", options=list(df_ev["event_type"].dropna().unique()), default=[])
        with col_f2:
            all_users = [u for u in df_ev["user"].dropna().unique() if u]
            sel_user = st.selectbox("Filter by User", ["All"] + all_users)
        with col_f3:
            all_hosts = list(set(df_ev["src_host"].dropna().unique()) | set(df_ev["dst_host"].dropna().unique()))
            sel_host = st.selectbox("Filter by Host", ["All"] + all_hosts)
        with col_f4:
            ground_truth_only = st.checkbox("Show Red Team Ground Truth Only")

        # Filter DataFrame
        filtered_df = df_ev.copy()
        if sel_types:
            filtered_df = filtered_df[filtered_df["event_type"].isin(sel_types)]
        if sel_user != "All":
            filtered_df = filtered_df[filtered_df["user"] == sel_user]
        if sel_host != "All":
            filtered_df = filtered_df[(filtered_df["src_host"] == sel_host) | (filtered_df["dst_host"] == sel_host)]
        if ground_truth_only:
            filtered_df = filtered_df[filtered_df["is_ground_truth"] == True]

        st.caption(f"Displaying **{len(filtered_df):,}** of **{len(df_ev):,}** records.")

        # Interactive Timeline Chart
        if not filtered_df.empty:
            if HAS_PLOTLY and px:
                fig_time = px.scatter(
                    filtered_df.head(2000),  # Limit to 2000 markers for fluid browser rendering
                    x="timestamp",
                    y="action",
                    color="event_type",
                    hover_data=["user", "src_host", "dst_host", "source_file", "line_number"],
                    title="Event Occurrences Along Relative Seconds Timeline",
                    color_discrete_sequence=px.colors.qualitative.Dark24,
                )
                fig_time.update_layout(
                    template="plotly_dark",
                    xaxis_title="Relative Time (Seconds)",
                    yaxis_title="Action Taken",
                    paper_bgcolor="#090d16",
                    plot_bgcolor="#090d16",
                    font=dict(color="#94a3b8"),
                    height=360,
                )
                st.plotly_chart(fig_time, use_container_width=True)
            else:
                st.line_chart(filtered_df.set_index("timestamp")["action"].value_counts())

        st.markdown("<div class='section-header'>Evidentiary Event Log Table</div>", unsafe_allow_html=True)
        st.dataframe(
            filtered_df[[
                "event_id", "timestamp", "event_type", "action", "user",
                "src_host", "dst_host", "process_name", "source_file", "line_number"
            ]].sort_values(by=["timestamp", "line_number"]),
            use_container_width=True,
            height=380,
        )

        st.markdown("<div class='section-header'>Raw Evidence Record Inspector</div>", unsafe_allow_html=True)
        inspect_id = st.text_input("Enter `event_id` (e.g. `auth.txt.gz:5`) to inspect raw underlying line:", "")
        if inspect_id:
            matched = next((e for e in events if e.event_id == inspect_id), None)
            if matched:
                st.json(matched.to_dict())
                st.code(matched.raw_line, language="text")
            else:
                st.warning("No event found matching that ID.")


# ---------------- PAGE 4: EVIDENCE GRAPH ----------------
elif page == "Evidence Graph":
    st.markdown("<div class='soc-kicker'>INTERACTION TOPOLOGY</div>", unsafe_allow_html=True)
    st.markdown("<div class='main-title'>Forensic Entity Relationship Graph</div>", unsafe_allow_html=True)
    st.markdown("<div class='subtitle'>Evidence-backed interaction mapping between users, hosts, and processes.</div>", unsafe_allow_html=True)

    if not st.session_state.events:
        st.warning("No events loaded. Load data to visualize the graph.")
    else:
        events = st.session_state.events

        col_g1, col_g2 = st.columns([2, 1])
        with col_g1:
            focus_search = st.text_input("Filter/Focus on specific entity (e.g. `C553` or `U999`):", "")
        with col_g2:
            max_nodes_graph = st.slider("Max Entities in View", min_value=20, max_value=200, value=80, step=10, help="Prevents lag on 8 GB RAM machines")

        with st.spinner("Generating entity graph..."):
            builder = EvidenceGraphBuilder(max_nodes=max_nodes_graph)
            g = builder.build_graph(events, focus_entity=focus_search if focus_search else None)
            if HAS_PLOTLY:
                fig_g = builder.render_plotly()
                st.plotly_chart(fig_g, use_container_width=True)
            else:
                st.info("Interactive visual graph rendering is available when Plotly is loaded. Displaying entity connections:")
                degrees = [{"Entity": n, "Type": g.nodes[n].get("node_type", "Entity"), "Degree Connections": g.degree(n)} for n in g.nodes]
                st.dataframe(pd.DataFrame(degrees).sort_values(by="Degree Connections", ascending=False), use_container_width=True)

        st.markdown("""
        <div class="soc-airgap-box" style="margin-top: 10px;">
            <b>Graph Legend:</b> Blue = Users &bull; Teal = Hosts &bull; Purple = Processes &bull; Red = Confirmed Ground Truth. Hover over any node to inspect degree connections.
        </div>
        """, unsafe_allow_html=True)


# ---------------- PAGE 5: ANOMALY ANALYSIS ----------------
elif page == "Anomaly Analysis":
    st.markdown("<div class='soc-kicker'>STATISTICAL BEHAVIORAL SCORING</div>", unsafe_allow_html=True)
    st.markdown("<div class='main-title'>Machine Learning Behavioral Anomaly Radar</div>", unsafe_allow_html=True)
    st.markdown("<div class='subtitle'>Scikit-Learn Isolation Forest baseline features used strictly as triage prioritization signals.</div>", unsafe_allow_html=True)

    if not st.session_state.events:
        st.warning("No events loaded.")
    else:
        st.markdown("""
        <div class="soc-airgap-box" style="margin-bottom: 16px; border-color: rgba(234, 179, 8, 0.3);">
            <b>Forensic Notice:</b> Statistical anomaly scores highlight behavioral outliers compared to peers in the log sample. They <b>DO NOT</b> represent confirmed compromise or evidence of guilt.
        </div>
        """, unsafe_allow_html=True)

        detector = EntityAnomalyDetector(contamination=0.05)
        with st.spinner("Computing behavioral vectors and fitting Isolation Forest..."):
            df_anom = detector.fit_predict(st.session_state.events)

        if df_anom.empty:
            st.warning("No entities with sufficient behavioral telemetry to score.")
        else:
            col_a1, col_a2 = st.columns([1.5, 1])
            with col_a1:
                st.markdown("<div class='section-header'>Entity Anomaly Rankings</div>", unsafe_allow_html=True)
                st.dataframe(
                    df_anom[[
                        "entity_id", "anomaly_score", "is_anomaly", "primary_factor",
                        "failed_auth_count", "success_auth_count", "unique_destinations", "total_bytes_transferred"
                    ]],
                    use_container_width=True,
                    height=360,
                )

            with col_a2:
                st.markdown("<div class='section-header'>Anomaly Score Distribution</div>", unsafe_allow_html=True)
                if HAS_PLOTLY and px:
                    fig_hist = px.histogram(
                        df_anom,
                        x="anomaly_score",
                        color="is_anomaly",
                        nbins=15,
                        title="Distribution of Entity Anomaly Scores",
                        color_discrete_map={True: "#f43f5e", False: "#38bdf8"}
                    )
                    fig_hist.update_layout(
                        template="plotly_dark",
                        paper_bgcolor="#090d16",
                        plot_bgcolor="#090d16",
                        font=dict(color="#94a3b8"),
                        height=320
                    )
                    st.plotly_chart(fig_hist, use_container_width=True)
                else:
                    st.bar_chart(df_anom["is_anomaly"].value_counts())


# ---------------- PAGE 6: INVESTIGATION STORY ----------------
elif page == "Investigation Story":
    st.markdown("<div class='soc-kicker'>NARRATIVE ASSEMBLY & REPORTING</div>", unsafe_allow_html=True)
    st.markdown("<div class='main-title'>Evidence-Grounded Investigation Story Builder</div>", unsafe_allow_html=True)
    st.markdown("<div class='subtitle'>Deterministic forensic narrative assembling verified evidence, hypotheses, and defensive actions.</div>", unsafe_allow_html=True)

    if not st.session_state.events:
        st.warning("No events available to build an investigation story.")
    else:
        analyst_notes_input = st.text_area(
            "Case / Analyst Notes (Optional):",
            placeholder="e.g. Investigating alert triggered by target workstation C553 on LAN segment 2."
        )

        builder = StoryBuilder(analyst_notes=analyst_notes_input)
        report = builder.build_report(
            events=st.session_state.events,
            findings=st.session_state.findings,
            provenance_records=st.session_state.provenance,
        )

        md_report = builder.render_markdown(report)

        st.markdown("---")
        st.markdown(md_report)

        st.markdown("---")
        st.markdown("<div class='section-header'>Investigation Artifacts & Evidence Export</div>", unsafe_allow_html=True)
        st.caption("Download signed forensic artifacts or export directly to the local reports directory.")

        # Prepare all export payloads
        try:
            pdf_bytes = generate_pdf_forensic_report(report)
        except Exception as pdf_err:
            pdf_bytes = None
            st.error(f"PDF generation note: {pdf_err}")

        html_report = generate_html_forensic_report(report)
        json_str = export_report_to_json(report)
        df_all = events_to_dataframe(st.session_state.events)
        safe_csv = safe_dataframe_to_csv(df_all)

        def make_b64_btn(data: bytes | str, filename: str, label: str, mime: str, ext_tag: str) -> str:
            raw = data.encode("utf-8") if isinstance(data, str) else data
            b64_val = base64.b64encode(raw).decode("ascii")
            return (
                f'<a href="data:{mime};base64,{b64_val}" download="{filename}" class="soc-download-btn">'
                f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.75rem;padding:2px 6px;border-radius:4px;background:rgba(56,189,248,0.15);color:#38bdf8;margin-right:8px;font-weight:700;">{ext_tag}</span>'
                f'{label}'
                f'</a>'
            )

        col_ex1, col_ex2, col_ex3, col_ex4 = st.columns(4)

        with col_ex1:
            if pdf_bytes:
                st.markdown(
                    make_b64_btn(pdf_bytes, "tracemind_forensic_report.pdf", "PDF Forensic Report", "application/pdf", "PDF"),
                    unsafe_allow_html=True,
                )
            else:
                st.button("PDF Unavailable", disabled=True, use_container_width=True)

        with col_ex2:
            st.markdown(
                make_b64_btn(html_report, "tracemind_forensic_report.html", "HTML Interactive Report", "text/html", "HTML"),
                unsafe_allow_html=True,
            )

        with col_ex3:
            st.markdown(
                make_b64_btn(json_str, "tracemind_investigation_report.json", "JSON Evidence Graph", "application/json", "JSON"),
                unsafe_allow_html=True,
            )

        with col_ex4:
            st.markdown(
                make_b64_btn(safe_csv, "tracemind_normalized_events.csv", "CSV Normalized Logs", "text/csv", "CSV"),
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

        # Direct Local Disk Save Option
        col_save_btn, col_save_info = st.columns([1.3, 2.7])
        with col_save_btn:
            if st.button("Save All Reports to 'reports/' Folder", use_container_width=True):
                rep_dir = Path("reports")
                rep_dir.mkdir(parents=True, exist_ok=True)
                if pdf_bytes:
                    (rep_dir / "tracemind_forensic_report.pdf").write_bytes(pdf_bytes)
                (rep_dir / "tracemind_forensic_report.html").write_text(html_report, encoding="utf-8")
                (rep_dir / "tracemind_investigation_report.json").write_text(json_str, encoding="utf-8")
                (rep_dir / "tracemind_normalized_events.csv").write_text(safe_csv, encoding="utf-8")
                st.session_state["reports_saved"] = True

        with col_save_info:
            if st.session_state.get("reports_saved"):
                abs_rep = Path("reports").resolve()
                st.success(f"Artifacts successfully written to disk: `{abs_rep}`")
            else:
                st.caption("Writes all 4 files (.pdf, .html, .json, .csv) directly to disk in D:\\New folder\\reports\\.")


# ---------------- PAGE 7: SETTINGS & DATASET GUIDE ----------------
elif page == "Settings & Dataset Guide":
    st.markdown("<div class='soc-kicker'>CONFIGURATION & REFERENCE</div>", unsafe_allow_html=True)
    st.markdown("<div class='main-title'>Settings & Dataset Architecture Guide</div>", unsafe_allow_html=True)

    st.markdown("<div class='section-header'>Correlation Engine Settings</div>", unsafe_allow_html=True)
    new_window = st.slider(
        "Temporal Correlation Window (Seconds)",
        min_value=30,
        max_value=3600,
        value=st.session_state.time_window,
        step=30,
        help="Maximum time delta between multi-stage actions (e.g., login to process execution) to link them into an incident finding."
    )
    if new_window != st.session_state.time_window:
        st.session_state.time_window = new_window
        engine = CorrelationEngine(time_window_seconds=new_window)
        st.session_state.findings = engine.correlate(st.session_state.events)
        st.success(f"Updated correlation window to {new_window} seconds. Recorrelated findings.")

    st.markdown("---")
    st.subheader("LANL Cyber-Security Dataset Reference")
    st.markdown("""
    The official Los Alamos National Laboratory (LANL) dataset consists of 5 files:
    - `auth.txt.gz`: Authentication events (`time, src_user, dst_user, src_host, dst_host, auth_type, logon_type, auth_orientation, status`)
    - `proc.txt.gz`: Process start/stop (`time, user, host, process_name, action`)
    - `flows.txt.gz`: Network socket flows (`time, duration, src_host, src_port, dst_host, dst_port, protocol, packet_count, byte_count`)
    - `dns.txt.gz`: Host lookup resolutions (`time, src_host, resolved_host`)
    - `redteam.txt.gz`: Ground truth penetration tester events (`time, user, src_host, dst_host`)

    **Official Website**: [https://csr.lanl.gov/data/cyber1/](https://csr.lanl.gov/data/cyber1/)
    """)
