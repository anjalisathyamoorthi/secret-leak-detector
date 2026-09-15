"""Streamlit Dashboard for Secret Leak Detector team compliance tracking."""

import os
import sys
import datetime
import pandas as pd
import requests
import streamlit as st
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reports.export import generate_csv_report

API_URL = os.getenv("SECRET_DETECTOR_API_URL", "http://127.0.0.1:8000/api")

st.set_page_config(
    page_title="Secret Leak Detector Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ Secret Leak Detector Compliance Dashboard")
st.caption("Real-time team security monitoring, pre-commit compliance, and secret exposure mitigation.")


def fetch_api(endpoint: str):
    """Helper to fetch JSON data from backend API with error handling."""
    try:
        res = requests.get(f"{API_URL}/{endpoint}", timeout=3.0)
        if res.status_code == 200:
            return res.json()
    except Exception as e:
        st.sidebar.error(f"Backend API connection error ({endpoint}): {e}")
    return None


# Sidebar Navigation / System Info
st.sidebar.title("Navigation")
page = st.sidebar.radio("Select View", ["Overview", "Findings", "Repositories", "Reports"])

st.sidebar.markdown("---")
st.sidebar.markdown("### API Connection")
st.sidebar.code(API_URL, language="text")
if st.sidebar.button("Refresh Data"):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.info("🔐 Plaintext secrets are never stored or displayed. Only SHA-256 fingerprints and masked strings are retained.")

# ==================== PAGE 1: OVERVIEW ====================
if page == "Overview":
    st.header("📊 Compliance Overview")

    metrics = fetch_api("metrics")
    if not metrics:
        st.warning("Backend API is currently offline. Start the backend server (`python -m uvicorn backend.main:app --port 8000`) to view real-time metrics.")
        st.stop()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Repositories Scanned", metrics["repositories_scanned"])
    with col2:
        st.metric("Total Scans Run", metrics["total_scans"])
    with col3:
        st.metric("Open Findings", metrics["open_findings"], delta=-metrics["open_findings"], delta_color="inverse")
    with col4:
        st.metric("Critical / High Findings", metrics["critical_findings"], delta=-metrics["critical_findings"], delta_color="inverse")

    st.markdown("---")

    col5, col6, col7, col8 = st.columns(4)
    with col5:
        st.metric("Blocked Commits", metrics["blocked_commits"])
    with col6:
        st.metric("Resolved Findings", metrics["resolved_findings"])
    with col7:
        comp_score = metrics["compliance_percentage"]
        st.metric("Team Compliance", f"{comp_score:.1f}%")
    with col8:
        st.metric("Bypasses Logged", metrics["bypasses_count"])

    st.markdown("---")

    st.subheader("🛡️ Team Security Posture")
    st.progress(metrics["compliance_percentage"] / 100.0)
    st.caption("Compliance % formula: `(Scans with 0 HIGH/CRITICAL findings / Total Scans) * 100`")

# ==================== PAGE 2: FINDINGS ====================
elif page == "Findings":
    st.header("🚨 Leaked Secret Findings")

    findings = fetch_api("findings")
    if findings is None:
        st.warning("Unable to connect to backend API.")
        st.stop()

    if not findings:
        st.success("No leaked secret findings recorded yet. Codebase is clean!")
        st.stop()

    df = pd.DataFrame(findings)

    # Filter Controls
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        status_filter = st.selectbox("Filter by Status", ["All", "open", "resolved", "false_positive"])
    with col_f2:
        severity_filter = st.selectbox("Filter by Severity", ["All", "critical", "high", "medium", "low"])

    filtered_df = df.copy()
    if status_filter != "All":
        filtered_df = filtered_df[filtered_df["status"] == status_filter]
    if severity_filter != "All":
        filtered_df = filtered_df[filtered_df["severity"] == severity_filter]

    st.subheader(f"Matching Findings ({len(filtered_df)})")

    # Display Data Table
    display_cols = ["id", "scan_id", "file_path", "line_number", "rule_id", "severity", "masked_value", "status", "created_at"]
    available_cols = [c for c in display_cols if c in filtered_df.columns]
    
    st.dataframe(filtered_df[available_cols], use_container_width=True)

    st.markdown("---")
    st.subheader("⚙️ Update Finding Status")

    finding_options = {f"{r['id']} - {r['rule_id']} in {r['file_path']}:{r['line_number']} [{r['severity'].upper()}]": r['id'] for _, r in filtered_df.iterrows()}
    
    if finding_options:
        selected_label = st.selectbox("Select Finding to Update", list(finding_options.keys()))
        selected_id = finding_options[selected_label]
        
        col_act1, col_act2 = st.columns(2)
        with col_act1:
            if st.button("Mark as Resolved"):
                res = requests.patch(f"{API_URL}/findings/{selected_id}", json={"status": "resolved", "reason": "Manually resolved via dashboard"})
                if res.status_code == 200:
                    st.success(f"Finding #{selected_id} marked as Resolved!")
                    st.rerun()
                else:
                    st.error("Failed to update finding status.")
        with col_act2:
            if st.button("Mark as False Positive"):
                res = requests.patch(f"{API_URL}/findings/{selected_id}", json={"status": "false_positive", "reason": "Marked false positive via dashboard"})
                if res.status_code == 200:
                    st.success(f"Finding #{selected_id} marked as False Positive!")
                    st.rerun()
                else:
                    st.error("Failed to update finding status.")

# ==================== PAGE 3: REPOSITORIES ====================
elif page == "Repositories":
    st.header("📁 Monitored Repositories")

    repos = fetch_api("repositories")
    scans = fetch_api("scans")

    if repos is None:
        st.warning("Unable to fetch repositories from backend API.")
        st.stop()

    if not repos:
        st.info("No repositories registered yet. Perform a scan or commit to auto-register repositories.")
        st.stop()

    repos_df = pd.DataFrame(repos)
    st.dataframe(repos_df, use_container_width=True)

    st.markdown("---")
    st.subheader("📜 Recent Scan History")
    if scans:
        scans_df = pd.DataFrame(scans)
        st.dataframe(scans_df, use_container_width=True)
    else:
        st.info("No scan history available.")

# ==================== PAGE 4: REPORTS ====================
elif page == "Reports":
    st.header("📈 Compliance Reports & Data Export")

    reports_data = fetch_api("reports")
    if reports_data is None:
        st.warning("Unable to fetch reports data.")
        st.stop()

    st.subheader("📥 Export Findings to CSV")
    csv_content = generate_csv_report(reports_data)
    
    st.download_button(
        label="Download CSV Report",
        data=csv_content,
        file_name=f"secret_leak_findings_{datetime.date.today().isoformat()}.csv",
        mime="text/csv"
    )

    st.markdown("---")
    st.subheader("📊 Findings Trend Over Time")

    if reports_data:
        df = pd.DataFrame(reports_data)
        if "created_at" in df.columns and not df.empty:
            df["date"] = pd.to_datetime(df["created_at"]).dt.date
            trend_df = df.groupby(["date", "severity"]).size().unstack(fill_value=0)
            st.line_chart(trend_df)
        else:
            st.info("Insufficient timeline data for trends.")
    else:
        st.info("No findings data available to display trend chart.")
