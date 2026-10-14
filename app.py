"""Streamlit entry point for the OpsPilot AI dashboard."""

from __future__ import annotations

import os
import hashlib
from pathlib import Path

import pandas as pd
import streamlit as st

from opspilot.models import AnalysisResult
from opspilot.pipeline import analyze_log_text
from opspilot.reporter import build_markdown_report

PROJECT_DIR = Path(__file__).parent
SAMPLES = {
    "Checkout API · database outage": "checkout-service.log",
    "Payments API · expired TLS certificate": "payments-tls.log",
    "Invoice worker · queue backlog": "worker-queue.log",
    "Catalog API · disk pressure": "catalog-storage.log",
}

st.set_page_config(page_title=os.getenv("OPSPILOT_TITLE", "OpsPilot AI"), page_icon="🛰️", layout="wide")


@st.cache_data
def load_sample(filename: str = "checkout-service.log") -> str:
    return (PROJECT_DIR / "sample_logs" / filename).read_text(encoding="utf-8")


def _event_table(result: AnalysisResult) -> pd.DataFrame:
    return pd.DataFrame([
        {
            "Line": event.line_number,
            "Timestamp": event.timestamp.isoformat(sep=" ") if event.timestamp else "-",
            "Severity": event.severity,
            "Service": event.service,
            "Message": event.message,
        }
        for event in result.events
    ])


def _render_context(result: AnalysisResult) -> None:
    context = result.context
    if not context:
        st.info("No incident context could be built from the supplied logs.")
        return
    warning_count = sum(event.severity == "WARN" for event in result.events)
    cols = st.columns(4)
    cols[0].metric("Parsed events", context.event_count)
    cols[1].metric("Error events", context.error_count)
    cols[2].metric("Warnings", warning_count)
    cols[3].metric("Services", len(context.affected_services))
    duration = f"{context.duration_seconds:.0f}s" if context.start else "n/a"
    if context.start:
        st.caption(f"Observed time window: {duration}")
    else:
        without_time = sum(event.timestamp is None for event in result.events)
        st.caption(f"Timestamps were not recognized on {without_time} event(s); findings still use message and severity evidence.")
    st.write("**Affected services:** " + (", ".join(context.affected_services) or "unknown"))
    if context.clusters:
        st.write("**Correlated event clusters:**")
        for cluster in context.clusters:
            st.caption(cluster)


def _render_findings(result: AnalysisResult) -> None:
    if not result.findings:
        st.success("No configured error pattern or statistical anomaly matched this log window.")
        return
    for finding in result.findings:
        with st.expander(f"{finding.title} · {finding.confidence:.0%} confidence"):
            st.write(finding.description)
            if finding.event_lines:
                st.caption("Evidence lines: " + ", ".join(str(line) for line in finding.event_lines))
            for evidence in finding.evidence:
                st.write("- " + evidence)


def _render_hypotheses(result: AnalysisResult) -> None:
    if not result.hypotheses:
        st.info("No ranked hypothesis was generated. Add more structured or error-level context.")
        return
    for index, hypothesis in enumerate(result.hypotheses, start=1):
        st.subheader(f"{index}. {hypothesis.summary}")
        cols = st.columns(3)
        cols[0].metric("Confidence", f"{hypothesis.confidence:.0%}")
        cols[1].metric("Evidence score", f"{hypothesis.score:.1f}/100")
        cols[2].metric("Services", ", ".join(hypothesis.related_services) or "unknown")
        st.write("**Why it is ranked:**")
        for evidence in hypothesis.evidence:
            st.write("- " + evidence)


def _render_actions(result: AnalysisResult) -> None:
    st.info("These are investigation suggestions only. OpsPilot never runs commands or changes infrastructure.")
    if not result.recommendations:
        st.write("No action recommendation was generated.")
        return
    for action in result.recommendations:
        with st.expander(action.title, expanded=True):
            st.write(action.rationale)
            for step in action.steps:
                st.write("- " + step)
            st.warning(action.caution)


st.title("🛰️ OpsPilot AI")
st.caption("Local-first application log investigation for calm, evidence-based incident response")

with st.sidebar:
    st.header("Investigation input")
    source = st.radio("Log source", ("Load bundled sample", "Paste logs", "Upload file"))
    st.divider()
    st.markdown("**Pipeline**")
    st.caption("Parse → detect → correlate → rank → recommend → report")
    st.caption("Rules and statistics are transparent; no paid API is used.")

if source == "Load bundled sample":
    selected_sample = st.selectbox("Choose a sample incident", tuple(SAMPLES))
    log_text = load_sample(SAMPLES[selected_sample])
    st.info(f"Loaded sample: {selected_sample}. Switch the input type to analyze your own logs.")
elif source == "Upload file":
    upload = st.file_uploader(
        "Choose a log file",
        help="Text-based logs are accepted in plain text, JSON/JSONL, or CSV formats. File extensions are not restricted.",
    )
    log_text = upload.getvalue().decode("utf-8-sig", errors="replace") if upload else ""
    if not upload:
        st.warning("Upload a .log, .txt, or JSON-lines file to begin.")
else:
    log_text = st.text_area(
        "Paste application logs",
        placeholder="Paste any text-based application, web-server, container, or system logs here...",
        height=260,
    )

if st.button("Analyze incident", type="primary", disabled=not bool(log_text.strip())):
    with st.spinner("Parsing and correlating log evidence..."):
        st.session_state["analysis"] = analyze_log_text(log_text)
        st.session_state["analysis_digest"] = hashlib.sha256(log_text.encode("utf-8", errors="replace")).hexdigest()

current_digest = hashlib.sha256(log_text.encode("utf-8", errors="replace")).hexdigest() if log_text else ""
result = st.session_state.get("analysis") if st.session_state.get("analysis_digest") == current_digest else None
if result:
    st.divider()
    _render_context(result)
    st.subheader("OpsPilot assessment")
    st.info(result.assessment)
    tabs = st.tabs(["Overview", "Events", "Findings", "Root causes", "Safe actions", "Report"])
    with tabs[0]:
        st.subheader("Investigation overview")
        st.write("The assessment above summarizes what the supplied logs show and how strong the leading evidence is.")
        if result.hypotheses:
            st.success(f"Top lead: {result.hypotheses[0].summary} ({result.hypotheses[0].confidence:.0%} confidence)")
        else:
            st.info("There is not enough evidence for a ranked lead yet.")
    with tabs[1]:
        st.subheader("Normalized log events")
        st.dataframe(_event_table(result), width="stretch", hide_index=True)
    with tabs[2]:
        st.subheader("Transparent findings")
        _render_findings(result)
    with tabs[3]:
        st.subheader("Ranked root-cause hypotheses")
        _render_hypotheses(result)
    with tabs[4]:
        st.subheader("Safe recommended actions")
        _render_actions(result)
    with tabs[5]:
        st.subheader("Download incident report")
        report = build_markdown_report(result)
        st.download_button(
            "Download Markdown report",
            data=report,
            file_name="opspilot-incident-report.md",
            mime="text/markdown",
        )
        st.code(report, language="markdown")
else:
    st.markdown("### Start an investigation")
    st.write("Load the bundled incident, paste any text logs, or upload a text-based log file. Then select **Analyze incident** for an evidence-backed assessment.")

