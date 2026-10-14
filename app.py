"""Streamlit chat interface for the local-first OpsPilot incident assistant."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pandas as pd
import streamlit as st

from opspilot.conversation import answer_follow_up, build_incident_answer, looks_like_log_input
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

st.set_page_config(page_title=os.getenv("OPSPILOT_TITLE", "OpsPilot AI"), page_icon="🛰️", layout="centered")

st.markdown(
    """
    <style>
      :root { --ink: #172033; --muted: #69758a; --line: #e7ebf2; --accent: #4f6ef7; }
      .block-container { max-width: 920px; padding-top: 1.8rem; padding-bottom: 7rem; }
      [data-testid="stSidebar"] { background: #f6f8fc; border-right: 1px solid #e7ebf2; }
      [data-testid="stChatMessage"] { border: 1px solid #edf0f5; border-radius: 18px; padding: 1rem 1.1rem; margin-bottom: .8rem; }
      [data-testid="stChatMessage"]:has([data-testid="stMarkdownContainer"] h3) { background: #fff; }
      [data-testid="stChatInput"] { border-radius: 18px; }
      .opspilot-eyebrow { color: #50617d; font-size: .82rem; letter-spacing: .08em; text-transform: uppercase; font-weight: 700; }
      .opspilot-note { color: #69758a; font-size: .88rem; }
      div[data-testid="stMetric"] { background: #f7f9fd; border: 1px solid #ebeff5; border-radius: 14px; padding: .8rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def load_sample(filename: str) -> str:
    return (PROJECT_DIR / "sample_logs" / filename).read_text(encoding="utf-8")


def _event_table(result: AnalysisResult) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Line": event.line_number,
                "Timestamp": event.timestamp.isoformat(sep=" ") if event.timestamp else "—",
                "Severity": event.severity,
                "Service": event.service,
                "Message": event.message,
            }
            for event in result.events
        ]
    )


def _new_conversation() -> None:
    st.session_state.messages = []
    st.session_state.active_result = None


def _process_message(text: str, files=(), sample_label: str | None = None) -> None:
    filenames = [getattr(file, "name", "uploaded log") for file in files]
    if sample_label:
        filenames = [f"Sample: {sample_label}"]

    if files:
        log_text = "\n".join(file.getvalue().decode("utf-8-sig", errors="replace") for file in files)
    elif sample_label:
        log_text = load_sample(SAMPLES[sample_label])
    else:
        log_text = text

    user_text = text.strip()
    if not user_text:
        if sample_label:
            user_text = f"Investigate the {sample_label} sample logs."
        elif filenames:
            user_text = "Investigate the attached log file(s)."

    st.session_state.messages.append(
        {"role": "user", "content": user_text, "attachments": filenames}
    )

    if files or sample_label or looks_like_log_input(log_text):
        with st.spinner("Reading events and checking for incident signals…"):
            result = analyze_log_text(log_text)
        st.session_state.active_result = result
        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": build_incident_answer(result),
                "result": result,
                "sources": filenames,
            }
        )
        return

    previous = st.session_state.get("active_result")
    response = answer_follow_up(text, previous) if previous else (
        "I can investigate application logs locally. Use the **+** button to attach `.log`, `.txt`, `.json`, `.jsonl`, or `.csv` files, "
        "or paste log lines into the message box. You can also start with one of the sample incidents above.\n\n"
        "Once logs are analyzed, ask follow-ups like **What is the leading cause?**, **Show the error evidence**, or **What should I check next?**"
    )
    st.session_state.messages.append({"role": "assistant", "content": response})


def _render_result(result: AnalysisResult, sources: list[str]) -> None:
    if sources:
        source_text = ", ".join(sources)
        st.caption(f"Analyzed: {source_text}")
        if len(sources) > 1:
            st.caption("Evidence line numbers refer to the combined uploaded files.")

    st.markdown(result.assessment)
    context = result.context
    warning_count = sum(event.severity == "WARN" for event in result.events)
    metrics = st.columns(4)
    metrics[0].metric("Events", len(result.events))
    metrics[1].metric("Errors", result.error_count)
    metrics[2].metric("Warnings", warning_count)
    metrics[3].metric("Services", len(context.affected_services) if context else 0)

    if result.hypotheses:
        lead = result.hypotheses[0]
        st.markdown(f"**Leading hypothesis:** {lead.summary}")
        st.caption(
            f"Rule evidence score: {lead.confidence:.0%} · Related services: "
            f"{', '.join(lead.related_services) or 'not identified'}"
        )
        st.caption("This score reflects matching rules and corroborating log evidence; it is not a calibrated probability.")
        with st.expander("Why OpsPilot ranked this first", expanded=True):
            for evidence in lead.evidence[:4]:
                st.markdown(f"- {evidence}")
    elif result.findings:
        st.markdown("**Signal found, but no specific cause is established yet.**")
        for finding in result.findings[:3]:
            st.markdown(f"- **{finding.title}:** {finding.description}")
    else:
        st.info("No configured fault signature matched. Check that the log window covers the incident and compare it with a healthy baseline.")

    if result.recommendations:
        with st.expander("Suggested next checks · read-only", expanded=True):
            for action in result.recommendations[:2]:
                st.markdown(f"**{action.title}** — {action.rationale}")
                for step in action.steps:
                    st.markdown(f"- {step}")
                st.caption(f"Caution: {action.caution}")

    with st.expander("View findings and normalized events"):
        if result.findings:
            st.markdown("**Detected signals**")
            for finding in result.findings:
                st.markdown(f"- **{finding.title}** · {finding.confidence:.0%} rule match — {finding.description}")
        if result.events:
            st.markdown("**Parsed events**")
            st.dataframe(_event_table(result), width="stretch", hide_index=True)
        if context and context.clusters:
            st.markdown("**Correlated time windows**")
            for cluster in context.clusters:
                st.caption(cluster)

    report = build_markdown_report(result)
    digest = hashlib.sha1(report.encode("utf-8")).hexdigest()[:8]
    st.download_button(
        "⬇️ Download incident report",
        data=report,
        file_name=f"opspilot-incident-report-{digest}.md",
        mime="text/markdown",
        key=f"report-{digest}",
    )
    st.caption("Suggestions only. OpsPilot never executes commands or changes infrastructure.")


st.markdown('<div class="opspilot-eyebrow">LOCAL INCIDENT RESPONSE ASSISTANT</div>', unsafe_allow_html=True)
st.title("OpsPilot AI")
st.caption("Investigate application logs, follow the evidence, and decide what to check next.")

with st.sidebar:
    st.markdown("## 🛰️ OpsPilot")
    st.caption("Your incident workspace")
    if st.button("＋  New investigation", use_container_width=True):
        _new_conversation()
        st.rerun()
    st.divider()
    st.markdown("**How it works**")
    st.caption("Parse → detect → correlate → rank → explain")
    st.caption("Runs locally with transparent rules. No paid AI API; no infrastructure actions.")
    st.divider()
    st.markdown("**Privacy**")
    st.caption("Logs are analyzed in this app session and are not sent to an AI provider or saved as incident history.")

st.session_state.setdefault("messages", [])
st.session_state.setdefault("active_result", None)

if not st.session_state.messages:
    st.markdown("### Start with a log or a sample incident")
    st.markdown(
        '<p class="opspilot-note">Attach files with <b>＋</b>, paste logs below, or try a realistic incident. '
        "After analysis, ask questions in plain language about the evidence.</p>",
        unsafe_allow_html=True,
    )
    selected_sample = st.selectbox("Try a sample", tuple(SAMPLES), label_visibility="collapsed")
    if st.button("Investigate sample", type="secondary"):
        _process_message("", sample_label=selected_sample)
        st.rerun()

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        if message["role"] == "user" and message.get("attachments"):
            st.caption("📎 " + " · ".join(message["attachments"]))
        if message.get("result"):
            _render_result(message["result"], message.get("sources", []))
        else:
            st.markdown(message["content"])

submission = st.chat_input(
    "Ask about an incident, paste logs, or use + to attach files…",
    accept_file="multiple",
    file_type=["log", "txt", "json", "jsonl", "csv"],
)
if submission:
    prompt_text = submission.text.strip()
    uploaded = submission.files
    _process_message(prompt_text, uploaded)
    st.rerun()
