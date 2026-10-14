"""End-to-end incident analysis orchestration."""

from __future__ import annotations

from collections import Counter

from .actions import recommend_actions
from .correlator import correlate_events
from .detector import detect_findings
from .ml_model import predict_cause_hypotheses
from .models import AnalysisResult
from .parser import parse_log_text
from .ranker import rank_hypotheses


def _build_assessment(events, findings, hypotheses) -> str:
    if not events:
        return "No non-empty log lines were found. Paste text logs or upload a text-based log file to start an investigation."

    errors = sum(event.is_error for event in events)
    warnings = sum(event.severity == "WARN" for event in events)
    services = Counter(event.service for event in events if event.service != "unknown")
    service_text = f" Most events are labeled as {services.most_common(1)[0][0]}." if services else " No service name could be identified, so the analysis uses the log messages directly."

    if hypotheses:
        top = hypotheses[0]
        line_evidence = [item for item in top.evidence if item.startswith("Line ")]
        example = f" Example evidence: {line_evidence[0]}." if line_evidence else ""
        method = "trained-model signal" if top.method == "model" else "rule-based signal"
        score = "model match score" if top.method == "model" else "evidence score"
        return (
            f"Read {len(events)} log entries: {errors} error-level and {warnings} warning-level. "
            f"The strongest {method} is: {top.summary} ({top.confidence:.0%} {score}).{example}"
            f" Treat this as a lead to validate against metrics, traces, and recent changes.{service_text}"
        )

    if errors:
        return (
            f"Read {len(events)} log entries and found {errors} error-level event(s), but the current patterns could not classify them. "
            f"Start with the error evidence in the Findings tab and add service, request, and time context.{service_text}"
        )
    if warnings:
        return (
            f"Read {len(events)} log entries and found {warnings} warning-level event(s), with no specific fault pattern. "
            f"Compare their rate and timing with a known healthy window.{service_text}"
        )
    return (
        f"Read {len(events)} log entries. No explicit error or configured fault pattern was found in this window. "
        f"Check that the selected time range overlaps the issue, then compare these events with a healthy baseline.{service_text}"
    )


def analyze_log_text(text: str) -> AnalysisResult:
    """Run the complete local-first analysis pipeline."""

    events = parse_log_text(text)
    findings = detect_findings(events)
    context = correlate_events(events)
    hypotheses = rank_hypotheses(findings, events, context)
    hypotheses.extend(predict_cause_hypotheses(events, findings, hypotheses))
    hypotheses.sort(
        key=lambda hypothesis: (
            0 if hypothesis.method == "rules" and hypothesis.category not in {"unknown", "anomaly"}
            else 1 if hypothesis.method == "model"
            else 2,
            -hypothesis.score,
            hypothesis.summary,
        )
    )
    hypotheses = hypotheses[:5]
    assessment = _build_assessment(events, findings, hypotheses)
    return AnalysisResult(
        events=events,
        findings=findings,
        context=context,
        hypotheses=hypotheses,
        recommendations=recommend_actions(hypotheses),
        assessment=assessment,
    )

