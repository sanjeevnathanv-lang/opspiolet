"""Grounded, deterministic chat responses over an OpsPilot analysis result."""

from __future__ import annotations

import re

from .models import AnalysisResult

_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_LEVEL = re.compile(r"(?:^|[\s\[|])(?:TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|FATAL|CRITICAL)(?:$|[\s\]:|])", re.I)
_EXPLICIT_LEVEL = re.compile(r"\b(?:level|severity|levelname)\s*[=:]\s*(?:TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)\b", re.I)
_SINGLE_LOG_PREFIX = re.compile(r"^\s*(?:\{|\[|\d{1,2}/[A-Za-z]{3}/\d{4}:|Traceback \(most recent call last\)|(?:uncaught )?exception\s*:|(?:ERROR|FATAL|CRITICAL|WARN(?:ING)?|INFO|DEBUG)\b)", re.I)


def looks_like_log_input(text: str) -> bool:
    """Distinguish pasted log lines from a natural-language follow-up question."""

    content = text.strip()
    if not content:
        return False
    if _TIMESTAMP.search(content) or content.startswith(("{", "[")):
        return True
    if _SINGLE_LOG_PREFIX.search(content):
        return True

    lines = [line for line in content.splitlines() if line.strip()]
    if len(lines) < 2:
        return False
    marked = sum(
        bool(_TIMESTAMP.search(line) or _LEVEL.search(line) or _EXPLICIT_LEVEL.search(line))
        for line in lines
    )
    return marked >= 1


def build_incident_answer(result: AnalysisResult) -> str:
    """Create the concise opening message for a newly analyzed log batch."""

    if not result.events:
        return "I couldn't find any non-empty log entries to analyze. Try a text log, JSON/JSONL, or CSV export."

    context = result.context
    warnings = sum(event.severity == "WARN" for event in result.events)
    services = ", ".join(context.affected_services) if context and context.affected_services else "not identified"
    summary = (
        f"I read **{len(result.events)} events**: **{result.error_count} errors** and **{warnings} warnings**. "
        f"Affected services: **{services}**."
    )
    if result.hypotheses:
        lead = result.hypotheses[0]
        summary += f"\n\n**Leading lead:** {lead.summary} (rule evidence score **{lead.confidence:.0%}**)."
        summary += "\n\nI ranked this from the matching log signatures and corroborating evidence below. It is a lead to validate—not proof of root cause."
    elif result.error_count:
        summary += "\n\nI found errors, but the current rules could not identify a specific cause. I’ll keep the assessment cautious and show the raw error evidence."
    elif result.findings:
        summary += "\n\nI found warning or anomaly signals, but not enough evidence to name a root cause."
    else:
        summary += "\n\nNo configured fault pattern matched this window. Check that it overlaps the incident and compare it with a healthy period."
    return summary


def answer_follow_up(question: str, result: AnalysisResult | None) -> str:
    """Answer common incident questions using only the current analyzed evidence."""

    if result is None or not result.events:
        return "I don't have an analyzed incident in this conversation yet. Attach or paste a log first, and I can answer using its evidence."

    query = question.casefold()
    context = result.context
    if any(term in query for term in ("next step", "what should", "how do i fix", "how to fix", "remediat", "mitigat", "action", "resolve", "fix this")):
        if not result.recommendations:
            return "I don't see enough evidence to suggest a targeted next check. Confirm the incident time window and add service, dependency, or request context. I won't execute remediation actions."
        sections = ["**Safe next checks** (suggestions only; nothing will be executed):"]
        for action in result.recommendations[:2]:
            sections.append(f"\n**{action.title}** — {action.rationale}")
            sections.extend(f"- {step}" for step in action.steps[:3])
            sections.append(f"\n_Caution:_ {action.caution}")
        return "\n".join(sections)

    if any(term in query for term in ("confidence", "confident", "certain", "sure", "probability", "how likely")):
        if not result.hypotheses:
            return "There isn't a ranked root-cause hypothesis for this log batch, so I can't give a cause score. The score is based on local rule matches—not a calibrated probability."
        lead = result.hypotheses[0]
        return (
            f"The leading hypothesis is **{lead.summary}**, with a **{lead.confidence:.0%} rule evidence score**. "
            "That score reflects how strongly configured patterns and corroborating events matched; it is not a statistical probability or proof. "
            "Validate it against metrics, traces, and recent changes."
        )

    if any(term in query for term in ("show error", "list error", "error lines", "which errors", "failed event", "show the errors")):
        errors = [event for event in result.events if event.is_error]
        if not errors:
            return "No events were classified as ERROR, FATAL, or CRITICAL in this batch. There may still be warnings or non-error anomaly findings."
        lines = [f"I found **{len(errors)} error-level event(s)**. Here are the first {min(8, len(errors))}:"]
        lines.extend(f"- Line {event.line_number} · `{event.severity}` · **{event.service}** — {event.message[:220]}" for event in errors[:8])
        if len(errors) > 8:
            lines.append(f"- …and {len(errors) - 8} more. Open **View findings and normalized events** to inspect the full batch.")
        return "\n".join(lines)

    if any(term in query for term in ("service", "services", "affected", "impact", "scope", "blast radius")):
        services = context.affected_services if context else ()
        return "**Affected services:** " + (", ".join(services) if services else "not identified from these logs") + ".\n\nThis reflects service labels parsed from the supplied records; it may not capture downstream impact."

    if any(term in query for term in ("when", "time window", "duration", "how long", "correlated")):
        if context and context.start and context.end:
            return (
                f"The timestamped events span **{context.start.isoformat()} to {context.end.isoformat()}** "
                f"({context.duration_seconds:.0f} seconds). OpsPilot formed {len(context.clusters)} nearby event cluster(s)."
            )
        return "The supplied events did not contain timestamps I could reliably parse, so I can't establish an incident time window."

    if any(term in query for term in ("why", "cause", "root", "evidence", "what happened", "explain", "lead")):
        if result.hypotheses:
            lead = result.hypotheses[0]
            lines = [f"The strongest current lead is **{lead.summary}** (rule evidence score **{lead.confidence:.0%}**). Evidence:"]
            lines.extend(f"- {item}" for item in lead.evidence[:5])
            lines.append("\nThis is a rule-based lead, not causal proof. Check the correlated window against metrics, traces, and recent deployments.")
            return "\n".join(lines)
        if result.findings:
            finding = result.findings[0]
            lines = [f"I found **{finding.title}**, but no specific cause is ranked yet: {finding.description}"]
            lines.extend(f"- {item}" for item in finding.evidence[:4])
            return "\n".join(lines)
        return "I don't see an error pattern or anomaly in this batch. Confirm the time range and compare it against a known healthy period."

    # For a question outside the named intents, retrieve matching records instead
    # of fabricating an open-ended answer from incomplete context.
    stop_words = {
        "about", "after", "does", "from", "have", "here", "into", "logs", "that", "them",
        "this", "those", "what", "when", "where", "which", "with", "would", "could", "should",
        "likely", "please", "tell", "show", "explain", "mean", "indicate", "indicates", "look",
    }
    terms = {word for word in re.findall(r"[a-z0-9_.-]+", query) if len(word) > 2 and word not in stop_words}
    relevant = [
        event for event in result.events
        if any(term in f"{event.service} {event.message}".casefold() for term in terms)
    ]
    if relevant:
        lines = [f"I found **{len(relevant)} event(s)** that match the wording in your question:"]
        lines.extend(
            f"- Line {event.line_number} · `{event.severity}` · **{event.service}** — {event.message[:220]}"
            for event in relevant[:5]
        )
        if len(relevant) > 5:
            lines.append(f"- …and {len(relevant) - 5} more matching events.")
        lines.append("\nThat is what the supplied logs directly say; it may not establish a cause by itself.")
        return "\n".join(lines)

    return (
        "I couldn't find a direct log match for that question. "
        + (f"The current leading hypothesis is **{result.hypotheses[0].summary}**. " if result.hypotheses else "No specific root cause is ranked yet. ")
        + "Try asking about a service, error phrase, time window, evidence, or safe next check."
    )
