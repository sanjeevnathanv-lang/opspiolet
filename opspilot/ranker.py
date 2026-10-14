"""Evidence-weighted, deterministic root-cause hypotheses."""

from __future__ import annotations

from dataclasses import dataclass

from .models import IncidentContext, LogEvent, PatternFinding, RootCauseHypothesis


@dataclass(frozen=True)
class _CauseRule:
    pattern_id: str
    category: str
    summary: str
    base_score: float


_CAUSE_RULES = (
    _CauseRule("database-connection-refused", "dependency", "Database dependency is unavailable or unreachable", 92),
    _CauseRule("database-timeout", "dependency", "Database or upstream dependency is saturated or slow", 84),
    _CauseRule("out-of-memory", "resource", "Application memory pressure or a container memory limit is the likely cause", 96),
    _CauseRule("permission-denied", "configuration", "A runtime identity or resource permission changed", 86),
    _CauseRule("upstream-5xx", "dependency", "An upstream service failure is propagating into this application", 78),
    _CauseRule("authentication-failure", "configuration", "A credential, token, or authentication configuration is invalid", 88),
    _CauseRule("retry-storm", "behavior", "A failing dependency is causing retry amplification", 72),
    _CauseRule("dns-resolution", "network", "A DNS or hostname-resolution problem is preventing service discovery", 86),
    _CauseRule("tls-certificate", "configuration", "A TLS certificate or trust configuration is blocking service communication", 86),
    _CauseRule("disk-pressure", "resource", "A full or read-only filesystem is preventing application writes", 94),
    _CauseRule("cpu-pressure", "resource", "CPU pressure is delaying application work", 76),
    _CauseRule("process-restarts", "resource", "The process is crashing or restarting and interrupting service", 85),
    _CauseRule("http-rate-limit", "behavior", "An API or upstream rate limit is rejecting requests", 78),
    _CauseRule("queue-backlog", "dependency", "A queue consumer is falling behind incoming work", 77),
    _CauseRule("latency-regression", "performance", "Slow requests or queries are causing degraded response time", 70),
    _CauseRule("unclassified-error", "unknown", "An application error is present, but its cause is not classified by the current rules", 44),
    _CauseRule("unclassified-warning", "unknown", "Warnings suggest degraded behavior that needs comparison with a healthy baseline", 34),
    _CauseRule("error-burst", "anomaly", "A short-lived incident burst needs correlation with a dependency or deploy", 56),
    _CauseRule("high-error-ratio", "anomaly", "The supplied window shows broad application instability", 52),
    _CauseRule("repeated-error", "anomaly", "A repeated error signature is affecting one or more requests", 58),
    _CauseRule("traffic-spike", "anomaly", "An unusual traffic or event-rate spike may be contributing to pressure", 45),
)


def rank_hypotheses(
    findings: list[PatternFinding], events: list[LogEvent], context: IncidentContext
) -> list[RootCauseHypothesis]:
    """Score causes from explicit rules plus corroborating event evidence."""

    by_pattern = {rule.pattern_id: rule for rule in _CAUSE_RULES}
    hypotheses: list[RootCauseHypothesis] = []
    for finding in findings:
        rule = by_pattern.get(finding.pattern_id)
        if not rule:
            continue
        matched_events = [event for event in events if event.line_number in finding.event_lines]
        services = tuple(sorted({event.service for event in matched_events if event.service != "unknown"}))
        corroboration = min(8.0, max(0, len(matched_events) - 1) * 2.0)
        earliest_error_bonus = 5.0 if matched_events and any(event.is_error for event in matched_events[:1]) else 0.0
        score = min(99.0, rule.base_score * finding.confidence + corroboration + earliest_error_bonus)
        evidence = [f"{finding.title}: {finding.description}", *finding.evidence]
        if context.clusters:
            evidence.append(f"Correlated incident window: {context.clusters[0]}")
        hypotheses.append(
            RootCauseHypothesis(
                category=rule.category,
                summary=rule.summary,
                score=round(score, 1),
                confidence=round(min(0.99, score / 100), 2),
                evidence=tuple(evidence[:6]),
                related_services=services,
            )
        )

    hypotheses.sort(key=lambda hypothesis: (-hypothesis.score, hypothesis.summary))
    return hypotheses[:5]

