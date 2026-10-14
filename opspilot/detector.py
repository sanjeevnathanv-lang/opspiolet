"""Explainable rules and lightweight statistics for log findings."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
import re
from statistics import mean, pstdev

from .models import LogEvent, PatternFinding

_RULES = (
    {
        "id": "database-connection-refused",
        "title": "Database connection refused",
        "category": "dependency",
        "regex": r"connection refused|could not connect.*(?:postgres|mysql|database)|connection reset by peer",
        "confidence": 0.90,
        "description": "The application cannot establish a connection to its database dependency.",
    },
    {
        "id": "database-timeout",
        "title": "Database or dependency timeout",
        "category": "dependency",
        "regex": r"(?:database|sql|query|upstream|dependency).{0,30}timeout|timeout.{0,30}(?:database|sql|query|upstream|dependency)",
        "confidence": 0.82,
        "description": "A dependency call is exceeding its timeout budget.",
    },
    {
        "id": "out-of-memory",
        "title": "Out-of-memory condition",
        "category": "resource",
        "regex": r"out of memory|oomkilled|cannot allocate memory|memory limit exceeded|heap space",
        "confidence": 0.95,
        "description": "The process or container reports memory exhaustion.",
    },
    {
        "id": "permission-denied",
        "title": "Permission denied",
        "category": "configuration",
        "regex": r"permission denied|access denied|forbidden|eacces",
        "confidence": 0.83,
        "description": "The application identity cannot access a required resource.",
    },
    {
        "id": "upstream-5xx",
        "title": "Upstream HTTP 5xx failure",
        "category": "dependency",
        "regex": r"\b(?:HTTP\s*)?5\d\d\b|bad gateway|service unavailable|internal server error",
        "confidence": 0.78,
        "description": "An upstream or gateway is returning a server-side failure.",
    },
    {
        "id": "authentication-failure",
        "title": "Authentication or credential failure",
        "category": "configuration",
        "regex": r"authentication failed|invalid token|token expired|unauthorized|invalid credentials|login failed",
        "confidence": 0.84,
        "description": "A credential, token, or authentication exchange is being rejected.",
    },
    {
        "id": "retry-storm",
        "title": "Retry amplification",
        "category": "behavior",
        "regex": r"retry(?:ing| attempt)|backoff|too many requests|rate limit|circuit breaker",
        "confidence": 0.72,
        "description": "Retries or throttling indicate a failing dependency may be amplifying load.",
    },
    {
        "id": "dns-resolution",
        "title": "DNS resolution failure",
        "category": "network",
        "regex": r"no such host|name or service not known|temporary failure in name resolution|getaddrinfo failed|dns resolution failed|could not resolve host",
        "confidence": 0.88,
        "description": "The application cannot resolve a hostname needed to reach a service.",
    },
    {
        "id": "tls-certificate",
        "title": "TLS or certificate failure",
        "category": "configuration",
        "regex": r"certificate verify failed|certificate has expired|tls handshake|ssl handshake|unknown ca|certificate is not trusted",
        "confidence": 0.88,
        "description": "A TLS handshake or certificate validation is failing between services.",
    },
    {
        "id": "disk-pressure",
        "title": "Disk full or storage pressure",
        "category": "resource",
        "regex": r"no space left on device|disk full|enospc|read.only file system|filesystem.{0,20}(?:full|space)",
        "confidence": 0.94,
        "description": "The process cannot write because storage is full or read-only.",
    },
    {
        "id": "cpu-pressure",
        "title": "CPU pressure or throttling",
        "category": "resource",
        "regex": r"cpu throttl|cpu limit exceeded|high cpu usage|cpu saturation|load average.{0,12}(?:high|[89]\d)",
        "confidence": 0.78,
        "description": "CPU pressure may be delaying work or causing request timeouts.",
    },
    {
        "id": "process-restarts",
        "title": "Process crash or restart loop",
        "category": "resource",
        "regex": r"crashloopbackoff|oomkilled|restarting container|process exited with code|segmentation fault|segfault|uncaught exception",
        "confidence": 0.87,
        "description": "A process is crashing or restarting, which can interrupt traffic and lose work.",
    },
    {
        "id": "http-rate-limit",
        "title": "HTTP rate limiting",
        "category": "behavior",
        "regex": r"\b(?:HTTP\s*)?429\b|too many requests|rate limit exceeded|request quota exceeded",
        "confidence": 0.82,
        "description": "Requests are being throttled by a service or API quota.",
    },
    {
        "id": "queue-backlog",
        "title": "Queue backlog or consumer lag",
        "category": "dependency",
        "regex": r"consumer lag|queue backlog|queue is full|messages? (?:are )?backed up|dead.?letter queue|offset lag",
        "confidence": 0.80,
        "description": "A queue consumer may be unable to keep up with incoming work.",
    },
    {
        "id": "latency-regression",
        "title": "High latency or slow query",
        "category": "performance",
        "regex": r"slow query|latency (?:above|exceeded|over)|request took [1-9]\d{3,}\s*ms|exceeded.{0,15}latency|response time.{0,15}(?:high|slow)",
        "confidence": 0.74,
        "description": "The log reports slow work that may precede timeouts or user-visible delays.",
    },
)


def _evidence(event: LogEvent) -> str:
    return f"Line {event.line_number} [{event.severity}] {event.service}: {event.message[:180]}"


def _pattern_findings(events: list[LogEvent]) -> list[PatternFinding]:
    findings: list[PatternFinding] = []
    for rule in _RULES:
        matched = [event for event in events if re.search(rule["regex"], event.message, re.I)]
        if not matched:
            continue
        confidence = min(0.99, rule["confidence"] + min(0.08, (len(matched) - 1) * 0.02))
        findings.append(
            PatternFinding(
                pattern_id=rule["id"],
                title=rule["title"],
                category=rule["category"],
                confidence=round(confidence, 2),
                description=rule["description"],
                event_lines=tuple(event.line_number for event in matched),
                evidence=tuple(_evidence(event) for event in matched[:5]),
            )
        )
    return findings


def _statistical_findings(events: list[LogEvent]) -> list[PatternFinding]:
    findings: list[PatternFinding] = []
    errors = [event for event in events if event.is_error]
    if len(errors) >= 3 and all(event.timestamp for event in errors):
        times = sorted(event.timestamp for event in errors if event.timestamp)
        if times[-1] - times[0] <= timedelta(minutes=2):
            findings.append(
                PatternFinding(
                    "error-burst", "Error burst", "anomaly", 0.88,
                    "At least three error-level events occurred within two minutes.",
                    tuple(event.line_number for event in errors),
                    (f"{len(errors)} error events from {times[0].isoformat()} to {times[-1].isoformat()}",),
                )
            )

    if events and len(errors) / len(events) >= 0.40 and len(errors) >= 3:
        findings.append(
            PatternFinding(
                "high-error-ratio", "High error ratio", "anomaly", 0.80,
                "Errors make up at least 40% of parsed events in the supplied window.",
                tuple(event.line_number for event in errors),
                (f"{len(errors)} errors out of {len(events)} parsed events",),
            )
        )

    normalized_messages = Counter(re.sub(r"\d+", "<n>", event.message.lower()) for event in errors)
    repeated = [(message, count) for message, count in normalized_messages.items() if count >= 3]
    if repeated:
        message, count = max(repeated, key=lambda item: item[1])
        lines = tuple(event.line_number for event in errors if re.sub(r"\d+", "<n>", event.message.lower()) == message)
        findings.append(
            PatternFinding(
                "repeated-error", "Repeated error signature", "anomaly", 0.84,
                "The same normalized error message repeated at least three times.", lines,
                (f"Repeated {count} times: {message[:160]}",),
            )
        )

    timestamps = [event.timestamp for event in events if event.timestamp]
    if len(timestamps) >= 4:
        minute_counts = Counter(timestamp.replace(second=0, microsecond=0) for timestamp in timestamps)
        values = list(minute_counts.values())
        baseline = mean(values)
        spread = pstdev(values)
        maximum = max(values)
        if len(values) >= 3 and maximum >= 5 and maximum > baseline + max(1.0, 2 * spread):
            peak = max(minute_counts, key=minute_counts.get)
            findings.append(
                PatternFinding(
                    "traffic-spike", "Unusual event-rate spike", "anomaly", 0.70,
                    "One minute has materially more events than the other observed minutes.", (),
                    (f"Peak minute {peak.isoformat()} has {maximum} events; baseline is {baseline:.1f}",),
                )
            )
    return findings


def _unclassified_findings(events: list[LogEvent], findings: list[PatternFinding]) -> list[PatternFinding]:
    """Surface errors even when their wording is outside the configured rules."""

    covered_lines = {line for finding in findings for line in finding.event_lines}
    unclassified = [event for event in events if event.is_error and event.line_number not in covered_lines]
    if unclassified:
        return [PatternFinding(
            "unclassified-error", "Unclassified application error", "unknown", 0.55,
            "An error or exception was found, but its message does not match a configured cause pattern. Use the evidence below as a lead and add service or request context.",
            tuple(event.line_number for event in unclassified),
            tuple(_evidence(event) for event in unclassified[:5]),
        )]

    warnings = [event for event in events if event.severity == "WARN" and event.line_number not in covered_lines]
    if warnings and not findings:
        return [PatternFinding(
            "unclassified-warning", "Warnings or degraded behavior", "unknown", 0.42,
            "Warnings were present without a more specific configured pattern. Compare these events with a healthy baseline.",
            tuple(event.line_number for event in warnings),
            tuple(_evidence(event) for event in warnings[:5]),
        )]
    return []


def detect_findings(events: list[LogEvent]) -> list[PatternFinding]:
    """Return deduplicated rule and statistical findings."""

    findings = _pattern_findings(events)
    findings.extend(_statistical_findings(events))
    findings.extend(_unclassified_findings(events, findings))
    return sorted(findings, key=lambda finding: (-finding.confidence, finding.title))

