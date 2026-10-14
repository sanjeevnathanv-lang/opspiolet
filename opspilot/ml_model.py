"""Load and apply the compact trained log-cause text classifier."""

from __future__ import annotations

from collections import defaultdict
from functools import lru_cache
from pathlib import Path

import joblib

from .models import LogEvent, PatternFinding, RootCauseHypothesis

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "log_cause_classifier.joblib"

_CAUSES = {
    "database": (
        "dependency",
        "Database connection-pool or session pressure may be involved",
    ),
    "dependency": (
        "dependency",
        "A remote dependency or service endpoint may be failing",
    ),
    "memory": (
        "resource",
        "Application memory pressure may be involved",
    ),
    "storage": (
        "resource",
        "Storage capacity or a write-path problem may be involved",
    ),
    "dns": (
        "network",
        "DNS or service-name resolution may be failing",
    ),
    "tls": (
        "configuration",
        "TLS certificate or secure-channel validation may be failing",
    ),
    "authentication": (
        "configuration",
        "Authentication or workload identity may be failing",
    ),
    "rate_limit": (
        "behavior",
        "Rate limiting or request throttling may be involved",
    ),
    "queue": (
        "dependency",
        "Queue consumer throughput or backlog may be involved",
    ),
    "cpu": (
        "resource",
        "CPU scheduling or compute pressure may be involved",
    ),
    "latency": (
        "performance",
        "Request or downstream latency regression may be involved",
    ),
    "process_crash": (
        "resource",
        "Application process instability or repeated crashes may be involved",
    ),
}

MIN_MODEL_SCORE = 0.28
MIN_CLASS_MARGIN = 0.12
_RULE_MARKERS = {
    "database": ("database", "sql"),
    "dependency": ("upstream service failure", "dependency call", "partner endpoint"),
    "memory": ("memory",),
    "storage": ("filesystem", "storage", "disk"),
    "dns": ("dns", "hostname", "resolution"),
    "tls": ("tls", "certificate"),
    "authentication": ("credential", "authentication", "identity"),
    "rate_limit": ("rate limit", "throttling", "retry amplification"),
    "queue": ("queue", "consumer lag"),
    "cpu": ("cpu",),
    "latency": ("latency", "slow"),
    "process_crash": ("process is crashing", "restarting", "crash"),
}


@lru_cache(maxsize=1)
def _load_artifact() -> tuple[dict | None, str | None]:
    if not MODEL_PATH.is_file():
        return None, "trained classifier artifact is missing"
    try:
        artifact = joblib.load(MODEL_PATH)
        if not isinstance(artifact, dict) or "pipeline" not in artifact:
            return None, "classifier artifact has an unsupported format"
        return artifact, None
    except Exception as exc:  # Keep deterministic log analysis available if the optional model cannot load.
        return None, f"classifier could not be loaded ({type(exc).__name__})"


def classifier_status() -> tuple[bool, dict | None, str | None]:
    """Return model availability, training metadata, and a safe error message."""

    artifact, error = _load_artifact()
    return artifact is not None, artifact.get("metadata") if artifact else None, error


def _specific_pattern_lines(findings: list[PatternFinding]) -> set[int]:
    generic_ids = {
        "unclassified-error", "unclassified-warning", "error-burst", "high-error-ratio",
        "repeated-error", "traffic-spike",
    }
    return {
        line
        for finding in findings
        if finding.pattern_id not in generic_ids
        for line in finding.event_lines
    }


def predict_cause_hypotheses(
    events: list[LogEvent],
    findings: list[PatternFinding],
    existing: list[RootCauseHypothesis],
) -> list[RootCauseHypothesis]:
    """Add high-margin model leads for error events not already explained by a rule."""

    artifact, _ = _load_artifact()
    if artifact is None:
        return []

    covered_lines = _specific_pattern_lines(findings)
    eligible = [
        event for event in events
        if (event.is_error or event.severity == "WARN") and event.line_number not in covered_lines
    ]
    if not eligible:
        return []

    pipeline = artifact["pipeline"]
    probabilities = pipeline.predict_proba([event.message for event in eligible])
    labels = list(pipeline.named_steps["classifier"].classes_)
    grouped: dict[str, list[tuple[LogEvent, float]]] = defaultdict(list)

    for event, row in zip(eligible, probabilities, strict=True):
        ordered = sorted((float(score), index) for index, score in enumerate(row))
        top_score, top_index = ordered[-1]
        second_score = ordered[-2][0] if len(ordered) > 1 else 0.0
        threshold = MIN_MODEL_SCORE if event.is_error else 0.36
        if top_score < threshold or top_score - second_score < MIN_CLASS_MARGIN:
            continue
        label = labels[top_index]
        if label not in _CAUSES:
            continue
        grouped[label].append((event, top_score))

    candidates: list[RootCauseHypothesis] = []
    existing_text = [hypothesis.summary.casefold() for hypothesis in existing if hypothesis.category not in {"unknown", "anomaly"}]
    for label, observations in grouped.items():
        category, summary = _CAUSES[label]
        if any(marker in prior for prior in existing_text for marker in _RULE_MARKERS[label]):
            continue

        match_score = sum(score for _, score in observations) / len(observations)
        # Model candidates are intentionally capped below clear rule-based leads.
        ranking_score = min(69.0, 45.0 + 24.0 * match_score)
        services = tuple(sorted({event.service for event, _ in observations if event.service != "unknown"}))
        evidence = [
            f"Local TF-IDF classifier matched '{label}' with a {match_score:.0%} model score across {len(observations)} event(s).",
            *(
                f"Line {event.line_number} [{event.severity}] {event.service}: {event.message[:180]}"
                for event, _ in observations[:4]
            ),
        ]
        candidates.append(
            RootCauseHypothesis(
                category=category,
                summary=summary,
                score=round(ranking_score, 1),
                confidence=round(match_score, 3),
                evidence=tuple(evidence),
                related_services=services,
                method="model",
            )
        )

    return sorted(candidates, key=lambda hypothesis: (-hypothesis.score, hypothesis.summary))[:2]
