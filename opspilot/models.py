"""Shared data models for the OpsPilot analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class LogEvent:
    """One normalized log line."""

    line_number: int
    raw: str
    timestamp: datetime | None
    severity: str
    service: str
    message: str
    warnings: tuple[str, ...] = ()

    @property
    def is_error(self) -> bool:
        return self.severity in {"ERROR", "FATAL", "CRITICAL"}


@dataclass(frozen=True)
class PatternFinding:
    pattern_id: str
    title: str
    category: str
    confidence: float
    description: str
    event_lines: tuple[int, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class IncidentContext:
    start: datetime | None
    end: datetime | None
    duration_seconds: float
    affected_services: tuple[str, ...]
    event_count: int
    error_count: int
    clusters: tuple[str, ...]


@dataclass(frozen=True)
class RootCauseHypothesis:
    category: str
    summary: str
    score: float
    confidence: float
    evidence: tuple[str, ...]
    related_services: tuple[str, ...]


@dataclass(frozen=True)
class ActionRecommendation:
    title: str
    rationale: str
    steps: tuple[str, ...]
    caution: str


@dataclass
class AnalysisResult:
    events: list[LogEvent] = field(default_factory=list)
    findings: list[PatternFinding] = field(default_factory=list)
    context: IncidentContext | None = None
    hypotheses: list[RootCauseHypothesis] = field(default_factory=list)
    recommendations: list[ActionRecommendation] = field(default_factory=list)
    assessment: str = ""

    @property
    def error_count(self) -> int:
        return sum(event.is_error for event in self.events)

