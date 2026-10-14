"""Build incident context from event timing and service labels."""

from __future__ import annotations

from datetime import timedelta

from .models import IncidentContext, LogEvent


def _fmt_cluster(start, end, services: set[str], count: int) -> str:
    start_text = start.isoformat() if start else "unknown time"
    end_text = end.isoformat() if end else "unknown time"
    service_text = ", ".join(sorted(services)) or "unknown"
    return f"{start_text} to {end_text} | {count} events | services: {service_text}"


def correlate_events(events: list[LogEvent], gap_minutes: int = 5) -> IncidentContext:
    """Group timestamped events when adjacent records are close in time."""

    timestamped = sorted((event for event in events if event.timestamp), key=lambda event: event.timestamp)
    services = tuple(sorted({event.service for event in events if event.service != "unknown"}))
    if not timestamped:
        return IncidentContext(None, None, 0.0, services, len(events), sum(event.is_error for event in events), ())

    clusters: list[str] = []
    cluster_events: list[LogEvent] = []
    previous = None
    for event in timestamped:
        if previous and event.timestamp - previous > timedelta(minutes=gap_minutes):
            clusters.append(_fmt_cluster(cluster_events[0].timestamp, cluster_events[-1].timestamp, {item.service for item in cluster_events}, len(cluster_events)))
            cluster_events = []
        cluster_events.append(event)
        previous = event.timestamp
    if cluster_events:
        clusters.append(_fmt_cluster(cluster_events[0].timestamp, cluster_events[-1].timestamp, {item.service for item in cluster_events}, len(cluster_events)))

    start = timestamped[0].timestamp
    end = timestamped[-1].timestamp
    duration = max(0.0, (end - start).total_seconds())
    return IncidentContext(start, end, duration, services, len(events), sum(event.is_error for event in events), tuple(clusters))

