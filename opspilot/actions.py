"""Safe, human-approved investigation actions. No commands are executed."""

from __future__ import annotations

from .models import ActionRecommendation, RootCauseHypothesis


def recommend_actions(hypotheses: list[RootCauseHypothesis]) -> list[ActionRecommendation]:
    """Translate ranked causes into read-only runbook suggestions."""

    actions: list[ActionRecommendation] = []
    for hypothesis in hypotheses[:3]:
        summary = hypothesis.summary.lower()
        if "database" in summary or "dependency" in summary:
            actions.append(ActionRecommendation(
                "Validate dependency health and connectivity",
                "The logs contain dependency refusal, timeout, or upstream failure evidence.",
                (
                    "Check the dependency health dashboard and recent maintenance events.",
                    "Review connection pool saturation, latency, and network policy metrics.",
                    "Compare the first failing timestamp with deploy and configuration-change times.",
                ),
                "Do not restart or fail over a dependency until an owner confirms the blast radius.",
            ))
        elif "memory" in summary:
            actions.append(ActionRecommendation(
                "Inspect memory pressure and workload shape",
                "An out-of-memory signature is a high-confidence resource finding.",
                (
                    "Review container memory usage, limits, restarts, and garbage-collection metrics.",
                    "Compare request volume and payload sizes with a healthy period.",
                    "Capture a heap profile or reduce load only through the approved change process.",
                ),
                "Avoid increasing limits blindly; confirm whether usage is a leak, traffic change, or bad release.",
            ))
        elif "credential" in summary or "identity" in summary:
            actions.append(ActionRecommendation(
                "Verify identity and configuration safely",
                "The logs suggest permissions or authentication material is being rejected.",
                (
                    "Confirm the active workload identity and secret/configuration version.",
                    "Check the dependency audit log for denied requests at the same timestamp.",
                    "Validate a non-production credential or read-only permission path first.",
                ),
                "Never paste secret values into logs or this dashboard; rotate credentials only with the owner.",
            ))
        elif "retry" in summary:
            actions.append(ActionRecommendation(
                "Measure retry amplification",
                "Retry or backoff messages can multiply load while a dependency is unhealthy.",
                (
                    "Compare request count with downstream call count and retry rate.",
                    "Check circuit-breaker state and retry-budget configuration.",
                    "Use the approved rollback or rate-limit runbook if the dependency owner agrees.",
                ),
                "Do not disable retries globally without understanding idempotency and customer impact.",
            ))
        elif "dns" in summary or "hostname" in summary:
            actions.append(ActionRecommendation(
                "Check name resolution from the affected service",
                "The log contains a hostname or DNS resolution failure.",
                (
                    "Confirm the hostname and service-discovery record used by the application.",
                    "Compare resolution results from the affected runtime with a healthy instance.",
                    "Check recent DNS, network, and service-discovery changes around the first failure.",
                ),
                "Avoid changing shared DNS records until the owning team confirms the affected clients.",
            ))
        elif "tls" in summary or "certificate" in summary:
            actions.append(ActionRecommendation(
                "Verify certificate chain and expiry",
                "The logs suggest TLS negotiation or certificate trust is failing.",
                (
                    "Check the certificate expiry, issuer, hostname, and trust chain on both endpoints.",
                    "Compare the active certificate version with the last known healthy version.",
                    "Review recent secret, certificate, proxy, and runtime trust-store changes.",
                ),
                "Do not disable certificate verification as a workaround.",
            ))
        elif "filesystem" in summary or "storage" in summary:
            actions.append(ActionRecommendation(
                "Inspect storage capacity and write paths",
                "The logs indicate that a filesystem may be full or mounted read-only.",
                (
                    "Check free space, inode usage, volume health, and recent growth by directory.",
                    "Identify whether logs, temporary files, or application data grew unexpectedly.",
                    "Follow the storage owner’s cleanup or expansion runbook after confirming retention needs.",
                ),
                "Preserve application data and audit requirements before removing files.",
            ))
        elif "cpu" in summary:
            actions.append(ActionRecommendation(
                "Compare CPU pressure with request load",
                "CPU throttling or saturation can increase latency and trigger downstream timeouts.",
                (
                    "Review CPU usage, throttling, queue depth, and request rate for the same time window.",
                    "Compare the top workload or endpoint with a healthy period.",
                    "Check whether a recent release or traffic shift changed CPU demand.",
                ),
                "Confirm the bottleneck before scaling or changing resource limits.",
            ))
        elif "queue" in summary:
            actions.append(ActionRecommendation(
                "Measure queue growth and consumer health",
                "A backlog or consumer lag can delay processing even while the API is healthy.",
                (
                    "Compare publish rate, consume rate, oldest-message age, and consumer errors.",
                    "Check consumer restarts, partition assignments, and downstream dependency latency.",
                    "Review dead-letter volume and retry behavior before replaying messages.",
                ),
                "Avoid purging or replaying queue messages without validating idempotency and data impact.",
            ))
        elif "rate limit" in summary:
            actions.append(ActionRecommendation(
                "Check rate-limit source and request volume",
                "Requests may be exceeding a service quota or configured limit.",
                (
                    "Identify which endpoint or upstream returned the 429 response.",
                    "Compare request volume, quota headers, and client retry behavior.",
                    "Check for a traffic spike or duplicate requests before requesting a quota change.",
                ),
                "Do not increase quotas until the service owner confirms capacity and cost impact.",
            ))
        elif "latency" in summary or "slow" in summary:
            actions.append(ActionRecommendation(
                "Trace the slow operation",
                "The logs include a slow query, high latency, or long request duration.",
                (
                    "Compare latency percentiles by endpoint and dependency for the same window.",
                    "Use request or trace IDs to identify the slow stage in a representative request.",
                    "Check database query plans, connection pools, and recent workload changes.",
                ),
                "Avoid optimizing based on one slow sample; confirm the pattern across requests.",
            ))
        else:
            actions.append(ActionRecommendation(
                "Correlate the first error with recent changes",
                "The anomaly needs additional context before a corrective action is chosen.",
                (
                    "Identify the first failing event and the affected service owner.",
                    "Compare deploys, feature flags, config changes, and traffic around that timestamp.",
                    "Add traces or request IDs from a representative failed request.",
                ),
                "Treat the hypothesis as a lead, not proof; obtain human approval before making changes.",
            ))

    deduplicated: list[ActionRecommendation] = []
    seen_titles: set[str] = set()
    for action in actions:
        if action.title not in seen_titles:
            deduplicated.append(action)
            seen_titles.add(action.title)
    return deduplicated

