"""Generate a portable Markdown incident report."""

from __future__ import annotations

from datetime import datetime, timezone

from .models import AnalysisResult


def _pct(value: float) -> str:
    return f"{value:.0%}"


def build_markdown_report(result: AnalysisResult) -> str:
    context = result.context
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# OpsPilot AI Incident Report",
        "",
        f"Generated: {generated}",
        "",
        "> This report is an evidence-based starting point. OpsPilot does not execute remediation commands.",
        "",
        "## Summary",
        "",
        f"- Parsed events: {len(result.events)}",
        f"- Error-level events: {result.error_count}",
        f"- Findings: {len(result.findings)}",
        f"- Affected services: {', '.join(context.affected_services) if context else 'unknown'}",
        f"- Assessment: {result.assessment or 'No assessment available.'}",
    ]
    if context and context.start and context.end:
        lines.append(f"- Incident window: {context.start.isoformat()} to {context.end.isoformat()} ({context.duration_seconds:.0f}s)")

    lines.extend(["", "## Ranked root-cause hypotheses", ""])
    if result.hypotheses:
        for index, hypothesis in enumerate(result.hypotheses, start=1):
            services = ", ".join(hypothesis.related_services) or "unknown service"
            score_name = "Model match score" if hypothesis.method == "model" else "Rule evidence score"
            lines.extend([
                f"### {index}. {hypothesis.summary}",
                f"- {score_name}: {_pct(hypothesis.confidence)}",
                f"- Score: {hypothesis.score:.1f}/100",
                f"- Related services: {services}",
                f"- Method: {'local trained classifier' if hypothesis.method == 'model' else 'transparent rules/statistics'}",
                "- Evidence:",
            ])
            lines.extend(f"  - {item}" for item in hypothesis.evidence)
            lines.append("")
    else:
        lines.append("No root-cause hypothesis was generated from the supplied logs.\n")

    lines.extend(["## Findings", ""])
    if result.findings:
        for finding in result.findings:
            lines.append(f"- **{finding.title}** ({_pct(finding.confidence)} confidence): {finding.description}")
            lines.extend(f"  - {item}" for item in finding.evidence)
    else:
        lines.append("No configured pattern or statistical anomaly matched.")

    lines.extend(["", "## Recommended actions", ""])
    if result.recommendations:
        for action in result.recommendations:
            lines.extend([f"### {action.title}", action.rationale, "", "Steps:"])
            lines.extend(f"- {step}" for step in action.steps)
            lines.extend([f"\nCaution: {action.caution}", ""])
    else:
        lines.append("No action recommendation was generated.")

    return "\n".join(lines).rstrip() + "\n"

