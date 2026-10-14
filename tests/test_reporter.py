from opspilot.pipeline import analyze_log_text
from opspilot.reporter import build_markdown_report


def test_report_contains_summary_evidence_and_safety_note():
    result = analyze_log_text("2026-10-14T10:00:00Z ERROR api out of memory")
    report = build_markdown_report(result)
    assert "# OpsPilot AI Incident Report" in report
    assert "Out-of-memory condition" in report
    assert "does not execute remediation commands" in report
    assert "Recommended actions" in report
    assert "Assessment:" in report

