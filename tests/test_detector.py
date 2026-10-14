from opspilot.detector import detect_findings
from opspilot.parser import parse_log_text


def test_detector_finds_dependency_and_statistical_signals():
    text = "\n".join([
        "2026-10-14T10:00:00Z ERROR checkout-api database connection refused",
        "2026-10-14T10:00:01Z WARN checkout-api retrying database request",
        "2026-10-14T10:00:02Z ERROR checkout-api database connection refused",
        "2026-10-14T10:00:03Z ERROR checkout-api database connection refused",
    ])
    findings = detect_findings(parse_log_text(text))
    ids = {finding.pattern_id for finding in findings}
    assert "database-connection-refused" in ids
    assert "retry-storm" in ids
    assert "error-burst" in ids
    assert "repeated-error" in ids


def test_detector_returns_no_findings_for_healthy_window():
    events = parse_log_text("2026-10-14T10:00:00Z INFO api health check passed")
    assert detect_findings(events) == []


def test_detector_finds_storage_dns_tls_and_queue_patterns():
    text = "\n".join([
        "ERROR no space left on device while writing report",
        "WARN temporary failure in name resolution for billing-api",
        "ERROR certificate verify failed for upstream",
        "WARN consumer lag increased and queue backlog is growing",
    ])
    ids = {finding.pattern_id for finding in detect_findings(parse_log_text(text))}
    assert {"disk-pressure", "dns-resolution", "tls-certificate", "queue-backlog"} <= ids

