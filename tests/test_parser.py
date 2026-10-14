from opspilot.parser import parse_line, parse_log_text


def test_parse_plain_text_with_service_and_timestamp():
    event = parse_line(
        "2026-10-14T10:00:03Z ERROR checkout-api database connection refused service=checkout-api",
        1,
    )
    assert event.severity == "ERROR"
    assert event.service == "checkout-api"
    assert event.timestamp is not None
    assert "connection refused" in event.message


def test_parse_json_line():
    event = parse_line(
        '{"timestamp":"2026-10-14T10:00:03Z","level":"ERROR","service":"payments","message":"timeout"}',
        7,
    )
    assert event.line_number == 7
    assert event.service == "payments"
    assert event.message == "timeout"
    assert event.is_error


def test_parse_malformed_line_preserves_input_with_warning():
    event = parse_line("not a structured log line", 4)
    assert event.line_number == 4
    assert event.message == "not a structured log line"
    assert "unrecognized format" in event.warnings


def test_blank_lines_are_ignored():
    assert len(parse_log_text("\nINFO something\n\n")) == 1


def test_parse_logfmt_with_fields_out_of_order():
    event = parse_line(
        'service=orders severity=ERR timestamp=2026-10-14T10:00:03Z msg="Payment authorization failed"',
        3,
    )
    assert event.timestamp is not None
    assert event.severity == "ERROR"
    assert event.service == "orders"
    assert event.message == "Payment authorization failed"


def test_infer_error_without_standard_severity_or_timestamp():
    event = parse_line("Exception: payment provider returned code XJ-73", 5)
    assert event.severity == "ERROR"
    assert event.timestamp is None
    assert event.message == "Exception: payment provider returned code XJ-73"


def test_parse_nested_json_and_json_array():
    text = '[{"@timestamp":"2026-10-14T10:00:03Z","log":{"level":"ERROR"},"service":{"name":"billing"},"message":"invoice failed"}]'
    events = parse_log_text(text)
    assert len(events) == 1
    assert events[0].service == "billing"
    assert events[0].severity == "ERROR"


def test_parse_csv_export():
    events = parse_log_text("timestamp,severity,service,message\n2026-10-14T10:00:03Z,ERROR,billing,invoice failed\n")
    assert len(events) == 1
    assert events[0].service == "billing"
    assert events[0].is_error


def test_parse_apache_timestamp_and_infer_http_server_error():
    event = parse_line('[14/Oct/2026:10:00:03 +0000] "POST /checkout HTTP/1.1" 503 120', 8)
    assert event.timestamp is not None
    assert event.timestamp.year == 2026
    assert event.is_error


def test_parse_opentelemetry_json_fields():
    event = parse_line(
        '{"timeUnixNano":1791972000000000000,"severityNumber":17,"body":"upstream call failed","resource":{"attributes":{"service.name":"search-api"}}}',
        9,
    )
    assert event.timestamp is not None
    assert event.severity == "ERROR"
    assert event.service == "search-api"
    assert event.message == "upstream call failed"

