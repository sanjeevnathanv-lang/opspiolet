"""Parse common application log shapes into normalized events."""

from __future__ import annotations

import json
import re
import csv
import io
from datetime import datetime, timezone
from typing import Any

from .models import LogEvent

_TIMESTAMP_RE = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
_TIMESTAMP_SEARCH = re.compile(_TIMESTAMP_RE)
_APACHE_TIMESTAMP = re.compile(r"\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}")
_SEVERITY = re.compile(
    r"(?<![A-Za-z])(?:level|severity|levelname)\s*[=:]\s*(?P<field>TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|SEVERE|FATAL|CRITICAL|EMERG(?:ENCY)?|PANIC)(?![A-Za-z])"
    r"|(?:^|[\s\[|])(?P<plain>TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|SEVERE|FATAL|CRITICAL|EMERG(?:ENCY)?|PANIC)(?=$|[\s\]:|])",
    re.I,
)
_LOGFMT = re.compile(r"(?P<key>[A-Za-z_][\w.-]*)=(?:\"(?P<double>[^\"]*)\"|'(?P<single>[^']*)'|(?P<bare>[^\s]+))")
_LEVELS = {"TRACE", "DEBUG", "INFO", "NOTICE", "WARN", "ERROR", "FATAL", "CRITICAL", "EMERGENCY", "PANIC"}
_MESSAGE_FIRST_WORDS = {
    "a", "an", "application", "cache", "certificate", "consumer", "database", "delete",
    "failed", "failure", "get", "head", "health", "http", "invalid", "job", "login",
    "memory", "no", "options", "patch", "post", "put", "request", "retry", "server",
    "starting", "temporary", "timeout", "token", "trace", "user", "worker",
}


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        # Accept Unix seconds and milliseconds, common in JSON application logs.
        numeric = float(value)
        if numeric > 10_000_000_000_000_000:
            numeric /= 1_000_000_000  # nanoseconds
        elif numeric > 10_000_000_000_000:
            numeric /= 1_000_000  # microseconds
        elif numeric > 10_000_000_000:
            numeric /= 1000
        try:
            return datetime.fromtimestamp(numeric, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip().replace(",", ".")
    if re.fullmatch(r"-?\d{10,20}(?:\.\d+)?", text):
        return _parse_timestamp(float(text))
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            try:
                parsed = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _canonical_level(value: Any) -> str:
    level = str(value or "INFO").upper()
    aliases = {"WARNING": "WARN", "ERR": "ERROR", "SEVERE": "ERROR", "EMERG": "EMERGENCY"}
    return aliases.get(level, level if level in _LEVELS else "INFO")


def _infer_level(value: Any, fallback: str = "INFO") -> str:
    if value not in (None, ""):
        return _canonical_level(value)
    text = str(fallback)
    if re.search(r"\b(?:fatal|critical|panic|emergency|segfault|oomkilled|out of memory)\b", text, re.I):
        return "FATAL"
    if re.search(r"\b(?:error|exception|traceback|failed|failure|crash(?:ed)?|refused|timed? out|timeout|denied|unavailable|killed)\b|\b(?:HTTP\s*5\d\d|status[= :]+5\d\d|response(?: code)?[= :]+5\d\d|5\d\d)\b", text, re.I):
        return "ERROR"
    if re.search(r"\b(?:warning|warn|degraded|retry(?:ing)?|slow)\b|\b(?:HTTP\s*429|status[= :]+429)\b", text, re.I):
        return "WARN"
    return "INFO"


def _nested_value(payload: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        if path in payload:
            return payload[path]
        value: Any = payload
        parts = path.split(".")
        for index, part in enumerate(parts):
            if not isinstance(value, dict):
                value = None
                break
            remaining = ".".join(parts[index:])
            if remaining in value:
                value = value[remaining]
                break
            if part not in value:
                value = None
                break
            value = value[part]
        if value is not None:
            return value
    return None


def _logfmt_fields(raw: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in _LOGFMT.finditer(raw):
        value = match.group("double") or match.group("single") or match.group("bare") or ""
        fields[match.group("key").lower()] = value
    return fields


def _find_timestamp(raw: str, fields: dict[str, Any] | None = None) -> tuple[datetime | None, tuple[int, int] | None]:
    fields = fields or {}
    for name in ("timestamp", "@timestamp", "time", "ts", "datetime"):
        if name in fields:
            parsed = _parse_timestamp(fields[name])
            if parsed:
                match = re.search(rf"\b{re.escape(name)}\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s]+)", raw, re.I)
                return parsed, match.span() if match else None
    for pattern, apache in ((_TIMESTAMP_SEARCH, False), (_APACHE_TIMESTAMP, True)):
        match = pattern.search(raw)
        if match:
            parsed = _parse_timestamp(match.group())
            if parsed:
                return parsed, match.span()
    return None, None


def _service_from_fields(fields: dict[str, Any]) -> str:
    for key in ("service", "service_name", "app", "application", "component", "logger", "container.name", "kubernetes.labels.app"):
        if fields.get(key):
            return str(fields[key])
    return "unknown"


def _extract_severity(raw: str) -> tuple[str | None, tuple[int, int] | None]:
    match = _SEVERITY.search(raw)
    if not match:
        return None, None
    group = "field" if match.group("field") else "plain"
    return _canonical_level(match.group(group)), match.span(group)


def _service_from_key_values(message: str) -> str | None:
    match = re.search(r"\b(?:service|app|component|logger)=([A-Za-z0-9_.:/-]+)", message, re.I)
    return match.group(1) if match else None


def _looks_like_service(token: str) -> bool:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{1,40}", token):
        return False
    return token.lower() not in _MESSAGE_FIRST_WORDS


def _parse_json_line(raw: str, line_number: int) -> LogEvent | None:
    if not raw.lstrip().startswith("{"):
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return _payload_to_event(payload, raw, line_number)


def _payload_to_event(payload: dict[str, Any], raw: str, line_number: int) -> LogEvent:
    timestamp = _nested_value(payload, "timestamp", "time", "@timestamp", "event.time", "ts", "timeUnixNano", "time_unix_nano", "datetime", "date")
    level = _nested_value(payload, "level", "severity_text", "severity", "log.level", "loglevel", "log_level", "levelname")
    if level is None:
        severity_number = _nested_value(payload, "severity_number", "severityNumber")
        try:
            number = int(severity_number)
            level = "TRACE" if number <= 4 else "DEBUG" if number <= 8 else "INFO" if number <= 12 else "WARN" if number <= 16 else "ERROR" if number <= 20 else "FATAL"
        except (TypeError, ValueError):
            pass
    message = _nested_value(payload, "message", "msg", "error", "log", "body", "event.message", "exception.message")
    service = _nested_value(payload, "service.name", "service_name", "resource.attributes.service.name", "app", "component", "logger", "container.name", "kubernetes.labels.app", "service")
    if isinstance(service, dict):
        service = service.get("name", service.get("service", "unknown"))
    message_text = str(message or "").strip() or raw
    warnings: list[str] = []
    if _parse_timestamp(timestamp) is None and timestamp not in (None, ""):
        warnings.append("unrecognized timestamp")
    return LogEvent(
        line_number=line_number,
        raw=raw,
        timestamp=_parse_timestamp(timestamp),
        severity=_infer_level(level, message_text),
        service=str(service or "unknown"),
        message=message_text,
        warnings=tuple(warnings),
    )


def parse_line(raw: str, line_number: int) -> LogEvent:
    """Parse one line, preserving it even when the format is incomplete."""

    stripped = raw.strip()
    json_event = _parse_json_line(stripped, line_number)
    if json_event:
        return json_event

    fields = _logfmt_fields(stripped)
    timestamp, timestamp_span = _find_timestamp(stripped, fields)
    explicit_level = fields.get("level") or fields.get("severity")
    level, level_span = _extract_severity(stripped)
    if explicit_level:
        level = _canonical_level(explicit_level)
    level = _infer_level(level, stripped)

    service = _service_from_fields(fields)
    if service == "unknown" and (timestamp_span or level_span):
        # Common format: timestamp LEVEL service-name message...
        working = stripped
        for span in sorted((timestamp_span, level_span), key=lambda part: part[0] if part else -1, reverse=True):
            if span:
                working = working[:span[0]] + " " + working[span[1]:]
        tokens = working.strip(" []|:-").split(maxsplit=2)
        if tokens and _looks_like_service(tokens[0]):
            service = tokens[0]
            service_inferred = True
        else:
            service_inferred = False
    else:
        service_inferred = False

    message = stripped
    remove_spans = [span for span in (timestamp_span, level_span) if span]
    for start, end in sorted(remove_spans, reverse=True):
        message = message[:start] + " " + message[end:]
    message = re.sub(r"\s+", " ", message).strip(" []|:-")
    if fields:
        # Keep the original text when removing structured fields would leave nothing useful.
        msg_field = fields.get("message") or fields.get("msg") or fields.get("error")
        if msg_field:
            message = msg_field
    if service != "unknown":
        message = re.sub(rf"\b(?:service|app|application|component|logger)={re.escape(service)}\b", "", message, flags=re.I).strip()
        if (service_inferred and timestamp_span) or (not service_inferred and (timestamp_span or level_span)):
            message = re.sub(rf"^\[?{re.escape(service)}\]?\s*:?\s*", "", message, flags=re.I)
    if not message:
        message = stripped

    warnings: list[str] = []
    if timestamp is None:
        warnings.append("timestamp unavailable or unrecognized")
    if not timestamp_span and not level_span and not fields:
        warnings.append("unrecognized format")
    if service == "unknown":
        warnings.append("service not identified")
    if not level_span and not any(key in fields for key in ("level", "severity", "levelname", "log_level")) and level == "INFO":
        warnings.append("severity inferred as INFO")

    return LogEvent(line_number, raw, timestamp, level, service, message, tuple(warnings))


def parse_log_text(text: str) -> list[LogEvent]:
    """Parse non-empty lines from pasted or uploaded log text."""

    if not any(line.strip() for line in text.splitlines()):
        return []

    # Accept pretty-printed JSON arrays as well as JSON-lines input.
    if text.lstrip().startswith("["):
        try:
            payloads = json.loads(text)
            if isinstance(payloads, list) and all(isinstance(item, dict) for item in payloads):
                return [_payload_to_event(item, json.dumps(item, ensure_ascii=False), index) for index, item in enumerate(payloads, start=1)]
        except json.JSONDecodeError:
            pass

    # Parse common CSV exports when a message column is present.
    try:
        reader = csv.DictReader(io.StringIO(text))
        headers = {str(name or "").strip().lower().lstrip("\ufeff") for name in (reader.fieldnames or [])}
        if headers & {"message", "msg", "log", "error"} and len(headers) >= 2:
            events = []
            for index, row in enumerate(reader, start=1):
                if not row or not any(value for value in row.values()):
                    continue
                normalized = {str(key or "").strip().lower().lstrip("\ufeff"): value for key, value in row.items()}
                events.append(_payload_to_event(normalized, str(row), index))
            if events:
                return events
    except csv.Error:
        pass

    return [parse_line(line, number) for number, line in enumerate(text.splitlines(), start=1) if line.strip()]

