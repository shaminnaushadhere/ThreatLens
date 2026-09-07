import re
from datetime import datetime

from engine.models import SecurityEvent


APACHE_LOG_PATTERN = re.compile(
    r'(?P<source_ip>(?:\d{1,3}\.){3}\d{1,3}) '
    r'.*?\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" '
    r'(?P<status_code>\d{3})'
)


def parse_web_timestamp(timestamp_text: str):
    """
    Parse Apache/Nginx-style timestamps such as:

    31/May/2026:12:15:01 -0700
    """

    try:
        return datetime.strptime(
            timestamp_text,
            "%d/%b/%Y:%H:%M:%S %z",
        )
    except ValueError:
        return None


def parse_web_line(line: str):
    """
    Convert one supported Apache/Nginx access-log line
    into a normalized SecurityEvent.
    """

    match = APACHE_LOG_PATTERN.search(line)

    if not match:
        return None

    return SecurityEvent(
        timestamp=parse_web_timestamp(
            match.group("timestamp")
        ),
        event_type="http_request",
        source_ip=match.group("source_ip"),
        path=match.group("path"),
        protocol="http",
        outcome=match.group("status_code"),
        raw_event=line,
        source_type="web_access",
    )


def parse_web_logs(log_text: str):
    """
    Convert supported web access logs into SecurityEvents.
    """

    events = []

    for line in log_text.splitlines():
        line = line.strip()

        if not line:
            continue

        event = parse_web_line(line)

        if event is not None:
            events.append(event)

    return events