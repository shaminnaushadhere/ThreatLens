import re
from datetime import datetime

from engine.models import SecurityEvent


FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<source_ip>(?:\d{1,3}\.){3}\d{1,3}) "
    r"port (?P<source_port>\d+)"
)

ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"Accepted password for (?P<username>\S+) "
    r"from (?P<source_ip>(?:\d{1,3}\.){3}\d{1,3}) "
    r"port (?P<source_port>\d+)"
)


def parse_syslog_timestamp(line: str):
    """
    Parse a traditional Linux syslog timestamp such as:
    Aug 24 18:30:01

    Traditional syslog does not contain the year,
    so ThreatLens uses the current year.
    """

    match = re.match(
        r"(?P<month>[A-Z][a-z]{2}) "
        r"(?P<day>\d{1,2}) "
        r"(?P<time>\d{2}:\d{2}:\d{2})",
        line,
    )

    if not match:
        return None

    timestamp_text = (
        f"{datetime.now().year} "
        f"{match.group('month')} "
        f"{match.group('day')} "
        f"{match.group('time')}"
    )

    try:
        return datetime.strptime(
            timestamp_text,
            "%Y %b %d %H:%M:%S",
        )

    except ValueError:
        return None


def parse_ssh_line(line: str):
    """
    Convert one supported SSH log line into a SecurityEvent.
    """

    failed_match = FAILED_PASSWORD_PATTERN.search(line)

    if failed_match:
        return SecurityEvent(
            timestamp=parse_syslog_timestamp(line),
            event_type="authentication",
            username=failed_match.group("username"),
            source_ip=failed_match.group("source_ip"),
            source_port=int(failed_match.group("source_port")),
            protocol="ssh",
            outcome="failure",
            raw_event=line,
            source_type="linux_ssh",
        )

    accepted_match = ACCEPTED_PASSWORD_PATTERN.search(line)

    if accepted_match:
        return SecurityEvent(
            timestamp=parse_syslog_timestamp(line),
            event_type="authentication",
            username=accepted_match.group("username"),
            source_ip=accepted_match.group("source_ip"),
            source_port=int(accepted_match.group("source_port")),
            protocol="ssh",
            outcome="success",
            raw_event=line,
            source_type="linux_ssh",
        )

    return None


def parse_ssh_logs(log_text: str):
    """
    Convert multiple supported SSH log lines into SecurityEvents.
    """

    events = []

    for line in log_text.splitlines():
        line = line.strip()

        if not line:
            continue

        event = parse_ssh_line(line)

        if event is not None:
            events.append(event)

    return events