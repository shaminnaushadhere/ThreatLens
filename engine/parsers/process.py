import re
from datetime import datetime

from engine.models import SecurityEvent


DETAILED_PROCESS_PATTERN = re.compile(
    r"Timestamp:\s*(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"Host:\s*(?P<host>\S+)\s+"
    r"User:\s*(?P<username>\S+)\s+"
    r"Process:\s*(?P<process>\S+)\s+"
    r"CommandLine:\s*(?P<command_line>.+)",
    re.IGNORECASE,
)


def parse_process_timestamp(timestamp_text: str):
    try:
        return datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S",
        )
    except ValueError:
        return None


def parse_process_line(line: str):
    """
    Parse process execution telemetry.

    Preferred V2 format:

    Timestamp: 2026-08-25 18:10:01 Host: WIN-DEV-04 User: admin
    Process: powershell.exe CommandLine: powershell.exe -EncodedCommand TEST

    The older simplified format is still supported.
    """

    detailed_match = DETAILED_PROCESS_PATTERN.search(line)

    if detailed_match:
        return SecurityEvent(
            timestamp=parse_process_timestamp(
                detailed_match.group("timestamp")
            ),
            event_type="process_execution",
            host=detailed_match.group("host"),
            username=detailed_match.group("username"),
            process=detailed_match.group("process"),
            command_line=detailed_match.group("command_line"),
            raw_event=line,
            source_type="process_telemetry",
        )

    # Backward compatibility with our existing test format
    if "Process:" not in line or "CommandLine:" not in line:
        return None

    try:
        process_part, command_part = line.split(
            "CommandLine:",
            1,
        )

        process = process_part.replace(
            "Process:",
            "",
        ).strip()

        command_line = command_part.strip()

        if not process or not command_line:
            return None

        return SecurityEvent(
            event_type="process_execution",
            process=process,
            command_line=command_line,
            raw_event=line,
            source_type="process_telemetry",
        )

    except ValueError:
        return None


def parse_process_logs(log_text: str):
    events = []

    for line in log_text.splitlines():
        line = line.strip()

        if not line:
            continue

        event = parse_process_line(line)

        if event is not None:
            events.append(event)

    return events