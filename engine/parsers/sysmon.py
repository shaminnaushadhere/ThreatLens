import re
from datetime import datetime

from engine.models import SecurityEvent


EVENT_ID_PATTERN = re.compile(
    r"EventID[:=]\s*(?P<event_id>\d+)",
    re.IGNORECASE,
)

UTC_TIME_PATTERN = re.compile(
    r"UtcTime[:=]\s*(?P<timestamp>[^\r\n]+)",
    re.IGNORECASE,
)

COMPUTER_PATTERN = re.compile(
    r"Computer[:=]\s*(?P<computer>[^\r\n]+)",
    re.IGNORECASE,
)

USER_PATTERN = re.compile(
    r"User[:=]\s*(?P<user>[^\r\n]+)",
    re.IGNORECASE,
)

IMAGE_PATTERN = re.compile(
    r"Image[:=]\s*(?P<image>[^\r\n]+)",
    re.IGNORECASE,
)

COMMAND_LINE_PATTERN = re.compile(
    r"CommandLine[:=]\s*(?P<command_line>[^\r\n]+)",
    re.IGNORECASE,
)

PARENT_IMAGE_PATTERN = re.compile(
    r"ParentImage[:=]\s*(?P<parent_image>[^\r\n]+)",
    re.IGNORECASE,
)

SOURCE_IP_PATTERN = re.compile(
    r"SourceIp[:=]\s*(?P<source_ip>[^\r\n]+)",
    re.IGNORECASE,
)

SOURCE_PORT_PATTERN = re.compile(
    r"SourcePort[:=]\s*(?P<source_port>\d+)",
    re.IGNORECASE,
)

DESTINATION_IP_PATTERN = re.compile(
    r"DestinationIp[:=]\s*(?P<destination_ip>[^\r\n]+)",
    re.IGNORECASE,
)

DESTINATION_PORT_PATTERN = re.compile(
    r"DestinationPort[:=]\s*(?P<destination_port>\d+)",
    re.IGNORECASE,
)

PROTOCOL_PATTERN = re.compile(
    r"Protocol[:=]\s*(?P<protocol>[^\r\n]+)",
    re.IGNORECASE,
)

TARGET_FILENAME_PATTERN = re.compile(
    r"TargetFilename[:=]\s*(?P<target_filename>[^\r\n]+)",
    re.IGNORECASE,
)

TARGET_OBJECT_PATTERN = re.compile(
    r"TargetObject[:=]\s*(?P<target_object>[^\r\n]+)",
    re.IGNORECASE,
)

DETAILS_PATTERN = re.compile(
    r"Details[:=]\s*(?P<details>[^\r\n]+)",
    re.IGNORECASE,
)

QUERY_NAME_PATTERN = re.compile(
    r"QueryName[:=]\s*(?P<query_name>[^\r\n]+)",
    re.IGNORECASE,
)

QUERY_RESULTS_PATTERN = re.compile(
    r"QueryResults[:=]\s*(?P<query_results>[^\r\n]+)",
    re.IGNORECASE,
)


def parse_sysmon_timestamp(value: str):
    value = value.strip()

    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]

    for timestamp_format in formats:
        try:
            return datetime.strptime(
                value,
                timestamp_format,
            )
        except ValueError:
            continue

    return None


def _extract(pattern, text):
    match = pattern.search(text)

    if not match:
        return None

    for value in match.groupdict().values():
        if value is not None:
            return value.strip()

    return None


def parse_sysmon_event(event_text: str):
    """
    Supported Sysmon events:
    Event ID 1  - Process Create
    Event ID 3  - Network Connection
    Event ID 11 - File Create
    Event ID 13 - Registry Value Set
    Event ID 22 - DNS Query
    """

    event_id = _extract(
        EVENT_ID_PATTERN,
        event_text,
    )

    if not event_id:
        return None

    timestamp_text = _extract(
        UTC_TIME_PATTERN,
        event_text,
    )

    timestamp = (
        parse_sysmon_timestamp(timestamp_text)
        if timestamp_text
        else None
    )

    # Event ID 1 - Process Create
    if event_id == "1":
        return SecurityEvent(
            timestamp=timestamp,
            event_type="process_execution",
            host=_extract(COMPUTER_PATTERN, event_text),
            username=_extract(USER_PATTERN, event_text),
            process=_extract(IMAGE_PATTERN, event_text),
            parent_process=_extract(
                PARENT_IMAGE_PATTERN,
                event_text,
            ),
            command_line=_extract(
                COMMAND_LINE_PATTERN,
                event_text,
            ),
            raw_event=event_text,
            source_type="sysmon_event_1",
        )

    # Event ID 3 - Network Connection
    if event_id == "3":
        source_port = _extract(
            SOURCE_PORT_PATTERN,
            event_text,
        )

        destination_port = _extract(
            DESTINATION_PORT_PATTERN,
            event_text,
        )

        return SecurityEvent(
            timestamp=timestamp,
            event_type="network_connection",
            host=_extract(COMPUTER_PATTERN, event_text),
            username=_extract(USER_PATTERN, event_text),
            process=_extract(IMAGE_PATTERN, event_text),
            source_ip=_extract(
                SOURCE_IP_PATTERN,
                event_text,
            ),
            destination_ip=_extract(
                DESTINATION_IP_PATTERN,
                event_text,
            ),
            source_port=(
                int(source_port)
                if source_port
                else None
            ),
            destination_port=(
                int(destination_port)
                if destination_port
                else None
            ),
            protocol=_extract(
                PROTOCOL_PATTERN,
                event_text,
            ),
            raw_event=event_text,
            source_type="sysmon_event_3",
        )

    # Event ID 11 - File Create
    if event_id == "11":
        return SecurityEvent(
            timestamp=timestamp,
            event_type="file_creation",
            host=_extract(COMPUTER_PATTERN, event_text),
            username=_extract(USER_PATTERN, event_text),
            process=_extract(IMAGE_PATTERN, event_text),
            path=_extract(
                TARGET_FILENAME_PATTERN,
                event_text,
            ),
            raw_event=event_text,
            source_type="sysmon_event_11",
        )

    # Event ID 13 - Registry Value Set
    if event_id == "13":
        target_object = _extract(
            TARGET_OBJECT_PATTERN,
            event_text,
        )

        details = _extract(
            DETAILS_PATTERN,
            event_text,
        )

        return SecurityEvent(
            timestamp=timestamp,
            event_type="registry_value_set",
            host=_extract(COMPUTER_PATTERN, event_text),
            username=_extract(USER_PATTERN, event_text),
            process=_extract(IMAGE_PATTERN, event_text),

            # For now, store the registry path here.
            path=target_object,

            # Preserve the value/data in command_line temporarily
            # so we don't need to change SecurityEvent yet.
            command_line=details,

            raw_event=event_text,
            source_type="sysmon_event_13",
        )

    # Event ID 22 - DNS Query
    if event_id == "22":
        query_name = _extract(
            QUERY_NAME_PATTERN,
            event_text,
        )

        query_results = _extract(
            QUERY_RESULTS_PATTERN,
            event_text,
        )

        return SecurityEvent(
            timestamp=timestamp,
            event_type="dns_query",
            host=_extract(COMPUTER_PATTERN, event_text),
            username=_extract(USER_PATTERN, event_text),
            process=_extract(IMAGE_PATTERN, event_text),

            # Store the queried domain in path for now.
            path=query_name,

            # Preserve DNS response information temporarily.
            command_line=query_results,

            raw_event=event_text,
            source_type="sysmon_event_22",
        )

     
    return None


def parse_sysmon_logs(log_text: str):
    """
    Parse multiple Sysmon events separated by blank lines.
    """

    events = []

    blocks = re.split(
        r"\n\s*\n",
        log_text.strip(),
    )

    for block in blocks:
        block = block.strip()

        if not block:
            continue

        event = parse_sysmon_event(block)

        if event is not None:
            events.append(event)

    return events