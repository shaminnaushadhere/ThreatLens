from collections import defaultdict
from datetime import timedelta

from engine.models import SecurityEvent


FILE_BURST_RULE_ID = "TL-FILE-001"


def detect_rapid_file_activity(
    events: list[SecurityEvent],
    threshold: int = 20,
    window_seconds: int = 60,
):
    """
    Detect unusually high file-creation activity from
    the same host/process inside a short time window.

    This is NOT a ransomware verdict by itself.
    """

    grouped_events = defaultdict(list)

    for event in events:
        if (
            event.event_type == "file_creation"
            and event.timestamp
            and event.host
            and event.process
            and event.path
        ):
            key = (
                event.host,
                event.process,
            )

            grouped_events[key].append(event)

    findings = []

    for (host, process), file_events in grouped_events.items():

        file_events.sort(
            key=lambda event: event.timestamp
        )

        for start_index in range(len(file_events)):
            start_event = file_events[start_index]

            matching_events = []

            for current_event in file_events[start_index:]:

                time_difference = (
                    current_event.timestamp
                    - start_event.timestamp
                )

                if time_difference <= timedelta(
                    seconds=window_seconds
                ):
                    matching_events.append(
                        current_event
                    )

                else:
                    break

            if len(matching_events) < threshold:
                continue

            first_seen = matching_events[0].timestamp
            last_seen = matching_events[-1].timestamp

            duration_seconds = int(
                (
                    last_seen
                    - first_seen
                ).total_seconds()
            )

            unique_paths = sorted({
                event.path
                for event in matching_events
            })

            findings.append({
                "rule_id": FILE_BURST_RULE_ID,
                "severity": "Medium",
                "category": "Impact",
                "issue": "Rapid File Creation Activity",
                "mitre": "N/A",
                "confidence": "Medium",

                "host": host,
                "process": process,

                "file_count": len(
                    matching_events
                ),

                "unique_file_count": len(
                    unique_paths
                ),

                "window_seconds": window_seconds,

                "observed_duration_seconds":
                    duration_seconds,

                "first_seen": first_seen,
                "last_seen": last_seen,

                "paths": unique_paths,

                "evidence": [
                    event.raw_event
                    for event in matching_events
                ],

                "explanation": (
                    f"Process {process} on host {host} "
                    f"created {len(matching_events)} files "
                    f"within {duration_seconds} seconds. "
                    f"Rapid file activity can occur during "
                    f"bulk processing, software installation, "
                    f"backup activity, or ransomware-like behavior."
                ),

                "recommendation": (
                    "Review the process legitimacy, inspect "
                    "created file extensions and directories, "
                    "correlate with process execution and "
                    "destructive commands, and avoid classifying "
                    "the activity as ransomware without additional evidence."
                ),
            })

            break

    return findings