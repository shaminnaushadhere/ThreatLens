from collections import defaultdict
from datetime import timedelta

from engine.models import SecurityEvent


SSH_BRUTE_FORCE_RULE_ID = "TL-AUTH-001"


def detect_ssh_bruteforce(
    events: list[SecurityEvent],
    threshold: int = 5,
    window_seconds: int = 60,
):
    """
    Detect repeated failed SSH authentication attempts
    from the same source IP within a defined time window.
    """

    failed_events_by_ip = defaultdict(list)

    for event in events:
        if (
            event.event_type == "authentication"
            and event.protocol == "ssh"
            and event.outcome == "failure"
            and event.source_ip
            and event.timestamp
        ):
            failed_events_by_ip[event.source_ip].append(event)

    findings = []

    for source_ip, source_events in failed_events_by_ip.items():

        # Ensure events are in chronological order
        source_events.sort(key=lambda event: event.timestamp)

        for start_index in range(len(source_events)):
            start_event = source_events[start_index]

            matching_events = []

            for current_event in source_events[start_index:]:

                time_difference = (
                    current_event.timestamp - start_event.timestamp
                )

                if time_difference <= timedelta(seconds=window_seconds):
                    matching_events.append(current_event)
                else:
                    break

            if len(matching_events) >= threshold:

                first_timestamp = matching_events[0].timestamp
                last_timestamp = matching_events[-1].timestamp

                duration_seconds = int(
                    (last_timestamp - first_timestamp).total_seconds()
                )

                findings.append({
                    "rule_id": SSH_BRUTE_FORCE_RULE_ID,
                    "severity": "High",
                    "category": "Credential Access",
                    "issue": "SSH Brute Force Attempt",
                    "mitre": "T1110 - Brute Force",
                    "confidence": "High",
                    "source_ip": source_ip,
                    "event_count": len(matching_events),
                    "window_seconds": window_seconds,
                    "observed_duration_seconds": duration_seconds,

                    "evidence": [
                        event.raw_event
                        for event in matching_events
                    ],

                    "explanation": (
                        f"{len(matching_events)} failed SSH authentication "
                        f"attempts from {source_ip} occurred within "
                        f"{duration_seconds} seconds."
                    ),

                    "recommendation": (
                        "Review authentication activity from the source IP, "
                        "check for successful logins, enforce MFA where "
                        "possible, and consider rate limiting or blocking "
                        "repeated authentication failures."
                    ),
                })

                # Prevent duplicate findings for the same burst
                break

    return findings