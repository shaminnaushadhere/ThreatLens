from collections import defaultdict
from statistics import mean, pstdev

from engine.models import SecurityEvent


C2_BEACON_RULE_ID = "TL-C2-001"


def detect_c2_beaconing(
    events: list[SecurityEvent],
    minimum_connections: int = 5,
    max_interval_deviation_seconds: float = 5.0,
):
    """
    Detect possible command-and-control beaconing based on
    repeated network connections with regular timing.

    Current logic:
    - Same host
    - Same process
    - Same destination IP
    - Same destination port
    - At least minimum_connections
    - Low variation between connection intervals

    This is a behavioral heuristic, not proof of C2.
    """

    grouped_connections = defaultdict(list)

    for event in events:
        if (
            event.event_type == "network_connection"
            and event.timestamp
            and event.host
            and event.destination_ip
            and event.destination_port is not None
        ):
            key = (
                event.host,
                event.process or "unknown",
                event.destination_ip,
                event.destination_port,
            )

            grouped_connections[key].append(event)

    findings = []

    for (
        host,
        process,
        destination_ip,
        destination_port,
    ), connection_events in grouped_connections.items():

        if len(connection_events) < minimum_connections:
            continue

        connection_events.sort(
            key=lambda event: event.timestamp
        )

        intervals = []

        for index in range(1, len(connection_events)):
            interval = (
                connection_events[index].timestamp
                - connection_events[index - 1].timestamp
            ).total_seconds()

            intervals.append(interval)

        if not intervals:
            continue

        average_interval = mean(intervals)

        interval_deviation = (
            pstdev(intervals)
            if len(intervals) > 1
            else 0.0
        )

        if interval_deviation > max_interval_deviation_seconds:
            continue

        first_seen = connection_events[0].timestamp
        last_seen = connection_events[-1].timestamp

        findings.append({
            "rule_id": C2_BEACON_RULE_ID,
            "severity": "High",
            "category": "Command and Control",
            "issue": "Possible C2 Beaconing Activity",
            "mitre": "T1071 - Application Layer Protocol",
            "confidence": "Medium",

            "host": host,
            "process": process,

            "destination_ip": destination_ip,
            "destination_port": destination_port,

            "connection_count": len(connection_events),

            "average_interval_seconds": round(
                average_interval,
                2,
            ),

            "interval_deviation_seconds": round(
                interval_deviation,
                2,
            ),

            "first_seen": first_seen,
            "last_seen": last_seen,

            "evidence": [
                event.raw_event
                for event in connection_events
            ],

            "explanation": (
                f"{len(connection_events)} connections from host "
                f"{host} to {destination_ip}:{destination_port} "
                f"occurred at an average interval of "
                f"{average_interval:.2f} seconds with only "
                f"{interval_deviation:.2f} seconds of timing "
                f"variation. Repeated low-variance communication "
                f"may indicate automated beaconing."
            ),

            "recommendation": (
                "Review the destination reputation, inspect the "
                "originating process, compare traffic against the "
                "host's normal behavior, inspect DNS and proxy logs, "
                "and correlate with suspicious execution or persistence "
                "activity before confirming command-and-control."
            ),
        })

    return findings