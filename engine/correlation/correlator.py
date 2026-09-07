from collections import defaultdict
from datetime import timedelta


CORRELATED_EXECUTION_INCIDENT_ID = "TL-CORR-001"


def correlate_execution_findings(
    findings: list[dict],
    events: list,
    window_seconds: int = 120,
):
    """
    Correlate suspicious execution activity using:

    - TL-EXEC-001: Encoded PowerShell
    - TL-EXEC-002: Suspicious Download
    - Same host
    - Close timing

    This avoids correlating unrelated findings from different hosts.
    """

    incidents = []

    # Group process events by host
    events_by_host = defaultdict(list)

    for event in events:
        if (
            event.event_type == "process_execution"
            and event.host
            and event.timestamp
        ):
            events_by_host[event.host].append(event)

    for host, host_events in events_by_host.items():
        host_events.sort(key=lambda event: event.timestamp)

        for index, first_event in enumerate(host_events):

            first_command = (first_event.command_line or "").lower()

            encoded_powershell = (
                "powershell" in (first_event.process or "").lower()
                and (
                    "-enc" in first_command
                    or "-encodedcommand" in first_command
                    or "encodedcommand" in first_command
                )
            )

            if not encoded_powershell:
                continue

            for second_event in host_events[index + 1:]:

                time_delta = (
                    second_event.timestamp - first_event.timestamp
                )

                if time_delta > timedelta(seconds=window_seconds):
                    break

                second_command = (
                    second_event.command_line or ""
                ).lower()

                suspicious_download = any(
                    pattern in second_command
                    for pattern in [
                        "invoke-webrequest",
                        "downloadstring",
                        "downloadfile",
                        "start-bitstransfer",
                        "bitsadmin /transfer",
                        "certutil -urlcache",
                        "certutil.exe -urlcache",
                    ]
                )

                if not suspicious_download:
                    continue

                duration_seconds = int(
                    time_delta.total_seconds()
                )

                incidents.append({
                    "incident_id": CORRELATED_EXECUTION_INCIDENT_ID,
                    "severity": "Critical",
                    "confidence": "High",

                    "title": "Suspicious PowerShell Download Chain",
                    "category": "Possible Malware Execution",

                    "host": host,
                    "username": (
                        first_event.username
                        or second_event.username
                    ),

                    "first_seen": first_event.timestamp,
                    "last_seen": second_event.timestamp,

                    "observed_duration_seconds": duration_seconds,
                    "correlation_window_seconds": window_seconds,

                    "contributing_rules": [
                        "TL-EXEC-001",
                        "TL-EXEC-002",
                    ],

                    "evidence": [
                        first_event.raw_event,
                        second_event.raw_event,
                    ],

                    "explanation": (
                        f"Encoded PowerShell execution on host {host} "
                        f"was followed by suspicious download behavior "
                        f"within {duration_seconds} seconds. "
                        f"Multiple related execution behaviors on the "
                        f"same host increase confidence that the activity "
                        f"may represent malicious payload delivery."
                    ),

                    "recommendation": (
                        "Decode and inspect the PowerShell content, "
                        "identify the downloaded resource, collect file "
                        "hashes, review parent-child process relationships, "
                        "inspect network connections, and isolate the host "
                        "if additional malicious activity is confirmed."
                    ),
                })

                # One correlated incident for this chain
                break

    return incidents