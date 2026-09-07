from collections import defaultdict
from datetime import timedelta


CORRELATION_RULE_ID = "TL-CORR-002"


def correlate_execution_persistence(
    findings: list[dict],
    events: list,
    window_seconds: int = 300,
):
    """
    Correlate suspicious execution activity with registry
    persistence on the same host within a short time window.

    Required signals:
    - TL-EXEC-001 or TL-EXEC-002
    - TL-PERSIST-001
    """

    suspicious_execution_rules = {
        "TL-EXEC-001",
        "TL-EXEC-002",
    }

    execution_findings = [
        finding
        for finding in findings
        if finding.get("rule_id")
        in suspicious_execution_rules
    ]

    persistence_findings = [
        finding
        for finding in findings
        if finding.get("rule_id")
        == "TL-PERSIST-001"
    ]

    incidents = []

    for execution in execution_findings:
        execution_host = execution.get("host")
        execution_time = execution.get("first_seen")

        if not execution_host or not execution_time:
            continue

        for persistence in persistence_findings:
            persistence_host = persistence.get("host")
            persistence_time = persistence.get("first_seen")

            if not persistence_host or not persistence_time:
                continue

            if execution_host != persistence_host:
                continue

            time_difference = (
                persistence_time
                - execution_time
            )

            if time_difference < timedelta(seconds=0):
                continue

            if time_difference > timedelta(
                seconds=window_seconds
            ):
                continue

            related_events = []

            for event in events:
                if event.host != execution_host:
                    continue

                if not event.timestamp:
                    continue

                if (
                    execution_time
                    <= event.timestamp
                    <= persistence_time
                ):
                    related_events.append(event)

            incidents.append({
                "incident_id": CORRELATION_RULE_ID,

                "severity": "Critical",

                "confidence": "High",

                "title": (
                    "Suspicious Execution Followed "
                    "by Registry Persistence"
                ),

                "category": (
                    "Execution and Persistence"
                ),

                "host": execution_host,

                "username": (
                    persistence.get("username")
                    or execution.get("username")
                ),

                "first_seen": execution_time,
                "last_seen": persistence_time,

                "observed_duration_seconds": int(
                    time_difference.total_seconds()
                ),

                "correlation_window_seconds":
                    window_seconds,

                "contributing_rules": [
                    execution.get("rule_id"),
                    persistence.get("rule_id"),
                ],

                "mitre": [
                    execution.get("mitre"),
                    persistence.get("mitre"),
                ],

                "evidence": [
                    event.raw_event
                    for event in related_events
                ],

                "explanation": (
                    "Suspicious execution activity was "
                    "followed by creation of a registry "
                    "Run/RunOnce persistence entry on the "
                    "same host within the correlation window."
                ),

                "recommendation": (
                    "Investigate the initiating process, "
                    "validate the registry persistence entry, "
                    "inspect the referenced executable, and "
                    "review surrounding network and file "
                    "activity on the affected host."
                ),
            })

    return incidents