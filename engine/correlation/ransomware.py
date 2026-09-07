def correlate_ransomware_activity(
    findings: list[dict],
    events: list,
    window_seconds: int = 300,
):
    """
    Correlate suspicious execution, recovery inhibition,
    and rapid file activity on the same host.

    The combination provides substantially stronger evidence
    of ransomware-like behavior than any individual signal.
    """

    incidents = []

    execution_findings = [
        finding
        for finding in findings
        if finding.get("rule_id") in {
            "TL-EXEC-001",
            "TL-EXEC-002",
        }
    ]

    impact_findings = [
        finding
        for finding in findings
        if finding.get("rule_id") == "TL-IMPACT-001"
    ]

    file_findings = [
        finding
        for finding in findings
        if finding.get("rule_id") == "TL-FILE-001"
    ]

    for execution in execution_findings:

        execution_host = execution.get("host")
        execution_time = execution.get("first_seen")

        if not execution_host or not execution_time:
            continue

        for impact in impact_findings:

            if impact.get("host") != execution_host:
                continue

            impact_time = impact.get("first_seen")

            if not impact_time:
                continue

            execution_to_impact = (
                impact_time - execution_time
            ).total_seconds()

            if not 0 <= execution_to_impact <= window_seconds:
                continue

            for file_activity in file_findings:

                if file_activity.get("host") != execution_host:
                    continue

                file_time = file_activity.get("first_seen")

                if not file_time:
                    continue

                execution_to_files = (
                    file_time - execution_time
                ).total_seconds()

                if not 0 <= execution_to_files <= window_seconds:
                    continue

                last_seen = max(
                    execution.get("last_seen") or execution_time,
                    impact.get("last_seen") or impact_time,
                    file_activity.get("last_seen") or file_time,
                )

                related_events = [
                    event.raw_event
                    for event in events
                    if (
                        event.host == execution_host
                        and event.timestamp is not None
                        and execution_time
                        <= event.timestamp
                        <= last_seen
                    )
                ]

                incidents.append({
                    "incident_id": "TL-RANSOM-001",
                    "severity": "Critical",
                    "confidence": "High",

                    "title": (
                        "High-Confidence Ransomware-Like Activity"
                    ),

                    "category": "Impact",

                    "host": execution_host,
                    "username": (
                        execution.get("username")
                        or impact.get("username")
                        or file_activity.get("username")
                    ),

                    "first_seen": execution_time,
                    "last_seen": last_seen,

                    "observed_duration_seconds": (
                        last_seen - execution_time
                    ).total_seconds(),

                    "correlation_window_seconds": window_seconds,

                    "contributing_rules": [
                        execution["rule_id"],
                        "TL-IMPACT-001",
                        "TL-FILE-001",
                    ],

                    "mitre": [
                        technique
                        for technique in [
                            execution.get("mitre"),
                            impact.get("mitre"),
                            file_activity.get("mitre"),
                            "T1486 - Data Encrypted for Impact",
                        ]
                        if technique and technique != "N/A"
                    ],

                    "evidence": related_events,

                    "explanation": (
                        "ThreatLens observed suspicious execution, "
                        "recovery-inhibition behavior, and rapid file "
                        "activity on the same host within a short time "
                        "window. Together, these behaviors are strongly "
                        "consistent with ransomware-like activity."
                    ),

                    "recommendation": (
                        "Immediately investigate and consider isolating "
                        "the affected host. Review process ancestry, "
                        "recent file modifications, recovery configuration, "
                        "network activity, user activity, and additional "
                        "endpoint telemetry to determine the scope and "
                        "confirm whether destructive encryption occurred."
                    ),
                })

    return incidents