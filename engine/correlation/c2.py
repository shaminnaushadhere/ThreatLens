from datetime import timedelta


C2_CORRELATION_ID = "TL-CORR-003"


def correlate_dns_with_c2(
    findings: list[dict],
    events: list,
    window_seconds: int = 300,
):
    """
    Correlate Sysmon DNS query activity with TL-C2-001
    network beaconing.

    Required conditions:
    - TL-C2-001 finding exists
    - DNS query occurred on the same host
    - DNS query came from the same process
    - DNS result contains the beacon destination IP
    - DNS query occurred shortly before or during beaconing
    """

    incidents = []

    c2_findings = [
        finding
        for finding in findings
        if finding.get("rule_id") == "TL-C2-001"
    ]

    dns_events = [
        event
        for event in events
        if (
            event.event_type == "dns_query"
            and event.timestamp
            and event.host
            and event.path
        )
    ]

    for c2_finding in c2_findings:
        c2_host = c2_finding.get("host")
        c2_process = c2_finding.get("process")
        destination_ip = c2_finding.get("destination_ip")
        first_seen = c2_finding.get("first_seen")
        last_seen = c2_finding.get("last_seen")

        if not (
            c2_host
            and destination_ip
            and first_seen
            and last_seen
        ):
            continue

        correlation_start = (
            first_seen
            - timedelta(seconds=window_seconds)
        )

        matching_dns_events = []

        for dns_event in dns_events:

            if dns_event.host != c2_host:
                continue

            if (
                c2_process
                and dns_event.process
                and dns_event.process != c2_process
            ):
                continue

            if not (
                correlation_start
                <= dns_event.timestamp
                <= last_seen
            ):
                continue

            dns_results = (
                dns_event.command_line or ""
            )

            if destination_ip not in dns_results:
                continue

            matching_dns_events.append(dns_event)

        if not matching_dns_events:
            continue

        first_dns = min(
            event.timestamp
            for event in matching_dns_events
        )

        related_evidence = [
            event.raw_event
            for event in matching_dns_events
        ]

        related_evidence.extend(
            c2_finding.get("evidence", [])
        )

        incidents.append({
            "incident_id": C2_CORRELATION_ID,
            "severity": "High",
            "confidence": "High",

            "title": (
                "DNS-Resolved C2 Beaconing Activity"
            ),

            "category": "Command and Control",

            "host": c2_host,
            "process": c2_process,

            "destination_ip": destination_ip,
            "destination_port": (
                c2_finding.get("destination_port")
            ),

            "queried_domains": sorted({
                event.path
                for event in matching_dns_events
            }),

            "first_seen": first_dns,
            "last_seen": last_seen,

            "contributing_rules": [
                "TL-C2-001",
            ],

            "mitre": [
                "T1071 - Application Layer Protocol",
                "T1071.004 - DNS",
            ],

            "evidence": related_evidence,

            "explanation": (
                "ThreatLens observed a DNS query whose "
                "resolved destination matched the IP used "
                "by a periodic beaconing pattern on the "
                "same host and process. This additional "
                "DNS context increases confidence that the "
                "network activity may represent command-and-control."
            ),

            "recommendation": (
                "Review the queried domain and destination reputation, "
                "inspect the originating process, check proxy and DNS "
                "history, and correlate with execution, persistence, "
                "or additional suspicious endpoint behavior."
            ),
        })

    return incidents