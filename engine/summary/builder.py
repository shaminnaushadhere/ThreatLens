from collections import Counter


def build_analysis_summary(events, findings, incidents, risk):
    """
    Build the ThreatLens V2 user-facing summary.

    Extracts:
    - severity counts
    - affected hosts
    - users
    - IPs
    - domains
    - processes
    - files
    - registry paths
    - MITRE techniques
    - incident timeline
    """

    severity_counts = Counter(
        finding.get("severity", "Unknown")
        for finding in findings
    )

    hosts = set()
    users = set()
    ips = set()
    domains = set()
    processes = set()
    files = set()
    registry_paths = set()
    mitre_techniques = set()

    timeline = []

    # -------------------------------------------------
    # Extract entities from normalized events
    # -------------------------------------------------

    for event in events:

        if event.host:
            hosts.add(event.host)

        if event.username:
            users.add(event.username)

        if event.source_ip:
            ips.add(event.source_ip)

        if event.destination_ip:
            ips.add(event.destination_ip)

        if event.process:
            processes.add(event.process)

        if event.event_type == "dns_query" and event.path:
            domains.add(event.path)

        if event.event_type == "file_creation" and event.path:
            files.add(event.path)

        if event.event_type == "registry_value_set" and event.path:
            registry_paths.add(event.path)

    # -------------------------------------------------
    # Extract MITRE mappings from findings
    # -------------------------------------------------

    for finding in findings:

        mitre = finding.get("mitre")

        if mitre and mitre != "N/A":
            mitre_techniques.add(mitre)

    # -------------------------------------------------
    # Extract MITRE mappings from incidents
    # -------------------------------------------------

    for incident in incidents:

        mitre = incident.get("mitre")

        if isinstance(mitre, list):
            for technique in mitre:
                if technique and technique != "N/A":
                    mitre_techniques.add(technique)

        elif mitre and mitre != "N/A":
            mitre_techniques.add(mitre)


    # -------------------------------------------------
    # Build security timeline from findings
    # -------------------------------------------------

    for finding in findings:

        first_seen = finding.get("first_seen")

        timeline.append({
            "timestamp": (
                first_seen.isoformat()
                if first_seen
                else None
            ),

            "event": finding.get(
                "issue",
                "Security Finding",
            ),

            "severity": finding.get(
                "severity",
                "Unknown",
            ),

            "rule_id": finding.get(
                "rule_id"
            ),

            "incident_id": None,

            "host": finding.get(
                "host"
            ),

            "type": "finding",
        })


    # -------------------------------------------------
    # Add correlated incidents to timeline
    # -------------------------------------------------

    for incident in incidents:

        first_seen = incident.get("first_seen")

        timeline.append({
            "timestamp": (
                first_seen.isoformat()
                if first_seen
                else None
            ),

            "event": incident.get(
                "title",
                incident.get(
                    "incident_id",
                    "Security Incident",
                ),
            ),

            "severity": incident.get(
                "severity",
                "Unknown",
            ),

            "rule_id": None,

            "incident_id": incident.get(
                "incident_id"
            ),

            "host": incident.get(
                "host"
            ),

            "type": "incident",
        })


    # -------------------------------------------------
    # Sort timeline chronologically
    # -------------------------------------------------

    timeline.sort(
        key=lambda item: (
            item["timestamp"] is None,
            item["timestamp"] or "",
        )
    )

    # Sort timeline by timestamp where possible
    timeline.sort(
        key=lambda item: (
            item["timestamp"] is None,
            item["timestamp"] or "",
        )
    )

    # -------------------------------------------------
    # Executive summary text
    # -------------------------------------------------

    if incidents:
        executive_summary = (
            f"ThreatLens analyzed {len(events)} security events "
            f"and identified {len(findings)} findings across "
            f"{len(incidents)} correlated incident(s). "
            f"Overall risk is {risk['risk_level']} "
            f"({risk['risk_score']}/100)."
        )

    elif findings:
        executive_summary = (
            f"ThreatLens analyzed {len(events)} security events "
            f"and identified {len(findings)} security finding(s). "
            f"No multi-stage incident correlation was confirmed. "
            f"Overall risk is {risk['risk_level']} "
            f"({risk['risk_score']}/100)."
        )

    else:
        executive_summary = (
            f"ThreatLens analyzed {len(events)} security events "
            f"and did not identify activity matching the current "
            f"detection rules. Overall risk is "
            f"{risk['risk_level']} ({risk['risk_score']}/100)."
        )

    # -------------------------------------------------
    # Final V2 summary
    # -------------------------------------------------

    return {
        "events_parsed": len(events),
        "findings_count": len(findings),
        "incidents_count": len(incidents),

        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],

        "critical": severity_counts.get("Critical", 0),
        "high": severity_counts.get("High", 0),
        "medium": severity_counts.get("Medium", 0),
        "low": severity_counts.get("Low", 0),

        "hosts": sorted(hosts),
        "users": sorted(users),
        "ips": sorted(ips),
        "domains": sorted(domains),
        "processes": sorted(processes),
        "files": sorted(files),
        "registry_paths": sorted(registry_paths),

        "mitre_techniques": sorted(
            mitre_techniques
        ),

        "timeline": timeline,

        "executive_summary": executive_summary,
    }