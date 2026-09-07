from collections import defaultdict

from engine.models import SecurityEvent


WEB_SCAN_RULE_ID = "TL-WEB-001"


SENSITIVE_PATHS = {
    "/admin",
    "/wp-admin",
    "/.env",
    "/phpmyadmin",
    "/config",
    "/backup",
}


def detect_web_scanning(
    events: list[SecurityEvent],
    path_threshold: int = 3,
):
    """
    Detect one source probing multiple sensitive web paths.

    A single request to /admin should not automatically
    be classified as scanning.
    """

    events_by_ip = defaultdict(list)

    for event in events:
        if (
            event.event_type == "http_request"
            and event.source_ip
            and event.path
        ):
            events_by_ip[event.source_ip].append(event)

    findings = []

    for source_ip, source_events in events_by_ip.items():

        suspicious_events = [
            event
            for event in source_events
            if event.path.lower() in SENSITIVE_PATHS
        ]

        unique_paths = sorted({
            event.path.lower()
            for event in suspicious_events
        })

        if len(unique_paths) < path_threshold:
            continue

        findings.append({
            "rule_id": WEB_SCAN_RULE_ID,
            "severity": "Medium",
            "category": "Reconnaissance",
            "issue": "Possible Web Scanning Activity",
            "mitre": "T1595 - Active Scanning",
            "confidence": "High",

            "source_ip": source_ip,
            "paths_probed": unique_paths,
            "path_count": len(unique_paths),

            "evidence": [
                event.raw_event
                for event in suspicious_events
            ],

            "explanation": (
                f"{source_ip} requested "
                f"{len(unique_paths)} sensitive web paths: "
                f"{', '.join(unique_paths)}."
            ),

            "recommendation": (
                "Review activity from the source IP, inspect "
                "follow-up requests, apply rate limiting where "
                "appropriate, ensure administrative endpoints "
                "are not publicly exposed, and verify that "
                "sensitive configuration files cannot be accessed."
            ),
        })

    return findings