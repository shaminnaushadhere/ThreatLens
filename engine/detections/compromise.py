from collections import defaultdict
from datetime import timedelta

from engine.models import SecurityEvent


COMPROMISED_LOGIN_RULE_ID = "TL-AUTH-002"


def detect_compromised_login(
    events: list[SecurityEvent],
    failure_threshold: int = 3,
    window_seconds: int = 300,
):
    """
    Detect repeated failed SSH authentication attempts followed
    by a successful login from the same source IP.

    Important:
    A successful login alone is NOT considered malicious.
    """

    events_by_ip = defaultdict(list)

    # Group SSH authentication events by source IP
    for event in events:
        if (
            event.event_type == "authentication"
            and event.protocol == "ssh"
            and event.source_ip
            and event.timestamp
        ):
            events_by_ip[event.source_ip].append(event)

    findings = []

    for source_ip, source_events in events_by_ip.items():

        # Analyze events chronologically
        source_events.sort(key=lambda event: event.timestamp)

        for index, event in enumerate(source_events):

            # We only care about successful logins here
            if event.outcome != "success":
                continue

            window_start = event.timestamp - timedelta(
                seconds=window_seconds
            )

            # Find failures that occurred before this success
            # and inside our detection window
            prior_failures = [
                previous_event
                for previous_event in source_events[:index]
                if (
                    previous_event.outcome == "failure"
                    and previous_event.timestamp >= window_start
                )
            ]

            # Not enough evidence
            if len(prior_failures) < failure_threshold:
                continue

            evidence_events = prior_failures + [event]

            first_failure = prior_failures[0].timestamp

            duration_seconds = int(
                (event.timestamp - first_failure).total_seconds()
            )

            findings.append({
                "rule_id": COMPROMISED_LOGIN_RULE_ID,
                "severity": "Critical",
                "category": "Account Compromise",
                "issue": "Successful SSH Login After Repeated Failures",
                "mitre": "T1078 - Valid Accounts",
                "confidence": "High",

                "source_ip": source_ip,
                "username": event.username,

                "failed_attempts": len(prior_failures),
                "successful_logins": 1,

                "window_seconds": window_seconds,
                "observed_duration_seconds": duration_seconds,

                "evidence": [
                    evidence_event.raw_event
                    for evidence_event in evidence_events
                ],

                "explanation": (
                    f"{len(prior_failures)} failed SSH authentication "
                    f"attempts from {source_ip} were followed by a "
                    f"successful login for user '{event.username}' "
                    f"within {duration_seconds} seconds."
                ),

                "recommendation": (
                    "Verify whether the successful login was authorized. "
                    "Review activity performed after authentication, "
                    "including process execution, privilege escalation, "
                    "persistence, and network connections. Reset affected "
                    "credentials and isolate the host if compromise is confirmed."
                ),
            })

    return findings