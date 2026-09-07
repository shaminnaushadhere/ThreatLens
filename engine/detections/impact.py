from engine.models import SecurityEvent


RECOVERY_INHIBITION_RULE_ID = "TL-IMPACT-001"


def detect_recovery_inhibition(events: list[SecurityEvent]):
    """
    Detect command-line behavior associated with inhibiting
    system recovery mechanisms.

    This is a behavioral signal and does not by itself prove
    ransomware activity.
    """

    findings = []

    patterns = [
        ("vssadmin", "delete", "shadows"),
        ("wmic", "shadowcopy", "delete"),
        ("wbadmin", "delete", "catalog"),
        ("bcdedit", "recoveryenabled", "no"),
        ("bcdedit", "bootstatuspolicy", "ignoreallfailures"),
    ]

    for event in events:
        if event.event_type != "process_execution":
            continue

        if not event.command_line:
            continue

        command_line = event.command_line.lower()

        matched_patterns = []

        for pattern in patterns:
            if all(token in command_line for token in pattern):
                matched_patterns.append(" ".join(pattern))

        if not matched_patterns:
            continue

        findings.append({
            "rule_id": RECOVERY_INHIBITION_RULE_ID,
            "severity": "Critical",
            "category": "Impact",
            "issue": "Suspicious Recovery Inhibition Activity",
            "mitre": "T1490 - Inhibit System Recovery",
            "confidence": "High",

            "host": event.host,
            "username": event.username,
            "process": event.process,
            "parent_process": event.parent_process,
            "command_line": event.command_line,

            "first_seen": event.timestamp,
            "last_seen": event.timestamp,

            "matched_indicators": matched_patterns,

            "evidence": [
                event.raw_event
            ],

            "explanation": (
                "A process executed a command associated with modifying "
                "or removing system recovery mechanisms. This behavior "
                "can occur during destructive attacks, including some "
                "ransomware operations."
            ),

            "recommendation": (
                "Investigate the process and user context, verify whether "
                "the activity was authorized, review nearby process and "
                "file activity, and check for additional impact-related "
                "behavior on the host."
            ),
        })

    return findings