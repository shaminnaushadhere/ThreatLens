from engine.models import SecurityEvent


SUSPICIOUS_POWERSHELL_RULE_ID = "TL-EXEC-001"


def detect_suspicious_powershell(events: list[SecurityEvent]):
    """
    Detect suspicious encoded PowerShell execution.

    This rule focuses on encoded-command behavior rather than
    flagging all PowerShell activity.
    """

    findings = []

    indicators = [
        "-encodedcommand",
        "encodedcommand",
        "-enc",
        "-e ",
    ]

    for event in events:
        if event.event_type != "process_execution":
            continue

        if not event.command_line:
            continue

        process = (
            event.process.lower()
            if event.process
            else ""
        )

        command_line = event.command_line.lower()

        if (
            "powershell" not in process
            and "powershell" not in command_line
        ):
            continue

        matched_indicators = [
            indicator
            for indicator in indicators
            if indicator in command_line
        ]

        if not matched_indicators:
            continue

        findings.append({
            "rule_id": SUSPICIOUS_POWERSHELL_RULE_ID,
            "severity": "High",
            "category": "Execution",
            "issue": "Suspicious Encoded PowerShell Execution",
            "mitre": "T1059.001 - PowerShell",
            "confidence": "High",

            # Correlation metadata
            "host": event.host,
            "username": event.username,

            # Process evidence
            "process": event.process,
            "parent_process": event.parent_process,
            "command_line": event.command_line,

            # Time metadata
            "first_seen": event.timestamp,
            "last_seen": event.timestamp,

            "matched_indicators": matched_indicators,

            "evidence": [
                event.raw_event
            ],

            "explanation": (
                "PowerShell was executed with encoded-command behavior. "
                "Encoded PowerShell is frequently used to obscure command "
                "contents and can indicate malicious or evasive execution."
            ),

            "recommendation": (
                "Decode and review the PowerShell command, inspect the "
                "parent process, verify the user and host context, review "
                "network activity, and correlate with additional endpoint "
                "telemetry before confirming compromise."
            ),
        })

    return findings