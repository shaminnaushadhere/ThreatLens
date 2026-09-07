from engine.models import SecurityEvent


SUSPICIOUS_DOWNLOAD_RULE_ID = "TL-EXEC-002"


DOWNLOAD_PATTERNS = [
    "invoke-webrequest",
    "iwr ",
    "downloadstring",
    "downloadfile",
    "start-bitstransfer",
    "bitsadmin /transfer",
    "certutil -urlcache",
    "certutil.exe -urlcache",
]


def detect_suspicious_download(events: list[SecurityEvent]):
    """
    Detect suspicious command-line behavior associated with
    downloading files or payloads.

    The presence of PowerShell, certutil, or bitsadmin alone
    is not enough to trigger this rule.
    """

    findings = []

    for event in events:
        if event.event_type != "process_execution":
            continue

        command_line = (event.command_line or "").lower()

        matched_patterns = [
            pattern
            for pattern in DOWNLOAD_PATTERNS
            if pattern in command_line
        ]

        if not matched_patterns:
            continue

        findings.append({
            "rule_id": SUSPICIOUS_DOWNLOAD_RULE_ID,
            "severity": "High",
            "category": "Execution",
            "issue": "Suspicious Download Behavior",
            "mitre": "T1105 - Ingress Tool Transfer",
            "confidence": "High",

            "host": event.host,
            "username": event.username,
            "process": event.process,

            "command_line": event.command_line,


            "first_seen": event.timestamp,
            "last_seen": event.timestamp,
            "matched_indicators": matched_patterns,

            "evidence": [
                event.raw_event
            ],

            "explanation": (
                "The process command line contains behavior commonly "
                "used to retrieve files or payloads from a remote source."
            ),

            "recommendation": (
                "Review the remote destination, inspect the downloaded "
                "file or payload, collect hashes where available, verify "
                "the initiating user and parent process, and correlate "
                "with subsequent execution or network activity."
            ),
        })

    return findings