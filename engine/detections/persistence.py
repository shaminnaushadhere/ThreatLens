from engine.models import SecurityEvent


PERSISTENCE_RULE_ID = "TL-PERSIST-001"


SUSPICIOUS_RUN_KEYS = [
    "\\software\\microsoft\\windows\\currentversion\\run\\",
    "\\software\\microsoft\\windows\\currentversion\\runonce\\",
]


def detect_registry_persistence(events: list[SecurityEvent]):
    """
    Detect suspicious registry-based persistence using
    Windows Run and RunOnce registry keys.

    This rule does not flag every registry modification.
    It only examines registry value-set events targeting
    common startup persistence locations.
    """

    findings = []

    for event in events:
        if event.event_type != "registry_value_set":
            continue

        if not event.path:
            continue

        registry_path = event.path.lower()

        if not any(
            run_key in registry_path
            for run_key in SUSPICIOUS_RUN_KEYS
        ):
            continue

        value_data = (
            event.command_line.lower()
            if event.command_line
            else ""
        )

        suspicious_locations = [
            "\\appdata\\",
            "\\temp\\",
            "\\users\\public\\",
            "\\programdata\\",
        ]

        suspicious_interpreters = [
            "powershell",
            "cmd.exe",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
        ]

        suspicious_location = any(
            location in value_data
            for location in suspicious_locations
        )

        suspicious_interpreter = any(
            interpreter in value_data
            for interpreter in suspicious_interpreters
        )

        if not (
            suspicious_location
            or suspicious_interpreter
        ):
            continue

        findings.append({
            "rule_id": PERSISTENCE_RULE_ID,
            "severity": "High",
            "category": "Persistence",
            "issue": "Suspicious Registry Run-Key Persistence",
            "mitre": "T1547.001 - Registry Run Keys / Startup Folder",
            "confidence": "High",

            "host": event.host,
            "username": event.username,
            "process": event.process,

            "registry_path": event.path,
            "registry_value": event.command_line,

            "first_seen": event.timestamp,
            "last_seen": event.timestamp,

            "evidence": [
                event.raw_event
            ],

            "explanation": (
                "A registry value was written to a Windows "
                "Run or RunOnce startup location and points "
                "to a potentially suspicious executable or "
                "interpreter. These locations are commonly "
                "used to automatically execute programs "
                "after user logon."
            ),

            "recommendation": (
                "Verify whether the registry entry is "
                "authorized, inspect the referenced file or "
                "command, review the creating process, and "
                "correlate with nearby process, network, and "
                "file activity."
            ),
        })

    return findings
