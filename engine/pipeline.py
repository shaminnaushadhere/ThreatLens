from engine.source_detection import detect_log_sources
from engine.summary.builder import build_analysis_summary
from engine.scoring.risk import calculate_risk_score
from engine.correlation.c2 import correlate_dns_with_c2
from engine.correlation.ransomware import correlate_ransomware_activity
from engine.detections.impact import detect_recovery_inhibition
from engine.correlation.persistence import (
    correlate_execution_persistence,
)
from engine.detections.persistence import detect_registry_persistence
from engine.detections.file_activity import detect_rapid_file_activity
from engine.detections.c2 import detect_c2_beaconing
from engine.correlation.correlator import correlate_execution_findings
from engine.detections.download import detect_suspicious_download
from engine.parsers.process import parse_process_logs
from engine.detections.execution import detect_suspicious_powershell
from engine.parsers.sysmon import parse_sysmon_logs
from engine.parsers.web import parse_web_logs
from engine.detections.web import detect_web_scanning

from engine.parsers.ssh import parse_ssh_logs
from engine.detections.ssh import detect_ssh_bruteforce
from engine.detections.compromise import detect_compromised_login


def analyze_security_events(log_text: str):
    """
    Central ThreatLens V2 analysis pipeline.

    Current supported sources:
    - Linux SSH authentication logs
    - Apache/Nginx-style web access logs
    - Simplified process execution telemetry
    """

    # Detect what type of telemetry was provided
    detected_sources = detect_log_sources(
        log_text
    )    

    # 1. Parse raw logs into normalized SecurityEvent objects
    events = []

    events.extend(
        parse_ssh_logs(log_text)
    )

    events.extend(
        parse_web_logs(log_text)
    )

    events.extend(
        parse_process_logs(log_text)
    )

    events.extend(
        parse_sysmon_logs(log_text)
    )

    # 2. Run detection rules
    findings = []

    findings.extend(
        detect_ssh_bruteforce(events)
    )

    findings.extend(
        detect_compromised_login(events)
    )

    findings.extend(
        detect_web_scanning(events)
    )

    findings.extend(
        detect_suspicious_powershell(events)
    )

    findings.extend(
        detect_suspicious_download(events)
    )

    findings.extend(
        detect_c2_beaconing(events)
    )

    findings.extend(
        detect_rapid_file_activity(events)
    )

    findings.extend(
        detect_registry_persistence(events)
    )

    findings.extend(
        detect_recovery_inhibition(events)
    )

    

    # 3. Collect analysis metadata
    triggered_rules = sorted({
        finding["rule_id"]
        for finding in findings
    })

    incidents = []

    incidents.extend(
        correlate_execution_findings(
            findings,
            events,
        )
    )

    incidents.extend(
        correlate_execution_persistence(
            findings,
            events,
        )
    )

    incidents.extend(
        correlate_ransomware_activity(
            findings,
            events,
        )
    )

    incidents.extend(
        correlate_dns_with_c2(
            findings,
            events,
        )
    )

    risk = calculate_risk_score(
        findings,
        incidents,
    )

    summary = build_analysis_summary(
        events,
        findings,
        incidents,
        risk,
    )

    summary["triggered_rules"] = triggered_rules
    summary["detected_sources"] = detected_sources
    summary["input_supported"] = bool(detected_sources)

    return {
        "events": events,
        "findings": findings,
        "incidents": incidents,
        "summary": summary,
    }