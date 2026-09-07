SEVERITY_WEIGHTS = {
    "Low": 8,
    "Medium": 18,
    "High": 30,
    "Critical": 45,
}

INCIDENT_BONUS = {
    "Medium": 10,
    "High": 18,
    "Critical": 30,
}


def calculate_risk_score(findings: list[dict], incidents: list[dict]):
    """
    Calculate an overall ThreatLens risk score from actual findings
    and correlated incidents.

    The score is capped at 100.

    Findings contribute base risk.
    Correlated incidents contribute additional weight because
    multiple related signals are more meaningful than isolated alerts.
    """

    score = 0

    for finding in findings:
        severity = finding.get("severity", "Low")

        score += SEVERITY_WEIGHTS.get(
            severity,
            5,
        )

    for incident in incidents:
        severity = incident.get("severity", "Medium")

        score += INCIDENT_BONUS.get(
            severity,
            5,
        )

    score = min(score, 100)

    if score >= 85:
        risk_level = "Critical"

    elif score >= 6000:
        risk_level = "High"

    elif score >= 30:
        risk_level = "Medium"

    elif score > 0:
        risk_level = "Low"

    else:
        risk_level = "Informational"

    return {
        "risk_score": score,
        "risk_level": risk_level,
    }