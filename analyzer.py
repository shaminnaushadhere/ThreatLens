import re
from collections import Counter


def extract_ips(log_text):
    return list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_text)))


def extract_users(log_text):
    users = []
    patterns = [
        r'Failed password for invalid user (\w+)',
        r'Failed password for (\w+)',
        r'Accepted password for (\w+)'
    ]
    for pattern in patterns:
        users.extend(re.findall(pattern, log_text))
    return list(set(users))


def extract_timeline(log_text):
    timeline = []
    lines = log_text.splitlines()

    for line in lines:
        if "Failed password" in line:
            timeline.append({"event": "Failed SSH Login", "line": line})
        elif "Accepted password" in line:
            timeline.append({"event": "Successful SSH Login", "line": line})
        elif any(path in line.lower() for path in ["/admin", "/wp-admin", "/.env", "/phpmyadmin"]):
            timeline.append({"event": "Web Scanning Activity", "line": line})

    return timeline[:10]


def count_severities(findings):
    return {
        "critical": sum(1 for f in findings if f["severity"] == "Critical"),
        "high": sum(1 for f in findings if f["severity"] == "High"),
        "medium": sum(1 for f in findings if f["severity"] == "Medium"),
        "low": sum(1 for f in findings if f["severity"] == "Low"),
    }


def generate_executive_summary(findings, risk_level):
    issues = [f["issue"] for f in findings]
    summary = f"The uploaded file received an overall rating of {risk_level}. "

    if "Successful SSH Login After Failed Attempts" in issues:
        summary += "A successful SSH login occurred after repeated failed attempts, which may indicate account compromise. "
    if "SSH Brute Force Attempt" in issues:
        summary += "Multiple failed SSH login attempts suggest possible brute-force activity. "
    if "Possible Web Scanning Activity" in issues:
        summary += "Sensitive web paths were requested, suggesting possible reconnaissance or scanning. "

    summary += "Review suspicious IPs, affected user accounts, and authentication activity."

    return summary


def analyze_logs(log_text):
    findings = []
    lower_logs = log_text.lower()
    suspicious_ips = extract_ips(log_text)
    users = extract_users(log_text)
    timeline = extract_timeline(log_text)

    failed_login_ips = re.findall(
        r'Failed password .* from ((?:[0-9]{1,3}\.){3}[0-9]{1,3})',
        log_text
    )

    accepted_login_ips = re.findall(
        r'Accepted password .* from ((?:[0-9]{1,3}\.){3}[0-9]{1,3})',
        log_text
    )

    failed_counter = Counter(failed_login_ips)

    for ip, count in failed_counter.items():
        if count >= 5:
            findings.append({
                "severity": "High",
                "issue": "SSH Brute Force Attempt",
                "mitre": "T1110 - Brute Force",
                "evidence": f"{count} failed SSH login attempts from {ip}",
                "explanation": "Multiple failed SSH login attempts from the same IP may indicate password guessing.",
                "recommendation": "Block the IP, enforce MFA, disable root SSH login, and review account activity."
            })

    for ip in accepted_login_ips:
        if ip in failed_counter:
            findings.append({
                "severity": "Critical",
                "issue": "Successful SSH Login After Failed Attempts",
                "mitre": "T1078 - Valid Accounts",
                "evidence": f"Successful login from {ip} after failed attempts",
                "explanation": "A login succeeded from an IP that previously generated failed login attempts.",
                "recommendation": "Reset the affected account password and investigate whether the login was authorized."
            })

    web_scan_patterns = ["/admin", "/wp-admin", "/.env", "/phpmyadmin", "/config", "/backup", "/login"]

    for pattern in web_scan_patterns:
        if pattern in lower_logs:
            findings.append({
                "severity": "Medium",
                "issue": "Possible Web Scanning Activity",
                "mitre": "T1595 - Active Scanning",
                "evidence": f"Request found for sensitive path: {pattern}",
                "explanation": "The logs show requests for common administrative or sensitive paths.",
                "recommendation": "Review access logs, block suspicious IPs, and harden exposed services."
            })
            break

    if not findings:
        findings.append({
            "severity": "Low",
            "issue": "No Major Suspicious Activity Found",
            "mitre": "N/A",
            "evidence": "No detection rules were triggered.",
            "explanation": "The logs did not match the current SOC detection rules.",
            "recommendation": "Continue monitoring."
        })

    severity_counts = count_severities(findings)

    risk_score = min(
        severity_counts["critical"] * 35 +
        severity_counts["high"] * 25 +
        severity_counts["medium"] * 15 +
        severity_counts["low"] * 5,
        100
    )

    if risk_score >= 75:
        risk_level = "Critical Risk"
    elif risk_score >= 50:
        risk_level = "High Risk"
    elif risk_score >= 25:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    mitre_techniques = list(set(f["mitre"] for f in findings if f["mitre"] != "N/A"))

    summary = {
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "ips": suspicious_ips,
        "users": users,
        "timeline": timeline,
        "mitre_techniques": mitre_techniques,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "executive_summary": generate_executive_summary(findings, risk_level)
    }

    return findings, summary