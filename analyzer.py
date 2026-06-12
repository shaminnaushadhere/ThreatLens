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

    users = [u for u in users if u.lower() != "invalid"]

    return list(set(users))


def extract_timeline(log_text):
    timeline = []
    lines = log_text.splitlines()

    for line in lines:
        lower_line = line.lower()

        if "failed password" in lower_line:
            timeline.append({"event": "Failed SSH Login", "line": line})
        elif "accepted password" in lower_line:
            timeline.append({"event": "Successful SSH Login", "line": line})
        elif any(path in lower_line for path in ["/admin", "/wp-admin", "/.env", "/phpmyadmin"]):
            timeline.append({"event": "Web Scanning Activity", "line": line})
        elif any(word in lower_line for word in ["malware", "trojan", "ransomware", "powershell", "cmd.exe"]):
            timeline.append({"event": "Possible Malware-Related Activity", "line": line})

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
        summary += "A successful login occurred after repeated failed authentication attempts, which may indicate possible account compromise. "

    if "SSH Brute Force Attempt" in issues:
        summary += "Repeated SSH authentication failures indicate possible password guessing or brute-force activity. "

    if "Possible Web Scanning Activity" in issues:
        summary += "Requests to sensitive web paths suggest reconnaissance or automated scanning activity. "

    if "Possible Malware-Related Behavior" in issues:
        summary += "Suspicious malware-related indicators were found and should be reviewed further. "

    if "No Major Suspicious Activity Found" in issues:
        summary += "No major suspicious indicators were identified based on the current detection rules. "

    summary += "Review the extracted IOCs, MITRE mappings, threat intelligence results, and recommended response actions."

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
                "category": "Credential Access",
                "issue": "SSH Brute Force Attempt",
                "mitre": "T1110 - Brute Force",
                "evidence": f"{count} failed SSH login attempts from {ip}",
                "explanation": "The same source IP generated repeated failed SSH login attempts. This behavior is commonly associated with password guessing or brute-force attacks.",
                "analyst_assessment": "This event should be investigated as a credential access attempt. The source IP repeatedly attempted authentication and may be targeting weak or reused credentials.",
                "why_it_matters": "If successful, brute-force attacks can lead to unauthorized access, account compromise, and potential lateral movement.",
                "recommendation": "Block or rate-limit the source IP, enforce MFA, disable root SSH login, review authentication logs, and check whether any login later succeeded."
            })

    for ip in accepted_login_ips:
        if ip in failed_counter:
            findings.append({
                "severity": "Critical",
                "category": "Account Compromise",
                "issue": "Successful SSH Login After Failed Attempts",
                "mitre": "T1078 - Valid Accounts",
                "evidence": f"Successful login from {ip} after previous failed attempts",
                "explanation": "An IP address that previously generated failed login attempts later authenticated successfully.",
                "analyst_assessment": "This should be treated as a possible account compromise. The pattern suggests the attacker may have guessed or obtained valid credentials.",
                "why_it_matters": "Valid account access can allow an attacker to move deeper into the environment while appearing like a legitimate user.",
                "recommendation": "Reset the affected account password, verify whether the login was authorized, review user activity after login, check for privilege escalation, and investigate lateral movement."
            })

    web_scan_patterns = [
        "/admin",
        "/wp-admin",
        "/.env",
        "/phpmyadmin",
        "/config",
        "/backup",
        "/login"
    ]

    detected_path = None

    for pattern in web_scan_patterns:
        if pattern in lower_logs:
            detected_path = pattern
            break

    if detected_path:
        findings.append({
            "severity": "Medium",
            "category": "Reconnaissance",
            "issue": "Possible Web Scanning Activity",
            "mitre": "T1595 - Active Scanning",
            "evidence": f"Request found for sensitive path: {detected_path}",
            "explanation": "The uploaded content contains requests for common sensitive or administrative web paths.",
            "analyst_assessment": "This activity resembles reconnaissance or automated web scanning. It may be an early-stage attempt to identify exposed services or weak points.",
            "why_it_matters": "Web scanning can reveal exposed admin panels, leaked environment files, or vulnerable services that attackers may exploit later.",
            "recommendation": "Review the source IP, apply rate limiting, block repeated scanners, harden exposed web services, remove sensitive files, and monitor for follow-up exploitation attempts."
        })

    malware_keywords = [
        "trojan",
        "ransomware",
        "malware",
        "powershell -enc",
        "encodedcommand",
        "downloadstring",
        "certutil",
        "bitsadmin",
        "cmd.exe",
        "temp\\",
        ".exe"
    ]

    detected_malware_keyword = None

    for keyword in malware_keywords:
        if keyword in lower_logs:
            detected_malware_keyword = keyword
            break

    if detected_malware_keyword:
        findings.append({
            "severity": "High",
            "category": "Malware Behavior",
            "issue": "Possible Malware-Related Behavior",
            "mitre": "T1059 - Command and Scripting Interpreter",
            "evidence": f"Suspicious malware-related indicator found: {detected_malware_keyword}",
            "explanation": "The uploaded content contains keywords or behaviors commonly associated with malware execution, suspicious downloads, encoded commands, or potentially unwanted executable activity.",
            "analyst_assessment": "This does not confirm a Trojan or ransomware infection by itself, but it indicates behavior that should be investigated as potential malware activity.",
            "why_it_matters": "Trojan malware and ransomware often use scripting tools, suspicious executables, or command-and-control communication during early stages of compromise.",
            "recommendation": "Collect endpoint logs, review process execution, check file hashes, isolate suspicious hosts if needed, and correlate with EDR or antivirus alerts."
        })

    if not findings:
        findings.append({
            "severity": "Low",
            "category": "No Confirmed Threat",
            "issue": "No Major Suspicious Activity Found",
            "mitre": "N/A",
            "evidence": "The uploaded content did not contain indicators matching the current detection rules.",
            "explanation": "ThreatLens did not identify brute-force attempts, compromised logins, web scanning behavior, or malware-related indicators in the provided content.",
            "analyst_assessment": "No immediate security concern was identified from the uploaded file. This result depends on the quality and completeness of the provided logs or report.",
            "why_it_matters": "Security analysis is evidence-based. If the file does not contain relevant log events or readable text, no threat can be confirmed.",
            "recommendation": "If this was expected to contain security events, upload raw logs, a text-based security report, or more complete evidence for analysis."
        })

        severity_counts = count_severities(findings)

    risk_score = min(
        severity_counts["critical"] * 35 +
        severity_counts["high"] * 25 +
        severity_counts["medium"] * 15 +
        severity_counts["low"] * 5,
        100
    )

    if severity_counts["critical"] > 0:
        risk_level = "Critical Risk"
        risk_score = max(risk_score, 85)

    elif severity_counts["high"] > 0:
        risk_level = "High Risk"
        risk_score = max(risk_score, 65)

    elif severity_counts["medium"] > 0:
        risk_level = "Medium Risk"
        risk_score = max(risk_score, 40)

    else:
        risk_level = "Low Risk"
        risk_score = max(risk_score, 10)

    mitre_techniques = list(
        set(
            f["mitre"]
            for f in findings
            if f["mitre"] != "N/A"
        )
    )

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
        "executive_summary": generate_executive_summary(
            findings,
            risk_level
        )
    }

    return findings, summary
