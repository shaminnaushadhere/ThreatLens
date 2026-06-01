# Detection Rules

ThreatLens uses rule-based detection logic to identify suspicious behavior from uploaded logs and reports.

## SSH Brute Force Detection

Pattern:

Failed password ... from IP

Logic:

If the same IP address generates 5 or more failed SSH login attempts, ThreatLens creates a High severity finding.

MITRE Mapping:

T1110 - Brute Force

---

## Successful Login After Failed Attempts

Patterns:

Failed password ... from IP

Accepted password ... from IP

Logic:

If an IP address first generates failed logins and later successfully authenticates, ThreatLens creates a Critical severity finding.

MITRE Mapping:

T1078 - Valid Accounts

---

## Web Scanning Detection

ThreatLens checks for common sensitive paths:

* /admin
* /wp-admin
* /.env
* /phpmyadmin
* /config
* /backup
* /login

Logic:

If these paths appear in logs or PDF content, ThreatLens creates a Medium severity finding.

MITRE Mapping:

T1595 - Active Scanning

---

## IOC Extraction

ThreatLens extracts:

* IP addresses
* User accounts

---

## Risk Score

Severity scoring:

Critical = 35 points

High = 25 points

Medium = 15 points

Low = 5 points

The final score is capped at 100.
