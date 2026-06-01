# ThreatLens Architecture

ThreatLens is a Flask-based SOC analysis platform that processes uploaded logs and reports, detects suspicious activity, enriches indicators using threat intelligence, and generates investigation reports.

## Workflow

User Upload / Demo Logs
↓
Flask Web App
↓
PDF / TXT / LOG Parser
↓
Detection Engine
↓
IOC Extraction
↓
MITRE ATT&CK Mapping
↓
AbuseIPDB Threat Intelligence
↓
Risk Score + Dashboard
↓
PDF Report / CSV Export

## Components

### Frontend

* HTML
* CSS
* JavaScript
* Chart.js

### Backend

* Python
* Flask
* PyPDF2
* ReportLab
* Requests

### Threat Intelligence

* AbuseIPDB API

### Outputs

* Risk score dashboard
* Executive summary
* IOC list
* MITRE ATT&CK mapping
* PDF SOC report
* CSV IOC export
