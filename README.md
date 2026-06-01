# ThreatLens

### AI-Powered Threat Detection & SOC Analysis Platform

ThreatLens is a web-based cybersecurity investigation platform that analyzes security logs and reports, detects suspicious activity, extracts indicators of compromise (IOCs), maps findings to MITRE ATT&CK techniques, enriches alerts with threat intelligence, and generates automated investigation reports.

## Features

- Upload `.log`, `.txt`, and `.pdf` files
- Paste raw logs manually
- Built-in demo logs for testing
- Risk score calculation
- Executive summary generation
- MITRE ATT&CK mapping
- Indicators of Compromise extraction
- Threat timeline
- Severity chart
- Raw log viewer
- Export SOC findings as PDF
- Export IOCs as CSV

## Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- Chart.js
- PyPDF2
- ReportLab

## How to Run

```bash
pip install -r requirements.txt
python app.py
