# AI-Assisted SOC Log Analyzer

A Flask-based cybersecurity dashboard that analyzes security logs and reports to detect suspicious activity such as SSH brute-force attempts, successful logins after failures, web scanning, suspicious IPs, and user account indicators.

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