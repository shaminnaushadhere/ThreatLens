import csv
import io

from xml.sax.saxutils import escape

from flask import Flask, render_template, request, send_file, Response
# from analyzer import analyze_logs
from engine.pipeline import analyze_security_events
from engine.adapters.legacy_ui import adapt_v2_for_legacy_ui
import PyPDF2
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import os
from datetime import datetime
from dotenv import load_dotenv
import requests
import ipaddress

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

app = Flask(__name__)

latest_results = None
latest_summary = None

ALLOWED_EXTENSIONS = [".log", ".txt", ".pdf"]

DEMO_LOGS = {
    "normal": """
EventID: 1
UtcTime: 2026-08-25 18:00:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe Get-Service
ParentImage: C:\\Windows\\explorer.exe
""",

    "account_compromise": """
Aug 24 18:30:01 server sshd[4211]: Failed password for admin from 203.0.113.50 port 44121 ssh2
Aug 24 18:30:05 server sshd[4212]: Failed password for admin from 203.0.113.50 port 44122 ssh2
Aug 24 18:30:09 server sshd[4213]: Failed password for admin from 203.0.113.50 port 44123 ssh2
Aug 24 18:30:15 server sshd[4214]: Accepted password for admin from 203.0.113.50 port 44124 ssh2
""",

    "execution_persistence": """
EventID: 1
UtcTime: 2026-08-25 20:10:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -EncodedCommand TEST
ParentImage: C:\\Windows\\System32\\cmd.exe

EventID: 13
UtcTime: 2026-08-25 20:11:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
TargetObject: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater
Details: C:\\Users\\admin\\AppData\\Roaming\\updater.exe
""",

    "c2": """
EventID: 22
UtcTime: 2026-08-25 22:59:30.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
QueryName: update-service.example.com
QueryResults: 198.51.100.42

EventID: 3
UtcTime: 2026-08-25 23:00:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49721
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 23:01:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49722
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 23:02:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49723
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 23:03:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49724
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 23:04:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49725
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp
""",

    "ransomware": """
EventID: 1
UtcTime: 2026-08-25 22:00:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -EncodedCommand TEST
ParentImage: C:\\Windows\\System32\\cmd.exe

EventID: 1
UtcTime: 2026-08-25 22:00:30.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\vssadmin.exe
CommandLine: vssadmin.exe delete shadows /all /quiet
ParentImage: C:\\Windows\\System32\\cmd.exe

EventID: 11
UtcTime: 2026-08-25 22:01:00.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file01.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file02.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:02.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file03.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:03.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file04.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:04.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file05.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:05.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file06.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:06.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file07.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:07.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file08.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:08.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file09.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:09.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file10.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:10.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file11.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:11.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file12.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:12.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file13.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:13.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file14.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:14.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file15.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:15.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file16.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:16.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file17.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:17.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file18.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:18.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file19.docx.locked

EventID: 11
UtcTime: 2026-08-25 22:01:19.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file20.docx.locked
""",
}


def extract_text_from_pdf(uploaded_file):
    text = ""

    try:
        pdf_reader = PyPDF2.PdfReader(uploaded_file)

        for page in pdf_reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"

    except Exception:
        return ""

    return text


def check_ip_reputation(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            return {
                "ip": ip,
                "status": "Private/Internal IP",
                "abuse_score": "N/A",
                "country": "N/A",
                "isp": "N/A",
                "domain": "N/A",
                "total_reports": "N/A"
            }

        if not API_KEY:
            return {
                "ip": ip,
                "status": "API Key Missing",
                "abuse_score": "N/A",
                "country": "N/A",
                "isp": "N/A",
                "domain": "N/A",
                "total_reports": "N/A"
            }

        url = "https://api.abuseipdb.com/api/v2/check"

        headers = {
            "Accept": "application/json",
            "Key": API_KEY
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code != 200:
            return {
                "ip": ip,
                "status": f"API Error {response.status_code}",
                "abuse_score": "N/A",
                "country": "N/A",
                "isp": "N/A",
                "domain": "N/A",
                "total_reports": "N/A"
            }

        data = response.json()["data"]
        abuse_score = data.get("abuseConfidenceScore", 0)

        if abuse_score >= 75:
            status = "High Risk"
        elif abuse_score >= 40:
            status = "Suspicious"
        elif abuse_score > 0:
            status = "Low Risk"
        else:
            status = "Clean / No Recent Abuse"

        return {
            "ip": ip,
            "status": status,
            "abuse_score": abuse_score,
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "domain": data.get("domain", "N/A"),
            "total_reports": data.get("totalReports", 0)
        }

    except Exception as e:
        return {
            "ip": ip,
            "status": f"Lookup Failed: {str(e)}",
            "abuse_score": "N/A",
            "country": "N/A",
            "isp": "N/A",
            "domain": "N/A",
            "total_reports": "N/A"
        }


def enrich_summary_with_threat_intel(summary):
    threat_intel = []

    for ip in summary.get("ips", []):
        threat_intel.append(check_ip_reputation(ip))

    summary["threat_intel"] = threat_intel
    return summary


def create_pdf_report(results, summary):
    report_path = "ThreatLens_V2_SOC_Report.pdf"

    doc = SimpleDocTemplate(
        report_path,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    content = []

    def safe(value):
        if value is None:
            return "N/A"

        return escape(str(value))

    def joined(values):
        if not values:
            return "None"

        return ", ".join(
            safe(value)
            for value in values
        )

    # -------------------------------------------------
    # Report Header
    # -------------------------------------------------

    content.append(
        Paragraph(
            "ThreatLens v2.0 - SOC Investigation Report",
            styles["Title"],
        )
    )

    content.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["BodyText"],
        )
    )

    content.append(Spacer(1, 16))

    # -------------------------------------------------
    # Executive Summary
    # -------------------------------------------------

    content.append(
        Paragraph(
            "Executive Summary",
            styles["Heading2"],
        )
    )

    content.append(
        Paragraph(
            safe(
                summary.get(
                    "executive_summary",
                    "ThreatLens analysis complete.",
                )
            ),
            styles["BodyText"],
        )
    )

    content.append(Spacer(1, 12))

    # -------------------------------------------------
    # Investigation Overview
    # -------------------------------------------------

    content.append(
        Paragraph(
            "Investigation Overview",
            styles["Heading2"],
        )
    )

    risk_score = summary.get("risk_score")

    if risk_score is None:
        risk_score_text = "N/A"
    else:
        risk_score_text = f"{risk_score}/100"

    overview_lines = [
        f"Overall Risk: {safe(summary.get('risk_level', 'Informational'))}",
        f"Risk Score: {safe(risk_score_text)}",
        f"Events Analyzed: {summary.get('events_parsed', 0)}",
        f"Security Findings: {summary.get('findings_count', 0)}",
        f"Correlated Incidents: {summary.get('incidents_count', 0)}",
        (
            "Detected Telemetry: "
            + joined(
                summary.get(
                    "detected_sources",
                    [],
                )
            )
        ),
    ]

    for line in overview_lines:
        content.append(
            Paragraph(
                line,
                styles["BodyText"],
            )
        )

    content.append(Spacer(1, 12))

    # -------------------------------------------------
    # Severity Breakdown
    # -------------------------------------------------

    content.append(
        Paragraph(
            "Severity Breakdown",
            styles["Heading2"],
        )
    )

    content.append(
        Paragraph(
            (
                f"Critical: {summary.get('critical', 0)} | "
                f"High: {summary.get('high', 0)} | "
                f"Medium: {summary.get('medium', 0)} | "
                f"Low: {summary.get('low', 0)}"
            ),
            styles["BodyText"],
        )
    )

    content.append(Spacer(1, 12))

    # -------------------------------------------------
    # Affected Assets
    # -------------------------------------------------

    content.append(
        Paragraph(
            "Affected Assets",
            styles["Heading2"],
        )
    )

    asset_data = [
        (
            "Hosts",
            summary.get("hosts", []),
        ),
        (
            "Users",
            summary.get("users", []),
        ),
        (
            "Processes",
            summary.get("processes", []),
        ),
        (
            "Domains",
            summary.get("domains", []),
        ),
        (
            "IP Addresses",
            summary.get("ips", []),
        ),
        (
            "Files",
            summary.get("files", []),
        ),
        (
            "Registry Paths",
            summary.get("registry_paths", []),
        ),
    ]

    for label, values in asset_data:
        content.append(
            Paragraph(
                f"<b>{label}:</b> {joined(values)}",
                styles["BodyText"],
            )
        )

    content.append(Spacer(1, 12))

    # -------------------------------------------------
    # MITRE ATT&CK
    # -------------------------------------------------

    content.append(
        Paragraph(
            "MITRE ATT&CK Techniques",
            styles["Heading2"],
        )
    )

    content.append(
        Paragraph(
            joined(
                summary.get(
                    "mitre_techniques",
                    [],
                )
            ),
            styles["BodyText"],
        )
    )

    content.append(Spacer(1, 12))

    # -------------------------------------------------
    # Threat Intelligence
    # -------------------------------------------------

    content.append(
        Paragraph(
            "Threat Intelligence",
            styles["Heading2"],
        )
    )

    threat_intel = summary.get(
        "threat_intel",
        [],
    )

    if threat_intel:
        for item in threat_intel:
            content.append(
                Paragraph(
                    (
                        f"<b>{safe(item.get('ip'))}</b> | "
                        f"Status: {safe(item.get('status'))} | "
                        f"Abuse Score: {safe(item.get('abuse_score'))} | "
                        f"Country: {safe(item.get('country'))} | "
                        f"ISP: {safe(item.get('isp'))} | "
                        f"Reports: {safe(item.get('total_reports'))}"
                    ),
                    styles["BodyText"],
                )
            )
    else:
        content.append(
            Paragraph(
                "No IP reputation data available.",
                styles["BodyText"],
            )
        )

    content.append(Spacer(1, 12))

    # -------------------------------------------------
    # Threat Timeline
    # -------------------------------------------------

    content.append(
        Paragraph(
            "Threat Timeline",
            styles["Heading2"],
        )
    )

    timeline = summary.get(
        "timeline",
        [],
    )

    if timeline:
        for item in timeline:

            timestamp = item.get(
                "timestamp",
                "Unknown time",
            )

            event_name = item.get(
                "event",
                "Security Event",
            )

            severity = item.get(
                "severity",
                "Unknown",
            )

            host = item.get(
                "host",
            )

            rule_id = item.get(
                "rule_id",
            )

            incident_id = item.get(
                "incident_id",
            )

            identifier = (
                incident_id
                or rule_id
                or "N/A"
            )

            line = (
                f"<b>{safe(timestamp)}</b> - "
                f"{safe(event_name)} | "
                f"Severity: {safe(severity)} | "
                f"ID: {safe(identifier)}"
            )

            if host:
                line += (
                    f" | Host: {safe(host)}"
                )

            content.append(
                Paragraph(
                    line,
                    styles["BodyText"],
                )
            )

            content.append(
                Spacer(1, 4)
            )

    else:
        content.append(
            Paragraph(
                "No threat timeline events available.",
                styles["BodyText"],
            )
        )

    content.append(Spacer(1, 14))

    # -------------------------------------------------
    # Detailed Findings and Incidents
    # -------------------------------------------------

    content.append(
        Paragraph(
            "Detection and Incident Details",
            styles["Heading2"],
        )
    )

    if not results:
        content.append(
            Paragraph(
                "No security findings detected.",
                styles["BodyText"],
            )
        )

    for finding in results:

        rule_id = finding.get(
            "rule_id",
            "N/A",
        )

        severity = finding.get(
            "severity",
            "Unknown",
        )

        issue = finding.get(
            "issue",
            "Security Finding",
        )

        content.append(
            Paragraph(
                (
                    f"{safe(severity)} - "
                    f"{safe(issue)}"
                ),
                styles["Heading3"],
            )
        )

        detail_lines = [
            (
                "Rule / Incident ID",
                rule_id,
            ),
            (
                "Confidence",
                finding.get(
                    "confidence",
                    "N/A",
                ),
            ),
            (
                "Category",
                finding.get(
                    "category",
                    "N/A",
                ),
            ),
            (
                "MITRE ATT&CK",
                finding.get(
                    "mitre",
                    "N/A",
                ),
            ),
            (
                "Host",
                finding.get(
                    "host",
                    "N/A",
                ),
            ),
            (
                "User",
                finding.get(
                    "username",
                    "N/A",
                ),
            ),
            (
                "First Seen",
                finding.get(
                    "first_seen",
                    "N/A",
                ),
            ),
        ]

        for label, value in detail_lines:
            content.append(
                Paragraph(
                    (
                        f"<b>{label}:</b> "
                        f"{safe(value)}"
                    ),
                    styles["BodyText"],
                )
            )

        content.append(
            Paragraph(
                (
                    "<b>Explanation:</b> "
                    + safe(
                        finding.get(
                            "explanation",
                            "N/A",
                        )
                    )
                ),
                styles["BodyText"],
            )
        )

        content.append(
            Paragraph(
                (
                    "<b>Analyst Assessment:</b> "
                    + safe(
                        finding.get(
                            "analyst_assessment",
                            "N/A",
                        )
                    )
                ),
                styles["BodyText"],
            )
        )

        content.append(
            Paragraph(
                (
                    "<b>Why This Matters:</b> "
                    + safe(
                        finding.get(
                            "why_it_matters",
                            "N/A",
                        )
                    )
                ),
                styles["BodyText"],
            )
        )

        content.append(
            Paragraph(
                (
                    "<b>Recommended Action:</b> "
                    + safe(
                        finding.get(
                            "recommendation",
                            "N/A",
                        )
                    )
                ),
                styles["BodyText"],
            )
        )

        evidence = finding.get(
            "evidence",
        )

        if evidence:
            content.append(
                Paragraph(
                    "<b>Evidence:</b>",
                    styles["BodyText"],
                )
            )

            content.append(
                Paragraph(
                    safe(evidence),
                    styles["BodyText"],
                )
            )

        content.append(
            Spacer(1, 14)
        )

    # -------------------------------------------------
    # Footer
    # -------------------------------------------------

    content.append(
        Spacer(1, 20)
    )

    content.append(
        Paragraph(
            "Generated by ThreatLens v2.0",
            styles["BodyText"],
        )
    )

    doc.build(content)

    return report_path


@app.route("/", methods=["GET", "POST"])
def index():
    global latest_results, latest_summary

    results = None
    summary = None
    log_text = ""
    error = None
    file_info = None

    if request.method == "POST":
        demo_type = request.form.get("demo_type")
        uploaded_file = request.files.get("logfile")

        if demo_type in DEMO_LOGS:
            log_text = DEMO_LOGS[demo_type]
            file_info = {
                "name": f"Demo Sample: {demo_type}",
                "type": "Built-in Demo",
                "size": f"{len(log_text)} characters",
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        elif uploaded_file and uploaded_file.filename != "":
            filename = uploaded_file.filename
            extension = os.path.splitext(filename.lower())[1]

            if extension not in ALLOWED_EXTENSIONS:
                error = "Unsupported file type. Please upload only .log, .txt, or .pdf files."
            else:
                file_bytes = uploaded_file.read()
                file_size = round(len(file_bytes) / 1024, 2)

                file_info = {
                    "name": filename,
                    "type": extension.upper().replace(".", ""),
                    "size": f"{file_size} KB",
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                uploaded_file.seek(0)

                if extension == ".pdf":
                    log_text = extract_text_from_pdf(uploaded_file)
                else:
                    log_text = file_bytes.decode("utf-8", errors="ignore")

        else:
            log_text = request.form.get("logs", "")

            if log_text.strip():
                file_info = {
                    "name": "Manual Text Input",
                    "type": "Pasted Logs",
                    "size": f"{len(log_text)} characters",
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                error = "Please upload a file, paste logs, or choose a demo sample."

        if not error:
            if not log_text.strip():
                error = "No readable text was found. Please upload a valid LOG, TXT, or text-based PDF file. Scanned image PDFs are not supported yet."
            else:
                # Run ThreatLens V2
                v2_analysis = analyze_security_events(log_text)

                # Adapt V2 output to the existing UI structure
                results, summary = adapt_v2_for_legacy_ui(
                    v2_analysis
                )

                if not summary.get("input_supported", False):
                    summary["executive_summary"] = (
                        "ThreatLens could not identify this input as a supported "
                        "security log or telemetry source. No security conclusion "
                        "was made."
                    )

                    summary["risk_score"] = None
                    summary["risk_level"] = "Unsupported"

                # Enrich V2 IP indicators with threat intelligence
                summary = enrich_summary_with_threat_intel(
                    summary
                )

                latest_results = results
                latest_summary = summary
                

                
                

    return render_template(
        "index.html",
        results=results,
        summary=summary,
        log_text=log_text,
        error=error,
        file_info=file_info
    )


@app.route("/download-report")
def download_report():
    if latest_results is None or latest_summary is None:
        return "No report available. Please analyze logs first."

    report_path = create_pdf_report(latest_results, latest_summary)
    return send_file(report_path, as_attachment=True)


@app.route("/export-iocs")
def export_iocs():
    if latest_summary is None or latest_results is None:
        return "No IOC data available. Please analyze logs first."

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Category",
        "Type",
        "Value",
        "Additional Information",
    ])

    rows_written = 0

    # -------------------------------------------------
    # IP addresses
    # -------------------------------------------------

    for ip in latest_summary.get("ips", []):
        writer.writerow([
            "IOC",
            "IP Address",
            ip,
            "",
        ])

        rows_written += 1

    # -------------------------------------------------
    # Domains
    # -------------------------------------------------

    for domain in latest_summary.get(
        "domains",
        [],
    ):
        writer.writerow([
            "IOC",
            "Domain",
            domain,
            "",
        ])

        rows_written += 1

    # -------------------------------------------------
    # Users
    # -------------------------------------------------

    for user in latest_summary.get(
        "users",
        [],
    ):
        writer.writerow([
            "Affected Asset",
            "User",
            user,
            "",
        ])

        rows_written += 1

    # -------------------------------------------------
    # Hosts
    # -------------------------------------------------

    for host in latest_summary.get(
        "hosts",
        [],
    ):
        writer.writerow([
            "Affected Asset",
            "Host",
            host,
            "",
        ])

        rows_written += 1

    # -------------------------------------------------
    # Processes
    # -------------------------------------------------

    for process in latest_summary.get(
        "processes",
        [],
    ):
        writer.writerow([
            "Telemetry",
            "Process",
            process,
            "",
        ])

        rows_written += 1

    # -------------------------------------------------
    # Files
    # -------------------------------------------------

    for file_path in latest_summary.get(
        "files",
        [],
    ):
        writer.writerow([
            "Telemetry",
            "File",
            file_path,
            "",
        ])

        rows_written += 1

    # -------------------------------------------------
    # Registry paths
    # -------------------------------------------------

    for registry_path in latest_summary.get(
        "registry_paths",
        [],
    ):
        writer.writerow([
            "Telemetry",
            "Registry Path",
            registry_path,
            "",
        ])

        rows_written += 1

    # -------------------------------------------------
    # MITRE ATT&CK
    # -------------------------------------------------

    for technique in latest_summary.get(
        "mitre_techniques",
        [],
    ):
        writer.writerow([
            "MITRE ATT&CK",
            "Technique",
            technique,
            "",
        ])

        rows_written += 1

    # -------------------------------------------------
    # Threat intelligence
    # -------------------------------------------------

    for intel in latest_summary.get(
        "threat_intel",
        [],
    ):
        writer.writerow([
            "Threat Intelligence",
            intel.get(
                "status",
                "Unknown",
            ),
            intel.get(
                "ip",
                "",
            ),
            (
                f"abuse_score={intel.get('abuse_score', 'N/A')} "
                f"reports={intel.get('total_reports', 'N/A')} "
                f"country={intel.get('country', 'N/A')}"
            ),
        ])

        rows_written += 1

    # -------------------------------------------------
    # Findings and correlated incidents
    # -------------------------------------------------

    for finding in latest_results:

        finding_type = (
            "Incident"
            if finding.get(
                "is_incident",
                False,
            )
            else "Finding"
        )

        writer.writerow([
            finding_type,
            finding.get(
                "rule_id",
                "N/A",
            ),
            finding.get(
                "issue",
                "Security Finding",
            ),
            (
                f"severity={finding.get('severity', 'Unknown')} "
                f"confidence={finding.get('confidence', 'N/A')} "
                f"host={finding.get('host', 'N/A')}"
            ),
        ])

        rows_written += 1

    # -------------------------------------------------
    # Risk summary
    # -------------------------------------------------

    writer.writerow([
        "Summary",
        "Risk",
        latest_summary.get(
            "risk_level",
            "Informational",
        ),
        (
            f"score={latest_summary.get('risk_score') if latest_summary.get('risk_score') is not None else 'N/A'} "
            f"events={latest_summary.get('events_parsed', 0)} "
            f"findings={latest_summary.get('findings_count', 0)} "
            f"incidents={latest_summary.get('incidents_count', 0)}"
        ),
    ])

    rows_written += 1

    if rows_written == 1:
        writer.writerow([
            "Info",
            "None",
            "No IOCs or findings detected",
            "",
        ])

    csv_data = output.getvalue()

    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment;filename=ThreatLens_V2_Export.csv"
        },
    )


if __name__ == "__main__":
    app.run(debug=True)