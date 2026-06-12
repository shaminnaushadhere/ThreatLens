from flask import Flask, render_template, request, send_file, Response
from analyzer import analyze_logs
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
    "ssh": """May 31 10:01:12 ubuntu sshd[2451]: Failed password for invalid user admin from 185.220.101.45 port 49812 ssh2
May 31 10:01:15 ubuntu sshd[2451]: Failed password for invalid user admin from 185.220.101.45 port 49812 ssh2
May 31 10:01:18 ubuntu sshd[2451]: Failed password for invalid user admin from 185.220.101.45 port 49812 ssh2
May 31 10:01:22 ubuntu sshd[2451]: Failed password for invalid user admin from 185.220.101.45 port 49812 ssh2
May 31 10:01:28 ubuntu sshd[2451]: Failed password for invalid user admin from 185.220.101.45 port 49812 ssh2""",

    "compromise": """May 31 11:22:10 ubuntu sshd[3012]: Failed password for root from 45.67.89.10 port 53322 ssh2
May 31 11:22:14 ubuntu sshd[3012]: Failed password for root from 45.67.89.10 port 53322 ssh2
May 31 11:22:19 ubuntu sshd[3012]: Failed password for root from 45.67.89.10 port 53322 ssh2
May 31 11:23:01 ubuntu sshd[3012]: Accepted password for root from 45.67.89.10 port 53322 ssh2""",

    "web": """185.199.110.153 - - [31/May/2026:12:15:01 -0700] "GET /admin HTTP/1.1" 404 512
185.199.110.153 - - [31/May/2026:12:15:03 -0700] "GET /.env HTTP/1.1" 404 512
185.199.110.153 - - [31/May/2026:12:15:05 -0700] "GET /wp-admin HTTP/1.1" 404 512
185.199.110.153 - - [31/May/2026:12:15:07 -0700] "GET /phpmyadmin HTTP/1.1" 404 512""",

    "normal": """May 31 08:00:01 ubuntu sshd[1001]: Accepted password for shamin from 192.168.1.10 port 50122 ssh2
May 31 08:30:14 ubuntu systemd[1]: Started Daily apt download activities.
May 31 09:00:22 ubuntu sshd[1001]: pam_unix(sshd:session): session closed for user shamin"""
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
    report_path = "SOC_Findings_Report.pdf"
    doc = SimpleDocTemplate(report_path)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("SOC Investigation Report", styles["Title"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Executive Summary", styles["Heading2"]))
    content.append(Paragraph(summary["executive_summary"], styles["BodyText"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Overall Risk", styles["Heading2"]))
    content.append(Paragraph(f"Risk Score: {summary['risk_score']}/100", styles["BodyText"]))
    content.append(Paragraph(f"Risk Level: {summary['risk_level']}", styles["BodyText"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Indicators of Compromise", styles["Heading2"]))
    content.append(Paragraph(f"Suspicious IPs: {', '.join(summary['ips']) if summary['ips'] else 'None'}", styles["BodyText"]))
    content.append(Paragraph(f"User Accounts: {', '.join(summary['users']) if summary['users'] else 'None'}", styles["BodyText"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Threat Intelligence", styles["Heading2"]))
    if summary.get("threat_intel"):
        for item in summary["threat_intel"]:
            content.append(Paragraph(
                f"{item['ip']} | {item['status']} | Abuse Score: {item['abuse_score']} | Country: {item['country']} | Reports: {item['total_reports']}",
                styles["BodyText"]
            ))
    else:
        content.append(Paragraph("No IP reputation data available.", styles["BodyText"]))

    content.append(Spacer(1, 12))

    content.append(Paragraph("MITRE ATT&CK Techniques", styles["Heading2"]))
    content.append(Paragraph(", ".join(summary["mitre_techniques"]) if summary["mitre_techniques"] else "None", styles["BodyText"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Detailed Findings", styles["Heading2"]))

    for finding in results:
        content.append(Paragraph(f"{finding['severity']} - {finding['issue']}", styles["Heading3"]))
        content.append(Paragraph(f"Category: {finding.get('category', 'N/A')}", styles["BodyText"]))
        content.append(Paragraph(f"MITRE ATT&CK: {finding['mitre']}", styles["BodyText"]))
        content.append(Paragraph(f"Evidence: {finding['evidence']}", styles["BodyText"]))
        content.append(Paragraph(f"Explanation: {finding['explanation']}", styles["BodyText"]))
        content.append(Paragraph(f"Analyst Assessment: {finding.get('analyst_assessment', 'N/A')}", styles["BodyText"]))
        content.append(Paragraph(f"Why This Matters: {finding.get('why_it_matters', 'N/A')}", styles["BodyText"]))
        content.append(Paragraph(f"Recommendation: {finding['recommendation']}", styles["BodyText"]))
        content.append(Spacer(1, 10))

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
                results, summary = analyze_logs(log_text)
                summary = enrich_summary_with_threat_intel(summary)

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

    csv_data = "Category,Type,Value\n"

    for ip in latest_summary.get("ips", []):
        csv_data += f"IOC,IP,{ip}\n"

    for user in latest_summary.get("users", []):
        csv_data += f"IOC,User,{user}\n"

    for intel in latest_summary.get("threat_intel", []):
        csv_data += f"ThreatIntel,{intel['status']},{intel['ip']} abuse_score={intel['abuse_score']} reports={intel['total_reports']}\n"

    for technique in latest_summary.get("mitre_techniques", []):
        csv_data += f"MITRE,Technique,{technique}\n"

    for finding in latest_results:
        csv_data += f"Finding,{finding['severity']},{finding['issue']}\n"

    if csv_data == "Category,Type,Value\n":
        csv_data += "Info,None,No IOCs or findings detected\n"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=IOC_Report.csv"}
    )


if __name__ == "__main__":
    app.run(debug=True)
