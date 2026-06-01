# AbuseIPDB API Integration

ThreatLens integrates with AbuseIPDB to enrich extracted IP addresses with threat intelligence.

## Purpose

After extracting IP addresses from logs or PDF reports, ThreatLens checks each public IP against AbuseIPDB.

This helps determine whether an IP address has previously been reported for malicious activity.

## Information Retrieved

* IP address
* Abuse confidence score
* Country
* ISP
* Domain
* Total reports
* Risk status

## Risk Classification

75+ = High Risk

40-74 = Suspicious

1-39 = Low Risk

0 = Clean

## Environment Variable

ABUSEIPDB_API_KEY=your_api_key_here

The .env file should never be uploaded to GitHub.

## Libraries Used

* requests
* python-dotenv

## Security Note

API keys should never be hardcoded into source code or committed to public repositories.
