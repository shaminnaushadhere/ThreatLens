def adapt_v2_for_legacy_ui(v2_analysis: dict):
    """
    Convert ThreatLens V2 analysis output into the structure
    expected by the existing V1 Flask templates and reports.

    This adapter is temporary. It allows us to migrate the
    backend to V2 without immediately rewriting the frontend.
    """

    findings = v2_analysis.get("findings", [])
    incidents = v2_analysis.get("incidents", [])
    v2_summary = v2_analysis.get("summary", {})

    results = []

    # -------------------------------------------------
    # Convert V2 findings into current UI result cards
    # -------------------------------------------------

    for finding in findings:

        evidence = finding.get("evidence", [])

        if isinstance(evidence, list):
            evidence_text = "\n".join(
                str(item)
                for item in evidence
            )
        else:
            evidence_text = str(evidence)

        results.append({
            "severity": finding.get(
                "severity",
                "Unknown",
            ),

            "issue": finding.get(
                "issue",
                "Security Finding",
            ),

            "category": finding.get(
                "category",
                "Security",
            ),

            "mitre": finding.get(
                "mitre",
                "N/A",
            ),

            "evidence": evidence_text,

            "explanation": finding.get(
                "explanation",
                "No additional explanation available.",
            ),

            "analyst_assessment": (
                f"ThreatLens rule {finding.get('rule_id', 'N/A')} "
                f"identified behavior matching this detection."
            ),

            "why_it_matters": (
                "This activity matched a ThreatLens behavioral "
                "detection rule and should be reviewed together "
                "with surrounding host, user, process, file, "
                "network, and authentication context."
            ),

            "recommendation": finding.get(
                "recommendation",
                "Review the underlying evidence and surrounding telemetry.",
            ),

            # V2 metadata — current template can ignore these
            "rule_id": finding.get("rule_id"),
            "confidence": finding.get("confidence"),
            "host": finding.get("host"),
            "username": finding.get("username"),
            "first_seen": finding.get("first_seen"),
            "last_seen": finding.get("last_seen"),
        })

    # -------------------------------------------------
    # Also expose correlated incidents as result cards
    # -------------------------------------------------

    for incident in incidents:

        evidence = incident.get("evidence", [])

        if isinstance(evidence, list):
            evidence_text = "\n".join(
                str(item)
                for item in evidence
            )
        else:
            evidence_text = str(evidence)

        mitre = incident.get(
            "mitre",
            "N/A",
        )

        if isinstance(mitre, list):
            mitre_text = ", ".join(
                str(item)
                for item in mitre
                if item
            )
        else:
            mitre_text = str(mitre)

        contributing_rules = incident.get(
            "contributing_rules",
            [],
        )

        results.append({
            "severity": incident.get(
                "severity",
                "High",
            ),

            "issue": incident.get(
                "title",
                "Correlated Security Incident",
            ),

            "category": incident.get(
                "category",
                "Incident Correlation",
            ),

            "mitre": mitre_text,

            "evidence": evidence_text,

            "explanation": incident.get(
                "explanation",
                "ThreatLens correlated multiple related security signals.",
            ),

            "analyst_assessment": (
                f"Correlated incident {incident.get('incident_id', 'N/A')} "
                f"was formed from rules: "
                f"{', '.join(contributing_rules) if contributing_rules else 'N/A'}."
            ),

            "why_it_matters": (
                "Multiple related signals occurring on the same "
                "host within a relevant time window provide stronger "
                "evidence than an isolated alert."
            ),

            "recommendation": incident.get(
                "recommendation",
                "Investigate the full incident chain and validate affected assets.",
            ),

            "rule_id": incident.get(
                "incident_id"
            ),

            "confidence": incident.get(
                "confidence"
            ),

            "host": incident.get(
                "host"
            ),

            "username": incident.get(
                "username"
            ),

            "first_seen": incident.get(
                "first_seen"
            ),

            "last_seen": incident.get(
                "last_seen"
            ),

            "is_incident": True,
        })

    # -------------------------------------------------
    # Convert V2 summary to current UI summary structure
    # -------------------------------------------------

    summary = {
        "executive_summary": v2_summary.get(
            "executive_summary",
            "ThreatLens analysis complete.",
        ),

        "risk_score": v2_summary.get(
            "risk_score",
            0,
        ),

        "risk_level": v2_summary.get(
            "risk_level",
            "Informational",
        ),

        "critical": v2_summary.get(
            "critical",
            0,
        ),

        "high": v2_summary.get(
            "high",
            0,
        ),

        "medium": v2_summary.get(
            "medium",
            0,
        ),

        "low": v2_summary.get(
            "low",
            0,
        ),

        "ips": v2_summary.get(
            "ips",
            [],
        ),

        "users": v2_summary.get(
            "users",
            [],
        ),

        "hosts": v2_summary.get(
            "hosts",
            [],
        ),

        "domains": v2_summary.get(
            "domains",
            [],
        ),

        "processes": v2_summary.get(
            "processes",
            [],
        ),

        "files": v2_summary.get(
            "files",
            [],
        ),

        "registry_paths": v2_summary.get(
            "registry_paths",
            [],
        ),

        "mitre_techniques": v2_summary.get(
            "mitre_techniques",
            [],
        ),

        "timeline": v2_summary.get(
            "timeline",
            [],
        ),

        "triggered_rules": v2_summary.get(
            "triggered_rules",
            [],
        ),

        "events_parsed": v2_summary.get(
            "events_parsed",
            0,
        ),

        "findings_count": v2_summary.get(
            "findings_count",
            0,
        ),

        "incidents_count": v2_summary.get(
            "incidents_count",
            0,
        ),

        # app.py will populate this through AbuseIPDB
        "threat_intel": [],
    }

    return results, summary