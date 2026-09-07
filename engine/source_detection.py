def detect_log_sources(log_text: str):
    text = log_text or ""
    text_lower = text.lower()

    sources = []

    if (
        "eventid:" in text_lower
        and (
            "utctime:" in text_lower
            or "computer:" in text_lower
        )
    ):
        sources.append("Windows Sysmon")

    if (
        "sshd[" in text_lower
        and (
            "failed password" in text_lower
            or "accepted password" in text_lower
        )
    ):
        sources.append("Linux SSH Authentication")

    if (
        (
            '"get ' in text_lower
            or '"post ' in text_lower
            or '"put ' in text_lower
            or '"delete ' in text_lower
        )
        and "http/" in text_lower
    ):
        sources.append("Web Access Log")

    if (
        "process:" in text_lower
        and "commandline:" in text_lower
    ):
        sources.append("Process Telemetry")

    return sorted(set(sources))


def is_supported_telemetry(log_text: str):
    return len(detect_log_sources(log_text)) > 0