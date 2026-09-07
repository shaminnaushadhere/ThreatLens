from dataclasses import dataclass
from typing import Optional


@dataclass
class SecurityEvent:
    timestamp: Optional[str] = None
    event_type: Optional[str] = None

    host: Optional[str] = None
    username: Optional[str] = None

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None

    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    process: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None

    path: Optional[str] = None
    protocol: Optional[str] = None

    outcome: Optional[str] = None

    raw_event: str = ""
    source_type: str = "unknown"