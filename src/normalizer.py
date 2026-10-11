"""
Common Schema Normalizer
Normalizes disparate raw log events into a unified, evidence-traceable format.
"""

import html
import re
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
import pandas as pd


@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: int  # Relative seconds from start
    event_type: str  # AUTH, PROCESS, NETWORK_FLOW, DNS, REDTEAM, GENERIC
    action: str      # LOGON_SUCCESS, LOGON_FAIL, PROCESS_START, etc.
    user: Optional[str] = None
    src_host: Optional[str] = None
    dst_host: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    process_name: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    source_file: str = "unknown"
    line_number: int = 0
    raw_line: str = ""
    is_ground_truth: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def sanitize_string(val: Optional[str]) -> Optional[str]:
    """Sanitizes text fields to prevent XSS and control-character exploitation."""
    if val is None:
        return None
    val = str(val).strip()
    # Escape HTML to prevent injection in Streamlit / reports
    val = html.escape(val)
    # Strip null bytes and dangerous control chars
    val = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", val)
    return val


def normalize_record(raw: Dict[str, Any]) -> Optional[NormalizedEvent]:
    """
    Transforms a parsed raw dictionary into a NormalizedEvent.
    Preserves line references and integer relative seconds.
    """
    file_type = raw.get("_file_type", "")
    source_file = sanitize_string(raw.get("_source_file", "unknown")) or "unknown"
    line_number = raw.get("_line_number", 0)
    raw_line = raw.get("_raw_line", "")
    timestamp = raw.get("time")

    if timestamp is None:
        return None  # Cannot normalize event without time coordinate

    event_id = f"{source_file}:{line_number}"

    if file_type == "auth":
        status = (raw.get("status") or "").upper()
        action = "LOGON_SUCCESS" if "SUCCESS" in status else ("LOGON_FAIL" if "FAIL" in status else "AUTH_ATTEMPT")
        user = raw.get("src_user") or raw.get("dst_user")
        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type="AUTH",
            action=action,
            user=sanitize_string(user),
            src_host=sanitize_string(raw.get("src_host")),
            dst_host=sanitize_string(raw.get("dst_host")),
            details={
                "auth_type": sanitize_string(raw.get("auth_type")),
                "logon_type": sanitize_string(raw.get("logon_type")),
                "auth_orientation": sanitize_string(raw.get("auth_orientation")),
                "status": sanitize_string(raw.get("status")),
            },
            source_file=source_file,
            line_number=line_number,
            raw_line=raw_line,
            is_ground_truth=False,
        )

    elif file_type == "proc":
        action_raw = (raw.get("action") or "").lower()
        action = "PROCESS_START" if "start" in action_raw else ("PROCESS_STOP" if "end" in action_raw else "PROCESS_EVENT")
        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type="PROCESS",
            action=action,
            user=sanitize_string(raw.get("user")),
            src_host=sanitize_string(raw.get("host")),
            dst_host=sanitize_string(raw.get("host")),
            process_name=sanitize_string(raw.get("process_name")),
            details={
                "proc_action": sanitize_string(raw.get("action")),
            },
            source_file=source_file,
            line_number=line_number,
            raw_line=raw_line,
            is_ground_truth=False,
        )

    elif file_type == "flows":
        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type="NETWORK_FLOW",
            action="FLOW",
            src_host=sanitize_string(raw.get("src_host")),
            dst_host=sanitize_string(raw.get("dst_host")),
            src_port=raw.get("src_port"),
            dst_port=raw.get("dst_port"),
            protocol=sanitize_string(raw.get("protocol")),
            details={
                "duration": raw.get("duration"),
                "packet_count": raw.get("packet_count"),
                "byte_count": raw.get("byte_count"),
            },
            source_file=source_file,
            line_number=line_number,
            raw_line=raw_line,
            is_ground_truth=False,
        )

    elif file_type == "dns":
        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type="DNS",
            action="DNS_QUERY",
            src_host=sanitize_string(raw.get("src_host")),
            dst_host=sanitize_string(raw.get("resolved_host")),
            details={
                "resolved_host": sanitize_string(raw.get("resolved_host")),
            },
            source_file=source_file,
            line_number=line_number,
            raw_line=raw_line,
            is_ground_truth=False,
        )

    elif file_type == "redteam":
        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type="REDTEAM",
            action="REDTEAM_GROUND_TRUTH",
            user=sanitize_string(raw.get("user")),
            src_host=sanitize_string(raw.get("src_host")),
            dst_host=sanitize_string(raw.get("dst_host")),
            details={
                "description": "LANL documented red-team exercise activity",
            },
            source_file=source_file,
            line_number=line_number,
            raw_line=raw_line,
            is_ground_truth=True,
        )

    # Generic fallback
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type="GENERIC",
        action="EVENT",
        user=sanitize_string(raw.get("user")),
        src_host=sanitize_string(raw.get("src_host")),
        dst_host=sanitize_string(raw.get("dst_host")),
        details=raw,
        source_file=source_file,
        line_number=line_number,
        raw_line=raw_line,
        is_ground_truth=False,
    )


def events_to_dataframe(events: list) -> pd.DataFrame:
    """Converts a collection of NormalizedEvent objects or dicts into a typed DataFrame."""
    if not events:
        return pd.DataFrame(columns=[
            "event_id", "timestamp", "event_type", "action", "user",
            "src_host", "dst_host", "src_port", "dst_port", "protocol",
            "process_name", "source_file", "line_number", "is_ground_truth"
        ])

    data = [e.to_dict() if hasattr(e, "to_dict") else e for e in events]
    df = pd.DataFrame(data)
    # Ensure types
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    return df
