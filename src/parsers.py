"""
Streaming Log Ingestion and Schema Parsers
Supports memory-safe line-by-line reading of LANL cybersecurity gzip and plain-text files.
"""

import gzip
import io
import json
import csv
from pathlib import Path
from typing import Generator, Dict, Any, Optional, Tuple, List


# Official LANL Schemas (comma-separated, no headers, missing='?')
# auth: time, src_user@domain, dst_user@domain, src_comp, dst_comp, auth_type, logon_type, auth_orientation, status
# proc: time, user@domain, comp, proc_name, start/end
# flows: time, duration, src_comp, src_port, dst_comp, dst_port, protocol, packet_count, byte_count
# dns: time, src_comp, comp_resolved
# redteam: time, user@domain, src_comp, dst_comp

LANL_SCHEMAS = {
    "auth": ["time", "src_user", "dst_user", "src_host", "dst_host", "auth_type", "logon_type", "auth_orientation", "status"],
    "proc": ["time", "user", "host", "process_name", "action"],
    "flows": ["time", "duration", "src_host", "src_port", "dst_host", "dst_port", "protocol", "packet_count", "byte_count"],
    "dns": ["time", "src_host", "resolved_host"],
    "redteam": ["time", "user", "src_host", "dst_host"],
}


def detect_lanl_file_type(filename: str) -> Optional[str]:
    """Detect LANL file type based on file name prefix."""
    lower = Path(filename).name.lower()
    for ftype in ["auth", "proc", "flows", "dns", "redteam"]:
        if ftype in lower:
            return ftype
    return None


def open_log_stream(filepath: str):
    """
    Safely opens plain text or gzip compressed files for reading line-by-line.
    Uses 'replace' error handling for encoding issues.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    if path.suffix.lower() == ".gz":
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    else:
        return open(path, mode="rt", encoding="utf-8", errors="replace")


def parse_lanl_line(line: str, schema_fields: List[str]) -> Optional[Dict[str, Any]]:
    """
    Parses a single comma-delimited line from LANL dataset.
    Converts '?' to None, strips whitespace, validates expected column count.
    """
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    tokens = [t.strip() for t in raw.split(",")]
    if len(tokens) < len(schema_fields):
        return None

    record = {}
    for i, field in enumerate(schema_fields):
        val = tokens[i]
        if val == "?" or val == "":
            record[field] = None
        else:
            record[field] = val

    # Convert time to int if possible
    if "time" in record and record["time"] is not None:
        try:
            record["time"] = int(record["time"])
        except ValueError:
            return None

    # Convert numeric fields where applicable
    for num_col in ["duration", "src_port", "dst_port", "packet_count", "byte_count"]:
        if num_col in record and record[num_col] is not None:
            try:
                record[num_col] = int(record[num_col])
            except ValueError:
                pass

    return record


def stream_lanl_file(
    filepath: str,
    file_type: Optional[str] = None,
    max_rows: Optional[int] = 10000,
    sample_step: int = 1,
    time_min: Optional[int] = None,
    time_max: Optional[int] = None,
) -> Generator[Dict[str, Any], None, Tuple[int, int]]:
    """
    Incrementally yields parsed events from a LANL log file.
    Returns generator that ends with total processed lines and malformed line count.
    Memory-efficient for 8 GB RAM machines.
    """
    if file_type is None:
        file_type = detect_lanl_file_type(filepath)
        if file_type is None:
            raise ValueError(f"Could not auto-detect LANL file type for '{filepath}'. Specify file_type explicitly.")

    schema = LANL_SCHEMAS[file_type]
    filename = Path(filepath).name

    total_lines = 0
    yielded_records = 0
    malformed_lines = 0

    with open_log_stream(filepath) as stream:
        for line_idx, line in enumerate(stream, start=1):
            total_lines += 1

            # Subsampling check
            if sample_step > 1 and (line_idx % sample_step != 0):
                continue

            parsed = parse_lanl_line(line, schema)
            if parsed is None:
                malformed_lines += 1
                continue

            # Time window filter
            event_time = parsed.get("time")
            if time_min is not None and event_time is not None and event_time < time_min:
                continue
            if time_max is not None and event_time is not None and event_time > time_max:
                continue

            parsed["_source_file"] = filename
            parsed["_line_number"] = line_idx
            parsed["_raw_line"] = line.strip()
            parsed["_file_type"] = file_type

            yielded_records += 1
            yield parsed

            if max_rows is not None and yielded_records >= max_rows:
                break

    return yielded_records, malformed_lines


def stream_generic_json(
    filepath: str,
    max_rows: Optional[int] = 10000,
) -> Generator[Dict[str, Any], None, Tuple[int, int]]:
    """Reads JSON Lines format incrementally."""
    filename = Path(filepath).name
    yielded = 0
    malformed = 0

    with open_log_stream(filepath) as stream:
        for idx, line in enumerate(stream, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                data["_source_file"] = filename
                data["_line_number"] = idx
                data["_raw_line"] = line
                data["_file_type"] = "generic_json"
                yielded += 1
                yield data
                if max_rows is not None and yielded >= max_rows:
                    break
            except Exception:
                malformed += 1

    return yielded, malformed
