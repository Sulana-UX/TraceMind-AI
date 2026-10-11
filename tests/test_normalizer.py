"""
Unit tests for Event Normalization and Field Sanitization.
"""

from src.normalizer import normalize_record, sanitize_string, events_to_dataframe


def test_sanitize_string():
    assert sanitize_string("  NormalUser  ") == "NormalUser"
    assert sanitize_string("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert sanitize_string(None) is None


def test_normalize_auth():
    raw = {
        "_file_type": "auth",
        "_source_file": "auth.txt.gz",
        "_line_number": 42,
        "_raw_line": "100,U1@DOM1,C2,C1,C2,Kerberos,Network,LogOn,Success",
        "time": 100,
        "src_user": "U1@DOM1",
        "dst_user": "C2",
        "src_host": "C1",
        "dst_host": "C2",
        "status": "Success",
        "auth_type": "Kerberos",
        "logon_type": "Network",
        "auth_orientation": "LogOn",
    }
    ev = normalize_record(raw)
    assert ev is not None
    assert ev.event_id == "auth.txt.gz:42"
    assert ev.timestamp == 100
    assert ev.event_type == "AUTH"
    assert ev.action == "LOGON_SUCCESS"
    assert ev.user == "U1@DOM1"
    assert ev.src_host == "C1"
    assert ev.dst_host == "C2"
    assert ev.is_ground_truth is False


def test_normalize_redteam():
    raw = {
        "_file_type": "redteam",
        "_source_file": "redteam.txt.gz",
        "_line_number": 1,
        "_raw_line": "150885,U620@DOM1,C17693,C1003",
        "time": 150885,
        "user": "U620@DOM1",
        "src_host": "C17693",
        "dst_host": "C1003",
    }
    ev = normalize_record(raw)
    assert ev is not None
    assert ev.event_type == "REDTEAM"
    assert ev.is_ground_truth is True
    assert ev.user == "U620@DOM1"


def test_events_to_dataframe():
    raw = {
        "_file_type": "proc",
        "_source_file": "proc.txt.gz",
        "_line_number": 10,
        "_raw_line": "200,U1,C1,cmd.exe,Start",
        "time": 200,
        "user": "U1",
        "host": "C1",
        "process_name": "cmd.exe",
        "action": "Start",
    }
    ev = normalize_record(raw)
    df = events_to_dataframe([ev])
    assert len(df) == 1
    assert "timestamp" in df.columns
    assert df["timestamp"].iloc[0] == 200
