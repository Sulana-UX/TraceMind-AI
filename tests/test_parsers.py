"""
Unit tests for Streaming Log Parsers.
"""

import gzip
import tempfile
import os
from src.parsers import parse_lanl_line, stream_lanl_file, LANL_SCHEMAS


def test_parse_lanl_auth_valid():
    schema = LANL_SCHEMAS["auth"]
    line = "150885,U620@DOM1,C1003,C17693,C1003,Kerberos,Network,LogOn,Success"
    record = parse_lanl_line(line, schema)

    assert record is not None
    assert record["time"] == 150885
    assert record["src_user"] == "U620@DOM1"
    assert record["dst_user"] == "C1003"
    assert record["src_host"] == "C17693"
    assert record["dst_host"] == "C1003"
    assert record["status"] == "Success"


def test_parse_lanl_missing_fields_question_mark():
    schema = LANL_SCHEMAS["auth"]
    line = "100,?,?,C17693,C1003,?,?,?,Fail"
    record = parse_lanl_line(line, schema)

    assert record is not None
    assert record["time"] == 100
    assert record["src_user"] is None
    assert record["dst_user"] is None
    assert record["src_host"] == "C17693"
    assert record["status"] == "Fail"


def test_parse_lanl_malformed_lines():
    schema = LANL_SCHEMAS["proc"]
    # Too few tokens
    assert parse_lanl_line("100,U1@DOM1", schema) is None
    # Bad non-numeric timestamp
    assert parse_lanl_line("NOT_A_TIME,U1@DOM1,C1,cmd.exe,Start", schema) is None
    # Empty string or comment
    assert parse_lanl_line("", schema) is None
    assert parse_lanl_line("# comment", schema) is None


def test_stream_lanl_file_with_limits():
    # Create temporary gzipped auth file
    lines = [
        "10,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success\n",
        "20,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Fail\n",
        "BAD_LINE\n",
        "30,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success\n",
        "40,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success\n",
    ]
    with tempfile.NamedTemporaryFile("wb", suffix="_auth.txt.gz", delete=False) as f:
        with gzip.open(f, "wt", encoding="utf-8") as gz:
            gz.writelines(lines)
        temp_path = f.name

    try:
        # Test max_rows cap
        records = list(stream_lanl_file(temp_path, file_type="auth", max_rows=2))
        assert len(records) == 2
        assert records[0]["time"] == 10
        assert records[1]["time"] == 20

        # Test time filtering
        filtered = list(stream_lanl_file(temp_path, file_type="auth", time_min=25, time_max=35))
        assert len(filtered) == 1
        assert filtered[0]["time"] == 30
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
