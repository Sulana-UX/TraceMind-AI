"""
Unit tests for Safe Export Utilities.
"""

import pandas as pd
from src.export import sanitize_csv_cell, safe_dataframe_to_csv, generate_html_forensic_report, generate_pdf_forensic_report


def test_sanitize_csv_formula_injection():
    # Attack vectors starting with =, +, -, @
    assert sanitize_csv_cell("=cmd|'/C calc'!A0") == "'=cmd|'/C calc'!A0"
    assert sanitize_csv_cell("+12345") == "'+12345"
    assert sanitize_csv_cell("-5+5") == "'-5+5"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("NormalUser") == "NormalUser"


def test_safe_dataframe_to_csv():
    df = pd.DataFrame({
        "username": ["=DDE('calc')", "NormalU"],
        "count": [10, 20]
    })
    csv_str = safe_dataframe_to_csv(df)
    assert "'=DDE('calc')" in csv_str


def test_generate_html_forensic_report():
    mock_report = {
        "metadata": {"generated_at_utc": "2026-10-11T12:00:00Z"},
        "executive_summary": {
            "total_events_analyzed": 50,
            "ground_truth_matches": 1,
            "analytical_detections": 2,
            "duration_seconds": 600,
        },
        "findings": [{
            "title": "Brute Force Detected",
            "severity": "HIGH",
            "confidence_level": "ANALYTICAL_FINDING",
            "category": "AUTH_ANOMALY",
            "start_time": 100,
            "end_time": 150,
            "reason": "Test reason",
            "involved_hosts": ["C1"],
            "involved_users": ["U1"],
            "evidence_sources": [{"file": "auth.txt.gz", "line": 5}],
            "recommendation": "Inspect endpoint"
        }],
        "timeline_key_events": [],
        "provenance": []
    }
    html_out = generate_html_forensic_report(mock_report)
    assert "<!DOCTYPE html>" in html_out
    assert "TraceMind AI" in html_out
    assert "Brute Force Detected" in html_out


def test_generate_pdf_forensic_report():
    mock_report = {
        "metadata": {
            "generated_at_utc": "2026-10-11T12:00:00Z",
            "tool_name": "TraceMind AI",
            "version": "1.0.0",
            "analyst_notes": "Targeted test incident",
        },
        "executive_summary": {
            "total_events_analyzed": 150,
            "relative_time_start": 20,
            "relative_time_end": 500,
            "duration_seconds": 480,
            "unique_users_count": 3,
            "unique_hosts_count": 4,
            "ground_truth_matches": 1,
            "analytical_detections": 1,
        },
        "findings": [{
            "title": "Compromised Credentials via Red Team Activity",
            "severity": "CRITICAL",
            "confidence_level": "CONFIRMED_GROUND_TRUTH",
            "category": "GROUND_TRUTH_VALIDATION",
            "start_time": 120,
            "end_time": 120,
            "reason": "Event matched ground-truth penetration testing record.",
            "involved_hosts": ["C553", "C17693"],
            "involved_users": ["U999@DOM1"],
            "evidence_sources": [{"file": "redteam.txt.gz", "line": 10}],
            "recommendation": "Perform credential rotation."
        }],
        "timeline_key_events": [{
            "timestamp": 120,
            "event_type": "AUTHENTICATION",
            "action": "LogOn",
            "user": "U999@DOM1",
            "src_host": "C553",
            "dst_host": "C17693",
            "source_file": "redteam.txt.gz",
            "line_number": 10,
        }],
        "provenance": [{
            "filename": "redteam.txt.gz",
            "sha256_hash": "606635837c684ad11e464075ecf97bc5df325ff7d7f64614d2d8c8af18051669",
            "record_count": 749,
            "file_size_bytes": 10240,
        }],
        "plausible_explanations": ["Red team penetration testing exercise."],
        "alternative_explanations": ["Authorized internal security audit."],
        "evidence_limitations": ["Relative time format."],
    }
    pdf_bytes = generate_pdf_forensic_report(mock_report)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    # PDF magic bytes
    assert pdf_bytes.startswith(b"%PDF")

