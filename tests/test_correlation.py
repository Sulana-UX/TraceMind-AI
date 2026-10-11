"""
Unit tests for Event Correlation Engine.
"""

from src.normalizer import NormalizedEvent
from src.correlation_engine import CorrelationEngine


def test_correlate_failed_then_success():
    engine = CorrelationEngine(time_window_seconds=120)
    events = [
        NormalizedEvent("1", 100, "AUTH", "LOGON_FAIL", user="U1@DOM1", src_host="C10", dst_host="C50", source_file="auth", line_number=1),
        NormalizedEvent("2", 110, "AUTH", "LOGON_FAIL", user="U1@DOM1", src_host="C10", dst_host="C50", source_file="auth", line_number=2),
        NormalizedEvent("3", 120, "AUTH", "LOGON_FAIL", user="U1@DOM1", src_host="C10", dst_host="C50", source_file="auth", line_number=3),
        NormalizedEvent("4", 130, "AUTH", "LOGON_SUCCESS", user="U1@DOM1", src_host="C10", dst_host="C50", source_file="auth", line_number=4),
    ]

    findings = engine.correlate(events)
    assert len(findings) >= 1
    bf = next((f for f in findings if f.category == "AUTH_ANOMALY"), None)
    assert bf is not None
    assert bf.confidence_level == "ANALYTICAL_FINDING"
    assert bf.severity == "HIGH"
    assert "C50" in bf.involved_hosts
    assert len(bf.evidence_sources) == 4


def test_correlate_logon_to_process():
    engine = CorrelationEngine(time_window_seconds=60)
    events = [
        NormalizedEvent("1", 200, "AUTH", "LOGON_SUCCESS", user="U2@DOM1", src_host="C10", dst_host="C80", source_file="auth", line_number=1),
        NormalizedEvent("2", 215, "PROCESS", "PROCESS_START", user="U2@DOM1", src_host="C80", process_name="cmd.exe", source_file="proc", line_number=5),
    ]

    findings = engine.correlate(events)
    proc_finding = next((f for f in findings if f.category == "PROCESS_ANOMALY"), None)
    assert proc_finding is not None
    assert "cmd.exe" in proc_finding.reason


def test_no_false_correlation_outside_window():
    engine = CorrelationEngine(time_window_seconds=30)
    events = [
        NormalizedEvent("1", 100, "AUTH", "LOGON_FAIL", user="U1", src_host="C1", dst_host="C2", source_file="auth", line_number=1),
        NormalizedEvent("2", 110, "AUTH", "LOGON_FAIL", user="U1", src_host="C1", dst_host="C2", source_file="auth", line_number=2),
        NormalizedEvent("3", 120, "AUTH", "LOGON_FAIL", user="U1", src_host="C1", dst_host="C2", source_file="auth", line_number=3),
        # Success happens 200 seconds later (far outside 30s window)
        NormalizedEvent("4", 320, "AUTH", "LOGON_SUCCESS", user="U1", src_host="C1", dst_host="C2", source_file="auth", line_number=4),
    ]

    findings = engine.correlate(events)
    bf = [f for f in findings if f.category == "AUTH_ANOMALY"]
    assert len(bf) == 0
