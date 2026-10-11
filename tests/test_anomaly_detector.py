"""
Unit tests for Machine Learning Anomaly Detector.
"""

from src.normalizer import NormalizedEvent
from src.anomaly_detector import EntityAnomalyDetector


def test_anomaly_detector_small_sample():
    detector = EntityAnomalyDetector()
    events = [
        NormalizedEvent("1", 100, "AUTH", "LOGON_SUCCESS", user="U1@DOM1", src_host="C1", dst_host="C2"),
        NormalizedEvent("2", 105, "AUTH", "LOGON_FAIL", user="U_BAD@DOM1", src_host="C10", dst_host="C20"),
        NormalizedEvent("3", 110, "AUTH", "LOGON_FAIL", user="U_BAD@DOM1", src_host="C10", dst_host="C20"),
        NormalizedEvent("4", 115, "AUTH", "LOGON_FAIL", user="U_BAD@DOM1", src_host="C10", dst_host="C20"),
    ]

    df_anom = detector.fit_predict(events)
    assert not df_anom.empty
    assert "entity_id" in df_anom.columns
    assert "anomaly_score" in df_anom.columns
    top_entity = df_anom.iloc[0]["entity_id"]
    assert top_entity == "U_BAD@DOM1"


def test_anomaly_detector_empty():
    detector = EntityAnomalyDetector()
    df_anom = detector.fit_predict([])
    assert df_anom.empty
