"""
Unit tests for Evidence Relationship Graph Builder.
"""

from src.normalizer import NormalizedEvent
from src.evidence_graph import EvidenceGraphBuilder


def test_build_graph_entities_and_edges():
    builder = EvidenceGraphBuilder(max_nodes=50)
    events = [
        NormalizedEvent("1", 100, "AUTH", "LOGON_SUCCESS", user="U1@DOM1", src_host="C10", dst_host="C20", source_file="auth.txt.gz", line_number=1),
        NormalizedEvent("2", 110, "PROCESS", "PROCESS_START", user="U1@DOM1", src_host="C20", process_name="cmd.exe", source_file="proc.txt.gz", line_number=2),
        NormalizedEvent("3", 120, "NETWORK_FLOW", "FLOW", src_host="C20", dst_host="C99", source_file="flows.txt.gz", line_number=3),
    ]

    g = builder.build_graph(events)
    # Check nodes
    assert g.has_node("User:U1@DOM1")
    assert g.has_node("Host:C20")
    assert g.has_node("Proc:cmd.exe")
    assert g.has_node("Host:C99")

    # Check edges
    assert g.has_edge("User:U1@DOM1", "Host:C20")
    assert g.has_edge("Host:C20", "Proc:cmd.exe")
    assert g.has_edge("Host:C20", "Host:C99")


def test_build_graph_max_nodes_cap():
    builder = EvidenceGraphBuilder(max_nodes=5)
    # Create 10 different hosts
    events = [
        NormalizedEvent(str(i), 100 + i, "NETWORK_FLOW", "FLOW", src_host=f"C{i}", dst_host=f"C{i+10}", source_file="flows.txt.gz", line_number=i)
        for i in range(10)
    ]
    g = builder.build_graph(events)
    assert g.number_of_nodes() <= 5
