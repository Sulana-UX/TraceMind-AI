# TraceMind AI — Architecture & Technical Design

## 1. System Overview
TraceMind AI is a defensive digital forensics and incident investigation platform designed for low-resource environments (e.g., 8 GB RAM laptops).
Instead of storing entire multi-gigabyte event logs in memory or querying costly external databases, TraceMind AI utilizes a **Streaming Event Pipeline** and an **Explainable Forensics Correlation Engine**.

```
[LANL .gz / CSV / JSON] 
       │ (Incremental streaming generator, chunked reads)
       ▼
 [Log Parsers] (src/parsers.py)
       │ (Handles missing values '?', preserves line numbers & relative timestamps)
       ▼
[Common Normalizer] (src/normalizer.py)
       │ (Converts into NormalizedEvent schema, sanitizes untrusted input)
       ▼
┌──────────────────────┬────────────────────────┬──────────────────────┐
│                      │                        │                      │
▼                      ▼                        ▼                      ▼
[Correlation Engine]  [Anomaly Detector]    [Evidence Graph]     [Integrity Hash]
(Rule-based windows)  (Isolation Forest)    (NetworkX + Plotly)  (Streaming SHA-256)
       │                      │                        │                      │
       └──────────────────────┴────────────────────────┴──────────────────────┘
                               │
                               ▼
                   [Investigation Story Builder]
                   (src/story_builder.py)
                               │
              ┌────────────────┴────────────────┐
              ▼                                 ▼
      [Streamlit UI]                  [Export Engine]
     (Interactive App)            (JSON, Safe CSV, HTML)
```

## 2. Core Modules
- **`src/integrity.py`**: Calculates SHA-256 hashes incrementally in 64 KB buffers to protect memory while establishing a cryptographic chain of custody.
- **`src/parsers.py`**: Memory-efficient generator functions reading gzipped and plain-text LANL logs line-by-line without loading entire files into RAM.
- **`src/normalizer.py`**: Normalizes divergent schemas (`auth`, `proc`, `flows`, `dns`, `redteam`) into a canonical `NormalizedEvent` data structure.
- **`src/correlation_engine.py`**: Temporal and entity correlation engine that links multi-step incident behavior with human-readable rationale and exact evidence references.
- **`src/anomaly_detector.py`**: Isolation Forest baseline that generates behavioral outlier scores strictly as triage prioritization signals.
- **`src/evidence_graph.py`**: NetworkX graph generator with dynamic node pruning and Plotly interactive rendering.
- **`src/story_builder.py`**: Deterministic forensic narrative generator assembling facts, key timelines, hypotheses, and defensive remediation advice.
- **`src/export.py`**: Formula-injection-safe CSV generator, JSON serialization, and standalone HTML report exporter.

## 3. Memory & Resource Optimization for 8 GB RAM
1. **No In-Memory Full File Loading**: Streaming generators yield individual events.
2. **Configurable Ingestion Caps**: Users configure row limits (`max_rows`), sampling intervals (`sample_step`), and relative time windows.
3. **Graph Pruning**: Maximum nodes capped to prevent WebGL browser tab crashes.
4. **Local-First / Zero Cloud Overhead**: Runs 100% locally with zero paid APIs, GPUs, or background daemon databases.
