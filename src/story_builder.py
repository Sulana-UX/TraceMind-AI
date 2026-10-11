"""
Evidence-Grounded Investigation Story Builder
Generates deterministic, forensic investigation reports based strictly on observed log evidence.
Never fabricates evidence, commands, users, IP addresses, or attack outcomes.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from src.normalizer import NormalizedEvent
from src.correlation_engine import CorrelatedFinding


class StoryBuilder:
    def __init__(self, analyst_notes: Optional[str] = None):
        self.analyst_notes = analyst_notes or ""

    def build_report(
        self,
        events: List[NormalizedEvent],
        findings: List[CorrelatedFinding],
        anomaly_df: Any = None,
        provenance_records: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Builds a comprehensive, evidence-linked digital forensics story report.
        """
        total_events = len(events)
        timestamps = [e.timestamp for e in events if e.timestamp is not None]
        min_time = min(timestamps) if timestamps else 0
        max_time = max(timestamps) if timestamps else 0
        time_span = max_time - min_time

        unique_users = sorted(list({e.user for e in events if e.user}))
        unique_hosts = sorted(list({e.src_host for e in events if e.src_host} | {e.dst_host for e in events if e.dst_host}))

        # Severity count breakdown
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        # Ground truth matches vs analytical detections
        ground_truth_findings = [f for f in findings if f.confidence_level == "CONFIRMED_GROUND_TRUTH"]
        analytical_findings = [f for f in findings if f.confidence_level != "CONFIRMED_GROUND_TRUTH"]

        # Evidentiary Key Events Timeline (events linked to findings or anomalies)
        key_event_ids = set()
        for f in findings:
            key_event_ids.update(f.involved_events)

        key_events = [e for e in events if e.event_id in key_event_ids]
        key_events.sort(key=lambda x: (x.timestamp, x.line_number))

        # Forensic hypotheses and alternative explanations
        plausible_explanations = []
        alternative_explanations = []

        if any(f.category == "AUTH_ANOMALY" for f in findings):
            plausible_explanations.append(
                "Credential Guessing / Brute-Force: An unauthorized entity systematically tested credentials until achieving valid access."
            )
            alternative_explanations.append(
                "Benign Misconfiguration: A scheduled service, script, or user with expired credentials repeatedly retried automated authentication."
            )

        if any(f.category == "PROCESS_ANOMALY" for f in findings):
            plausible_explanations.append(
                "Post-Exploitation Execution: The actor obtained interactive command shell execution to execute discovery tools."
            )
            alternative_explanations.append(
                "Legitimate Administrative Activity: A system administrator or DevOps automation script executed maintenance tasks."
            )

        if any(f.category == "EXFILTRATION" for f in findings):
            plausible_explanations.append(
                "Data Exfiltration: Sensitive data staged on the host was transmitted outbound over network sockets."
            )
            alternative_explanations.append(
                "Routine Backup / File Synchronization: Legitimate file transfers or database synchronization occurred."
            )

        if not plausible_explanations:
            plausible_explanations.append("Activity conforms to normal baseline patterns observed in this log segment.")
            alternative_explanations.append("No active malicious indicators identified within selected time bounds.")

        # Limitations & Missing Evidence
        evidence_limitations = [
            "Dataset De-identification: LANL dataset uses masked identifiers (e.g., C17693, U620@DOM1) without public IP addresses or full hostnames.",
            "Process Arguments Missing: Process logs indicate executable names (e.g., cmd.exe) but lack full command-line arguments and parent process GUIDs.",
            "Temporal Relativity: Timestamps are preserved as relative integer seconds from dataset epoch rather than calendar UTC dates.",
            "Sampling Boundaries: Any row limits or time sampling configured in ingestion constrain the visibility of precursor or follow-on events.",
            "Unsupervised ML Boundaries: Isolation Forest scores highlight statistical outliers; they do not prove malicious intent or compromise.",
        ]

        # Recommended Defensive Actions
        defensive_recommendations = [
            "Audit targeted accounts across Active Directory / Kerberos domain controllers for unauthorized privileges.",
            "Verify endpoint telemetry on affected hosts for persistence mechanisms (Scheduled Tasks, Registry run keys, WMI subscriptions).",
            "Review firewall and flow egress records corresponding to identified high-byte transfer timestamps.",
            "Implement multi-factor authentication (MFA) and lock-out policies to mitigate repetitive credential guessing.",
        ]

        report = {
            "metadata": {
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "tool_name": "TraceMind AI - Digital Evidence Story Builder",
                "version": "1.0.0",
                "analyst_notes": self.analyst_notes,
            },
            "executive_summary": {
                "total_events_analyzed": total_events,
                "relative_time_start": min_time,
                "relative_time_end": max_time,
                "duration_seconds": time_span,
                "unique_users_count": len(unique_users),
                "unique_hosts_count": len(unique_hosts),
                "findings_summary": severity_counts,
                "ground_truth_matches": len(ground_truth_findings),
                "analytical_detections": len(analytical_findings),
            },
            "provenance": provenance_records or [],
            "ground_truth_analysis": [f.to_dict() for f in ground_truth_findings],
            "findings": [f.to_dict() for f in findings],
            "timeline_key_events": [e.to_dict() for e in key_events],
            "plausible_explanations": plausible_explanations,
            "alternative_explanations": alternative_explanations,
            "evidence_limitations": evidence_limitations,
            "defensive_recommendations": defensive_recommendations,
        }

        return report

    def render_markdown(self, report: Dict[str, Any]) -> str:
        """Renders report dictionary into a clean, professional GitHub-flavored Markdown report."""
        ex = report["executive_summary"]
        lines = []

        lines.append("# TraceMind AI — Digital Evidence Investigation Report")
        lines.append(f"*Generated at: {report['metadata']['generated_at_utc']} (UTC)*\n")
        lines.append("---")
        lines.append("## 1. Executive Summary")
        lines.append(f"- **Total Records Analyzed**: {ex['total_events_analyzed']:,}")
        lines.append(f"- **Relative Time Window**: t={ex['relative_time_start']} to t={ex['relative_time_end']} ({ex['duration_seconds']:,} seconds)")
        lines.append(f"- **Entities Observed**: {ex['unique_users_count']} Unique Users | {ex['unique_hosts_count']} Unique Hosts")
        lines.append(f"- **Confirmed Ground Truth Events**: {ex['ground_truth_matches']}")
        lines.append(f"- **Correlated Analytical Findings**: {ex['analytical_detections']}")
        lines.append("")
        lines.append("### Finding Severity Breakdown:")
        for sev, count in ex["findings_summary"].items():
            lines.append(f"- **{sev}**: {count}")

        if report["metadata"].get("analyst_notes"):
            lines.append("\n### Analyst Case Notes:")
            lines.append(f"> {report['metadata']['analyst_notes']}")

        lines.append("\n---")
        lines.append("## 2. Evidence-Correlated Incident Findings")
        if not report["findings"]:
            lines.append("No suspicious multi-event correlations detected within the analyzed event window.")
        else:
            for idx, f in enumerate(report["findings"], 1):
                lines.append(f"### Finding #{idx}: {f['title']}")
                lines.append(f"- **Severity**: `{f['severity']}` | **Confidence**: `{f['confidence_level']}` | **Category**: `{f['category']}`")
                lines.append(f"- **Time Span**: Relative seconds t={f['start_time']} to t={f['end_time']}")
                lines.append(f"- **Involved Entities**: Users: `{', '.join(f['involved_users']) or 'None'}` | Hosts: `{', '.join(f['involved_hosts']) or 'None'}`")
                lines.append(f"- **Correlation Reasoning**:\n  {f['reason']}")
                lines.append(f"- **Evidence Traceability**:")
                for src in f["evidence_sources"][:8]:
                    lines.append(f"  - Source: `{src['file']}` (Line #{src['line']})")
                if len(f["evidence_sources"]) > 8:
                    lines.append(f"  - *...and {len(f['evidence_sources']) - 8} more supporting log records*")
                lines.append(f"- **Investigative Recommendation**:\n  {f['recommendation']}\n")

        lines.append("---")
        lines.append("## 3. Timeline of Key Evidentiary Events")
        if not report["timeline_key_events"]:
            lines.append("No evidentiary events singled out.")
        else:
            lines.append("| Time (rel sec) | Event Type | Action | User | Src Host | Dst Host | Evidence Reference |")
            lines.append("|---|---|---|---|---|---|---|")
            for ke in report["timeline_key_events"][:30]:
                u = ke.get("user") or "-"
                sh = ke.get("src_host") or "-"
                dh = ke.get("dst_host") or "-"
                lines.append(f"| {ke['timestamp']} | {ke['event_type']} | {ke['action']} | {u} | {sh} | {dh} | `{ke['source_file']}:{ke['line_number']}` |")

        lines.append("\n---")
        lines.append("## 4. Analytical Hypotheses vs Alternative Explanations")
        lines.append("### Plausible Hypotheses:")
        for p in report["plausible_explanations"]:
            lines.append(f"- {p}")
        lines.append("\n### Alternative (Benign) Explanations:")
        for a in report["alternative_explanations"]:
            lines.append(f"- {a}")

        lines.append("\n---")
        lines.append("## 5. Confidence Limitations & Missing Evidence")
        for lim in report["evidence_limitations"]:
            lines.append(f"- [Limitation] {lim}")

        lines.append("\n---")
        lines.append("## 6. Recommended Defensive Actions")
        for rec in report["defensive_recommendations"]:
            lines.append(f"- [Action] {rec}")

        lines.append("\n---")
        lines.append("## 7. Evidence Provenance & Cryptographic Hashes")
        if report["provenance"]:
            lines.append("| File | SHA-256 Checksum | Records | Malformed | File Size |")
            lines.append("|---|---|---|---|---|")
            for p in report["provenance"]:
                lines.append(f"| `{p['filename']}` | `{p['sha256_hash'][:16]}...` | {p['record_count']:,} | {p['malformed_count']} | {p['file_size_bytes']:,} bytes |")
        else:
            lines.append("No external source file provenance captured for this session.")

        return "\n".join(lines)
