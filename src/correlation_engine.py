"""
Explainable Event Correlation Engine
Correlates normalized security events across multiple log sources.
Distinguishes between observed evidence, analytical findings, hypotheses, and confirmed ground truth.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict, field
from src.normalizer import NormalizedEvent


@dataclass
class CorrelatedFinding:
    finding_id: str
    title: str
    severity: str          # LOW, MEDIUM, HIGH, CRITICAL
    category: str          # AUTH_ANOMALY, PROCESS_ANOMALY, LATERAL_MOVEMENT, EXFILTRATION, GROUND_TRUTH
    confidence_level: str  # OBSERVED_FACT, ANALYTICAL_FINDING, HYPOTHESIS, CONFIRMED_GROUND_TRUTH
    reason: str
    involved_events: List[str]  # event_ids
    involved_users: List[str]
    involved_hosts: List[str]
    evidence_sources: List[Dict[str, Any]]  # [{"file": ..., "line": ...}]
    start_time: int
    end_time: int
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CorrelationEngine:
    def __init__(self, time_window_seconds: int = 300):
        """
        :param time_window_seconds: Configurable window for correlating related events.
        """
        self.time_window_seconds = time_window_seconds

    def correlate(self, events: List[NormalizedEvent]) -> List[CorrelatedFinding]:
        """
        Executes explainable correlation rules against a chronologically ordered list of events.
        """
        if not events:
            return []

        # Ensure events are sorted by timestamp
        sorted_events = sorted(events, key=lambda e: (e.timestamp, e.line_number))
        findings: List[CorrelatedFinding] = []

        # 1. Rule: Failed Logins followed by Successful Logon (Potential Brute Force / Credential Guessing)
        findings.extend(self._correlate_failed_then_success(sorted_events))

        # 2. Rule: Logon followed immediately by Process Execution on target host
        findings.extend(self._correlate_logon_to_process(sorted_events))

        # 3. Rule: DNS Resolution immediately followed by Outbound Network Flow
        findings.extend(self._correlate_dns_to_network_flow(sorted_events))

        # 4. Rule: Multi-Host Access / Potential Lateral Movement
        findings.extend(self._correlate_lateral_movement(sorted_events))

        # 5. Rule: Correlate Ground Truth Red Team Events with Observed Activity
        findings.extend(self._correlate_redteam_ground_truth(sorted_events))

        return findings

    def _correlate_failed_then_success(self, events: List[NormalizedEvent]) -> List[CorrelatedFinding]:
        findings = []
        auth_events = [e for e in events if e.event_type == "AUTH"]

        for i, ev in enumerate(auth_events):
            if ev.action == "LOGON_SUCCESS":
                # Look back in window for failed logins targeting the same host or user
                failed_preceding = []
                for prev in reversed(auth_events[:i]):
                    if ev.timestamp - prev.timestamp > self.time_window_seconds:
                        break
                    if prev.action == "LOGON_FAIL" and (
                        (prev.dst_host and prev.dst_host == ev.dst_host) or
                        (prev.user and prev.user == ev.user)
                    ):
                        failed_preceding.append(prev)

                if len(failed_preceding) >= 3:
                    f_id = f"FIND-AUTH-BF-{ev.event_id}"
                    users = list({e.user for e in failed_preceding + [ev] if e.user})
                    hosts = list({e.dst_host for e in failed_preceding + [ev] if e.dst_host} |
                                 {e.src_host for e in failed_preceding + [ev] if e.src_host})
                    ev_ids = [e.event_id for e in failed_preceding] + [ev.event_id]
                    ev_sources = [{"file": e.source_file, "line": e.line_number} for e in failed_preceding + [ev]]

                    findings.append(CorrelatedFinding(
                        finding_id=f_id,
                        title=f"Multiple Authentication Failures Preceding Successful Logon ({len(failed_preceding)} fails)",
                        severity="HIGH",
                        category="AUTH_ANOMALY",
                        confidence_level="ANALYTICAL_FINDING",
                        reason=(
                            f"Host '{ev.dst_host}' received {len(failed_preceding)} failed logon attempts within "
                            f"{self.time_window_seconds}s before a successful logon by user '{ev.user}'. "
                            f"This temporal sequence is consistent with credential guessing, password spraying, or misconfiguration."
                        ),
                        involved_events=ev_ids,
                        involved_users=users,
                        involved_hosts=hosts,
                        evidence_sources=ev_sources,
                        start_time=min(e.timestamp for e in failed_preceding),
                        end_time=ev.timestamp,
                        recommendation="Review the source IP/host, verify if the user legitimately attempted login, and inspect for secondary access tokens.",
                    ))
        return findings

    def _correlate_logon_to_process(self, events: List[NormalizedEvent]) -> List[CorrelatedFinding]:
        findings = []
        logons = [e for e in events if e.event_type == "AUTH" and e.action == "LOGON_SUCCESS"]
        procs = [e for e in events if e.event_type == "PROCESS" and e.action == "PROCESS_START"]

        for logon in logons:
            # Look forward for processes executed on dst_host within time window
            related_procs = []
            for proc in procs:
                if proc.timestamp < logon.timestamp:
                    continue
                if proc.timestamp - logon.timestamp > self.time_window_seconds:
                    break
                if proc.src_host == logon.dst_host or (proc.user and proc.user == logon.user):
                    related_procs.append(proc)

            # Check if any process is unusual or suspicious (e.g. cmd.exe, powershell, recon)
            suspicious_proc_names = ["cmd.exe", "powershell", "recon", "vssadmin", "mimikatz", "p999"]
            suspicious_executed = [
                p for p in related_procs
                if p.process_name and any(sp in p.process_name.lower() for sp in suspicious_proc_names)
            ]

            if suspicious_executed:
                f_id = f"FIND-PROC-EXEC-{logon.event_id}"
                ev_list = [logon] + suspicious_executed
                findings.append(CorrelatedFinding(
                    finding_id=f_id,
                    title="Suspicious Process Execution Followed Remote Authentication",
                    severity="HIGH",
                    category="PROCESS_ANOMALY",
                    confidence_level="ANALYTICAL_FINDING",
                    reason=(
                        f"Immediately after user '{logon.user}' logged onto '{logon.dst_host}' at t={logon.timestamp}, "
                        f"{len(suspicious_executed)} command execution / reconnaissance process(es) were launched "
                        f"({', '.join(p.process_name for p in suspicious_executed)})."
                    ),
                    involved_events=[e.event_id for e in ev_list],
                    involved_users=list({e.user for e in ev_list if e.user}),
                    involved_hosts=list({e.src_host for e in ev_list if e.src_host} | {e.dst_host for e in ev_list if e.dst_host}),
                    evidence_sources=[{"file": e.source_file, "line": e.line_number} for e in ev_list],
                    start_time=logon.timestamp,
                    end_time=max(p.timestamp for p in suspicious_executed),
                    recommendation="Isolate endpoint, inspect command-line arguments and parent process tree, and capture volatile memory if warranted.",
                ))
        return findings

    def _correlate_dns_to_network_flow(self, events: List[NormalizedEvent]) -> List[CorrelatedFinding]:
        findings = []
        dns_events = [e for e in events if e.event_type == "DNS"]
        flow_events = [e for e in events if e.event_type == "NETWORK_FLOW"]

        for dns in dns_events:
            for flow in flow_events:
                if flow.timestamp < dns.timestamp:
                    continue
                if flow.timestamp - dns.timestamp > self.time_window_seconds:
                    break
                # Check connection from same src_host
                if dns.src_host == flow.src_host and flow.dst_host == dns.dst_host:
                    bytes_val = flow.details.get("byte_count") if flow.details else 0
                    if bytes_val and bytes_val > 1000000:  # > 1 MB in single flow
                        f_id = f"FIND-NET-SPIKE-{dns.event_id}"
                        ev_list = [dns, flow]
                        findings.append(CorrelatedFinding(
                            finding_id=f_id,
                            title="Large Outbound Flow Preceded by DNS Resolution (Potential Data Exfiltration)",
                            severity="CRITICAL" if bytes_val > 50000000 else "MEDIUM",
                            category="EXFILTRATION",
                            confidence_level="HYPOTHESIS",
                            reason=(
                                f"Host '{dns.src_host}' resolved '{dns.dst_host}' at t={dns.timestamp}, followed by "
                                f"a high-volume network flow of {bytes_val:,} bytes to '{flow.dst_host}' at t={flow.timestamp}."
                            ),
                            involved_events=[e.event_id for e in ev_list],
                            involved_users=[],
                            involved_hosts=[dns.src_host, dns.dst_host],
                            evidence_sources=[{"file": e.source_file, "line": e.line_number} for e in ev_list],
                            start_time=dns.timestamp,
                            end_time=flow.timestamp,
                            recommendation="Inspect network capture, examine destination endpoint reputation, and check data transfer authorization.",
                        ))
        return findings

    def _correlate_lateral_movement(self, events: List[NormalizedEvent]) -> List[CorrelatedFinding]:
        findings = []
        user_auths: Dict[str, List[NormalizedEvent]] = {}
        for ev in events:
            if ev.event_type == "AUTH" and ev.action == "LOGON_SUCCESS" and ev.user:
                user_auths.setdefault(ev.user, []).append(ev)

        for user, auths in user_auths.items():
            if len(auths) < 2:
                continue
            # Check unique target computers in a sliding window
            for i in range(len(auths)):
                window = [
                    a for a in auths[i:]
                    if a.timestamp - auths[i].timestamp <= self.time_window_seconds
                ]
                distinct_dsts = {a.dst_host for a in window if a.dst_host}
                if len(distinct_dsts) >= 3:
                    f_id = f"FIND-LAT-MOV-{user}-{auths[i].timestamp}"
                    findings.append(CorrelatedFinding(
                        finding_id=f_id,
                        title=f"Rapid Multi-Host Logons for User {user} (Potential Lateral Movement)",
                        severity="HIGH",
                        category="LATERAL_MOVEMENT",
                        confidence_level="ANALYTICAL_FINDING",
                        reason=(
                            f"User '{user}' successfully logged into {len(distinct_dsts)} distinct hosts "
                            f"({', '.join(distinct_dsts)}) within {self.time_window_seconds}s."
                        ),
                        involved_events=[a.event_id for a in window],
                        involved_users=[user],
                        involved_hosts=list(distinct_dsts),
                        evidence_sources=[{"file": a.source_file, "line": a.line_number} for a in window],
                        start_time=window[0].timestamp,
                        end_time=window[-1].timestamp,
                        recommendation="Check if this account is a service account or domain administrator, and verify if multi-system hop is legitimate.",
                    ))
                    break  # Avoid duplicate sub-window findings
        return findings

    def _correlate_redteam_ground_truth(self, events: List[NormalizedEvent]) -> List[CorrelatedFinding]:
        findings = []
        redteam_events = [e for e in events if e.is_ground_truth or e.event_type == "REDTEAM"]
        other_events = [e for e in events if not e.is_ground_truth and e.event_type != "REDTEAM"]

        for rt in redteam_events:
            # Correlate with observed auth/proc/flows around the redteam timestamp
            nearby = [
                ev for ev in other_events
                if abs(ev.timestamp - rt.timestamp) <= self.time_window_seconds
                and (
                    (rt.user and ev.user == rt.user) or
                    (rt.src_host and ev.src_host == rt.src_host) or
                    (rt.dst_host and ev.dst_host == rt.dst_host)
                )
            ]

            ev_list = [rt] + nearby
            findings.append(CorrelatedFinding(
                finding_id=f"FIND-GROUNDTRUTH-{rt.event_id}",
                title=f"LANL Ground Truth Red Team Activity Matched (Host: {rt.dst_host})",
                severity="CRITICAL",
                category="GROUND_TRUTH",
                confidence_level="CONFIRMED_GROUND_TRUTH",
                reason=(
                    f"Official LANL red-team log confirms attack simulation at relative time t={rt.timestamp} "
                    f"involving User: '{rt.user}', Source: '{rt.src_host}', Destination: '{rt.dst_host}'. "
                    f"Found {len(nearby)} corresponding system event(s) in observed logs within {self.time_window_seconds}s."
                ),
                involved_events=[e.event_id for e in ev_list],
                involved_users=list({e.user for e in ev_list if e.user}),
                involved_hosts=list({e.src_host for e in ev_list if e.src_host} | {e.dst_host for e in ev_list if e.dst_host}),
                evidence_sources=[{"file": e.source_file, "line": e.line_number} for e in ev_list],
                start_time=min(e.timestamp for e in ev_list),
                end_time=max(e.timestamp for e in ev_list),
                recommendation="Compare defense detection rules against this confirmed baseline to calibrate sensitivity and false-negative rates.",
            ))
        return findings
