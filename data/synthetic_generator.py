"""
Synthetic Dataset Generator for TraceMind AI
Generates realistic, schema-compliant synthetic logs mirroring the LANL dataset format.
Includes attack scenarios, normal activity, and edge-case anomalies for testing.
"""

import os
import gzip
import random
from pathlib import Path
from typing import Dict, List, Tuple


def generate_synthetic_dataset(output_dir: str, include_edge_cases: bool = True) -> Dict[str, str]:
    """
    Generates synthetic LANL-format log files:
    - auth.txt.gz
    - proc.txt.gz
    - flows.txt.gz
    - dns.txt.gz
    - redteam.txt.gz
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    auth_lines = []
    proc_lines = []
    flows_lines = []
    dns_lines = []
    redteam_lines = []

    # Scenario 1: Normal baseline activity (Time 100 to 500)
    normal_users = ["U100@DOM1", "U101@DOM1", "U102@DOM1", "U103@DOM1"]
    normal_comps = ["C101", "C102", "C103", "C200"]
    normal_procs = ["explorer.exe", "svchost.exe", "browser.exe", "word.exe"]

    t = 100
    for _ in range(25):
        u = random.choice(normal_users)
        c_src = random.choice(normal_comps)
        c_dst = random.choice(normal_comps)
        # auth: time, src_user, dst_user, src_host, dst_host, auth_type, logon_type, auth_orientation, status
        auth_lines.append(f"{t},{u},{u},{c_src},{c_dst},Kerberos,Network,LogOn,Success")
        # proc: time, user, comp, process_name, action
        proc_lines.append(f"{t+2},{u},{c_dst},{random.choice(normal_procs)},Start")
        # flows: time, duration, src_comp, src_port, dst_comp, dst_port, protocol, packet_count, byte_count
        flows_lines.append(f"{t+3},5,{c_src},49152,{c_dst},445,6,12,1850")
        # dns: time, src_comp, computer_resolved
        dns_lines.append(f"{t+1},{c_src},{c_dst}")
        t += random.randint(10, 25)

    # Scenario 2: Suspicious Brute Force / Password Spraying (Time 600 - 640)
    # User U999@DOM1 fails 6 times against C553, then succeeds on 7th attempt
    attacker_user = "U999@DOM1"
    attacker_src = "C17693"
    target_comp = "C553"

    for i in range(6):
        auth_lines.append(f"{600 + (i * 5)},{attacker_user},{attacker_user},{attacker_src},{target_comp},NTLM,Network,LogOn,Fail")

    # Followed by success at t=635
    auth_lines.append(f"635,{attacker_user},{attacker_user},{attacker_src},{target_comp},NTLM,Network,LogOn,Success")
    # Redteam ground truth marked for this compromise
    redteam_lines.append(f"635,{attacker_user},{attacker_src},{target_comp}")

    # Scenario 3: Execution of unusual process immediately following unauthorized logon (t=642)
    proc_lines.append(f"642,{attacker_user},{target_comp},cmd.exe,Start")
    proc_lines.append(f"645,{attacker_user},{target_comp},powershell_recon.exe,Start")

    # Scenario 4: Suspicious DNS resolution & Network Data Exfiltration Spike (t=660 - 700)
    dns_lines.append(f"658,{target_comp},C9999_EXFIL")
    flows_lines.append(f"660,180,{target_comp},50123,C9999_EXFIL,443,6,15000,98500000")

    # Scenario 5: Lateral Movement attempt to C800 (t=720)
    auth_lines.append(f"720,{attacker_user},{attacker_user},{target_comp},C800,Kerberos,Network,LogOn,Success")
    redteam_lines.append(f"720,{attacker_user},{target_comp},C800")
    proc_lines.append(f"725,{attacker_user},C800,vssadmin.exe,Start")

    if include_edge_cases:
        # Edge cases: missing fields ('?'), out-of-order timestamps, malformed rows
        auth_lines.append("610,?,?,C17693,C553,?,?,?,Fail")  # Missing users
        auth_lines.append("INVALID_ROW,NOT_ENOUGH_COLUMNS")  # Malformed row
        auth_lines.append("550,U100@DOM1,U100@DOM1,C101,C102,Kerberos,Network,LogOn,Success") # Out-of-order time
        proc_lines.append("700,?,C553,?,Start")
        flows_lines.append("680,?,C553,?,?,80,6,?,?")

    # Write gzipped files
    files_created = {}

    def write_gz(filepath: Path, lines: List[str]):
        with gzip.open(filepath, "wt", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")

    files_map = {
        "auth.txt.gz": auth_lines,
        "proc.txt.gz": proc_lines,
        "flows.txt.gz": flows_lines,
        "dns.txt.gz": dns_lines,
        "redteam.txt.gz": redteam_lines,
    }

    for name, lines in files_map.items():
        fp = out_path / name
        write_gz(fp, lines)
        files_created[name] = str(fp.resolve())

    return files_created


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "synthetic"
    res = generate_synthetic_dataset(str(out))
    print(f"Generated {len(res)} synthetic test files in {out}:")
    for k, v in res.items():
        print(f" - {k}: {v}")
