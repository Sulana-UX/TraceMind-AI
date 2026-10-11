# LANL Cybersecurity Dataset Guide

## 1. About the LANL Dataset
The **Comprehensive, Multi-Source Cyber-Security Events** dataset is released by Los Alamos National Laboratory (LANL).
Official repository URL:
[https://csr.lanl.gov/data/cyber1/](https://csr.lanl.gov/data/cyber1/)

### Dataset Characteristics
- Total compressed size: ~12 GB (Uncompressed: > 100 GB).
- Contains 58 consecutive days of enterprise activity across ~12,000 computers.
- All entities and timestamps are de-identified to protect privacy.
- Missing values are explicitly represented as `?`.
- Files have **NO header row** and are comma-separated.

## 2. File Schemas

### A. Authentication (`auth.txt.gz`)
Columns:
1. `time`: Relative integer seconds from day 1.
2. `source_user@domain`: User initiating authentication (e.g. `U620@DOM1`).
3. `dest_user@domain`: User being authenticated on destination.
4. `source_computer`: Source computer ID (e.g. `C17693`).
5. `dest_computer`: Destination computer ID (e.g. `C1003`).
6. `auth_type`: Kerberos, NTLM, Negotiate, etc.
7. `logon_type`: Network, Interactive, Unlock, etc.
8. `auth_orientation`: LogOn, LogOff, AuthMap, etc.
9. `status`: `Success` or `Fail`.

### B. Process (`proc.txt.gz`)
Columns:
1. `time`: Relative integer seconds.
2. `user@domain`: User associated with process.
3. `computer`: Host executing the process.
4. `process_name`: Name of process (e.g. `P1`, `cmd.exe`).
5. `action`: `Start` or `End`.

### C. Network Flows (`flows.txt.gz`)
Columns:
1. `time`: Relative integer seconds.
2. `duration`: Integer duration in seconds.
3. `source_computer`: Source host ID.
4. `source_port`: Port number or `?`.
5. `dest_computer`: Destination host ID.
6. `dest_port`: Destination port number or `?`.
7. `protocol`: Protocol number or string.
8. `packet_count`: Total packets.
9. `byte_count`: Total bytes transferred.

### D. DNS Resolutions (`dns.txt.gz`)
Columns:
1. `time`: Relative integer seconds.
2. `source_computer`: Host querying DNS.
3. `computer_resolved`: Host/alias resolved.

### E. Red Team Ground Truth (`redteam.txt.gz`)
Columns:
1. `time`: Relative integer seconds.
2. `user@domain`: Attacking user account.
3. `source_computer`: Machine where attack originated.
4. `dest_computer`: Target machine compromised or probed.

> [!NOTE]
> The red-team events represent known ground-truth events documented during LANL internal penetration testing. However, they are **not exhaustive labels** of all anomalous or malicious behavior in the network.

## 3. How to Obtain the Dataset Safely
1. Visit [https://csr.lanl.gov/data/cyber1/](https://csr.lanl.gov/data/cyber1/).
2. Agree to the user terms and download specific individual `.gz` files (e.g., `redteam.txt.gz`).
3. **DO NOT download all 12 GB at once** if you have limited bandwidth or disk space.
4. Place the downloaded `.txt.gz` file directly into your working directory or TraceMind AI data directory.
5. In TraceMind AI, specify the path to process only the required number of records (e.g. 5,000 to 20,000 rows).
