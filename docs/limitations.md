# Forensic Assumptions & Scientific Limitations

## 1. Digital Forensics Scope
TraceMind AI is an **investigative decision-support system**. It is designed to empower human analysts, not replace formal evidentiary chain-of-custody protocols or certified forensic examiners.

## 2. Key Limitations
1. **Anomaly vs. Compromise**:
   - An anomaly score (e.g. from Isolation Forest) measures statistical deviation from the baseline; **it is not proof of compromise or malice**.
   - Many operational events (system updates, backup syncs, user password resets) naturally create statistical anomalies.
2. **De-Identified LANL Attributes**:
   - Computers are represented as synthetic IDs (`C17693`), not routable IP addresses.
   - TraceMind AI does not invent IP addresses or geolocation when working with LANL data.
3. **Absence of Payload Inspection**:
   - Network flow logs capture packet and byte totals, but not encrypted TLS traffic payloads or deep packet inspection (DPI) streams.
4. **Sampling & Row Limits**:
   - Because the system operates incrementally on limited RAM, applying row caps (e.g., 5,000 rows) may truncate earlier reconnaissance or later lateral movement phases outside the sample window. TraceMind AI clearly marks when row or time limits are active.
5. **Formula Injection Safety**:
   - Exported CSVs escape formula tokens (`=`, `+`, `-`, `@`) to protect forensic analysts opening evidence sheets in spreadsheet software.
