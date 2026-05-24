# SentinelTrace – Endpoint Telemetry Correlation & Threat Hunting Framework

SentinelTrace is a **baseline-aware endpoint threat hunting framework** designed to help SOC analysts identify **high-confidence malicious activity** from noisy Windows Sysmon telemetry.

Instead of generating large volumes of alerts, SentinelTrace focuses on **behavioral correlation, kill chain progression, and confidence-driven prioritization** to surface the small percentage of events that actually require investigation.

This project is built as a **personal SOC lab and final-year project**, modeled on real SOC investigation workflows rather than academic log analysis.

---

## Why SentinelTrace Exists

Modern Windows endpoints generate **thousands of Sysmon events per day**.  
Most are harmless background activity.

The real SOC challenge is:

- Distinguishing **baseline noise** from genuine attack behavior  
- Understanding **multi-step kill chain activity**, not isolated events  
- Prioritizing investigations when analyst time is limited  
- Reducing **alert fatigue** without missing real threats  

SentinelTrace was designed to address these exact problems.

---

## What SentinelTrace Does

SentinelTrace transforms raw endpoint telemetry into **actionable investigation context** by:

- Ingesting Sysmon XML logs from Windows endpoints  
- Parsing and normalizing event data into structured telemetry  
- Learning **baseline execution patterns** per host and process  
- Detecting **behavioral bursts** that deviate from baseline  
- Mapping activity to **MITRE ATT&CK tactics and kill chain stages**  
- Correlating related events into attack sequences  
- Assigning **confidence scores** to prioritize analyst attention  
- Explaining findings in plain English for rapid triage  

Think of SentinelTrace as a **signal amplifier**, not an alert generator.

---

## Who This Is For

- SOC Analysts (L1 / L2)  
- Threat Hunters  
- Incident Responders  
- Blue Team students and labs  
- Security engineering trainees  

This is **not a SIEM replacement**.  
It is a focused **endpoint threat hunting and analysis framework**.

---

## Core Capabilities

### Baseline-Aware Detection
- Learns normal execution behavior per endpoint  
- Suppresses expected high-volume processes  
- Prevents alerting on known benign patterns  

### Behavioral Burst Detection
- Identifies sudden spikes in execution or network activity  
- Groups related events into behavioral bursts  
- Differentiates sustained activity from short-lived noise  

### Kill Chain & MITRE ATT&CK Mapping
- Maps activity to the following stages:
  - Execution  
  - Persistence  
  - Privilege Escalation  
  - Command & Control  
  - Actions on Objectives  
- Higher kill chain progression increases confidence  

### Correlation-Driven Analysis
- Links execution, network, and persistence activity  
- Treats attacks as **campaigns**, not single alerts  
- Builds investigation context automatically  

### Confidence-Based Prioritization
- Assigns confidence scores (0–100) based on:
  - Kill chain progression  
  - Behavioral deviation from baseline  
  - Correlation strength  

---

## Example: Signal vs Noise

### Noise (Baseline Behavior)

| Process               | Executions | Rate      | Baseline State | Confidence |
|----------------------|------------|-----------|----------------|------------|
| splunk-optimize.exe  | 39,673     | ~110/min  | Stable         | 5          |

**Interpretation:**  
High-volume but expected behavior. No action required.

---

### Signal (Suspicious Behavior)

| Process         | Executions | Rate    | Kill Chain                         | Confidence |
|-----------------|------------|---------|------------------------------------|------------|
| powershell.exe  | 47         | ~8/min  | Execution → C2 → Persistence       | 78         |

**Interpretation:**  
Abnormal frequency with multi-stage kill chain progression. Requires investigation.

---

## Architecture Overview

SentinelTrace follows a layered, analyst-oriented pipeline:

1. **Data Ingestion**
   - Sysmon XML logs collected from Windows endpoints

2. **Event Parsing & Normalization**
   - Namespace-aware XML parsing  
   - Field normalization for consistent analysis  

3. **Baseline Learning**
   - Per-host and per-process behavioral baselines  
   - Noise suppression using low-severity activity  

4. **Behavioral Analysis**
   - Burst detection  
   - Parent-child anomaly detection  
   - Network behavior analysis  

5. **MITRE ATT&CK & Kill Chain Mapping**
   - Technique-to-tactic mapping  
   - Kill chain stage progression  

6. **Correlation Engine**
   - Process lineage correlation  
   - Time-window based grouping  

7. **Confidence Scoring**
   - Risk-based prioritization  
   - Analyst decision support  

8. **SOC Investigation Dashboard**
   - Timeline view  
   - Confidence-ranked detections  

---

## Detection Logic (High Level)

### Event Ingestion
- Namespace-aware Sysmon XML parsing  
- Deterministic event identifiers for correlation  

### Baseline Learning
- Learns normal execution behavior from low-severity activity  
- Prevents learning malicious behavior as baseline  

### Behavioral Detection
- Unusual execution frequency  
- Suspicious parent-child relationships  
- Abnormal outbound network activity  
- Persistence-related registry and file modifications  

### Correlation & Campaign Analysis
- Links events by:
  - Process lineage  
  - Host identity  
  - Time proximity  
- Builds attack narratives rather than isolated alerts  

---

## Supported Data Sources

- Windows Sysmon (XML export)  
- Windows Security events (basic support)  
- Firewall / network telemetry (optional)  
- YARA-based command-line and artifact detection  

---

## Tech Stack

- Python  
- Pandas  
- SQLite  
- Flask  
- Sysmon  
- MITRE ATT&CK  
- YARA (optional)  

---

## Installation & Quick Start

```bash
git clone https://github.com/lokilokith/sentineltrace.git
cd sentineltrace

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt
Run the Dashboard
bash
Copy code
python dashboard/app.py
Open in your browser:

arduino
Copy code
http://localhost:5000
How to Use
Load Sysmon XML logs

Allow baseline to form from normal activity

Review:

Confidence scores

Kill chain stages

Behavioral bursts

Investigate high-confidence detections

Ignore baseline-stable noise

Limitations (Honest)
Not a full SIEM

Near-real-time / batch analysis (not streaming)

Detection quality depends on Sysmon configuration

Behavioral detection does not guarantee malware identification

SentinelTrace assists analysts — it does not replace analyst judgment.

Project Status
Personal SOC lab and final-year project

Designed for learning, experimentation, and portfolio demonstration

Actively evolving

Author
Lokith Duraisamy
B.Tech CSE (Cyber Security) – Parul University, Gujarat
Aspiring SOC Analyst / Blue Team Practitioner

License
MIT License

Final Note
SOC work is fundamentally about signal versus noise.

SentinelTrace is built to help analysts:

Reduce noise

Understand attack behavior

Make better investigation decisions

If it helps you think more like a SOC analyst, it has done its job.
