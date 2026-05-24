# SentinelTrace Platform

SentinelTrace is a cybersecurity-focused investigation platform designed to analyze historical Sysmon telemetry and reconstruct suspicious activity chains through behavioral correlation, threat scoring, and MITRE ATT&CK-aligned analytics.

The platform focuses on:

- Endpoint telemetry analysis
- Attack timeline reconstruction
- Campaign correlation
- LOLBIN detection
- Analyst-oriented investigation workflows
- Baseline-aware threat scoring
- Process lineage reconstruction
- Behavioral threat hunting

Rather than acting as a traditional SIEM ingestion pipeline, SentinelTrace is designed as an offline threat hunting and forensic investigation environment for SOC-oriented workflows.

---

# Why Sysmon?

Sysmon provides high-fidelity Windows telemetry that is valuable for:

- Process creation tracking
- Parent-child process relationships
- Network connection monitoring
- Persistence detection
- PowerShell visibility
- Lateral movement investigation
- Command-line auditing
- Behavioral investigation workflows

SentinelTrace uses Sysmon XML telemetry as the foundation for behavioral analysis, telemetry enrichment, and attack-chain reconstruction.

---

# Core Features

## Sysmon Telemetry Analysis

- Parses Windows Sysmon XML logs
- Extracts process, network, parent-child, and command-line activity
- Normalizes endpoint telemetry for investigation workflows
- Reconstructs process lineage relationships
- Builds contextual event timelines

### Telemetry Coverage

- Process execution events
- Parent-child process relationships
- Command-line extraction
- Network activity visibility
- Suspicious execution tracing
- Endpoint behavioral telemetry

---

## Behavioral Correlation Engine

- Correlates suspicious event sequences
- Detects behavioral attack chains
- Links related telemetry into investigation campaigns
- Groups suspicious telemetry into analyst workflows

### Example Behaviors

- Encoded PowerShell execution
- LOLBIN abuse
- Suspicious parent-child process chains
- Lateral movement indicators
- Persistence behavior
- Remote execution workflows
- Command execution anomalies

---

## MITRE ATT&CK Mapping

- Maps telemetry into ATT&CK tactics and techniques
- Provides contextual ATT&CK enrichment for:

  - PowerShell
  - cmd.exe
  - rundll32
  - schtasks
  - regsvr32
  - Remote execution patterns

---

## Threat Scoring & Escalation

- Baseline-aware scoring
- Contextual execution weighting
- Behavioral escalation logic
- False-positive reduction mechanisms

---

## Threat Hunting Dashboard

Interactive SOC-oriented investigation dashboard featuring:

- Threat posture overview
- Campaign correlation
- Attack timeline reconstruction
- ATT&CK analytics
- Threat investigation workflows
- Hunt console views
- Incident prioritization

---

## LOLBIN & Command Analysis

Detects suspicious usage patterns involving:

- PowerShell
- cmd.exe
- rundll32
- regsvr32
- WMI
- Encoded commands
- Suspicious command-line execution

---

# Detection Methodology

SentinelTrace combines:

- Telemetry normalization
- Behavioral correlation
- Baseline comparison
- ATT&CK enrichment
- Threat scoring

The platform prioritizes behavioral relationships and investigation context over simple single-event signature matching.

---

# Example Detection Scenario

### Observed Process Chain

```text
WINWORD.exe
    ↓
powershell.exe -enc
    ↓
cmd.exe
    ↓
Outbound Network Activity
```

---

# Correlation Outcome

SentinelTrace identifies:

- Encoded execution behavior
- Suspicious scripting activity
- Abnormal process lineage
- ATT&CK tactic overlap
- Escalation-worthy telemetry

---

# ATT&CK Classification

| Tactic | Technique |
|---|---|
| Execution | PowerShell |
| Defense Evasion | Obfuscated Execution |
| Command & Scripting Interpreter | PowerShell |

---

# Threat Score

```text
82 / 100
```

---

# Escalation Result

```text
High Severity Investigation Queue
```

---

# Additional Documentation

For detailed engineering decisions, investigation methodology, architecture reasoning, and behavioral correlation design, see:

- [Engineering Case Study](CASE_STUDY.md)

---

# Architecture

![Architecture](screenshots/architecture.png)

```text
Sysmon XML Logs
        ↓
Event Parser
        ↓
Telemetry Normalization
        ↓
Baseline & Behavioral Analysis
        ↓
Behavioral Correlation Engine
        ↓
MITRE ATT&CK Enrichment
        ↓
Threat Scoring & Escalation
        ↓
SOC Investigation Dashboard
```

---

# Screenshots

## Main Dashboard

![Main Dashboard](screenshots/dashboard.png)

### Highlights

- Threat posture overview
- Incident queue management
- Analyst escalation workflows
- Contextual risk scoring
- Campaign prioritization

---

## MITRE ATT&CK Mapping

![MITRE ATT&CK](screenshots/mitre.png)

### Highlights

- ATT&CK tactic correlation
- Detection distribution
- Investigation enrichment
- Telemetry classification

---

## Threat Investigation

![Threat Investigation](screenshots/investigation.png)

### Highlights

- Attack storyline reconstruction
- Process chain visualization
- Timeline investigation
- Behavioral campaign analysis

---

## Hunt Console

![Hunt Console](screenshots/hunt_console.png)

### Highlights

- Active incident triage
- Escalation queue management
- SOC analyst workflows
- Incident prioritization

---

# Repository Structure

```text
dashboard/              Core platform source code
dashboard/templates/   HTML templates
dashboard/static/      CSS and frontend assets

tools/                 Validation and calibration tooling

docs/sql/              SQL setup scripts and migration files

screenshots/           Dashboard and architecture screenshots

sample_logs/           Example Sysmon telemetry datasets
```

---

# Technology Stack

| Component | Technology |
|---|---|
| Backend | Python |
| Framework | Flask |
| Frontend | HTML / CSS / JavaScript |
| Data Processing | Pandas |
| Telemetry Source | Sysmon |
| Threat Mapping | MITRE ATT&CK |
| Detection Logic | Behavioral Correlation |
| Investigation Workflow | SOC-Oriented Analytics |

---

# Installation

## Clone Repository

```bash
git clone https://github.com/lokilokith/sentineltrace-platform.git
cd sentineltrace-platform
```

---

## Create Virtual Environment

```bash
python -m venv .venv
```

### Windows

```bash
.venv\Scripts\activate
```

### Linux / macOS

```bash
source .venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Running the Platform

```bash
python dashboard/app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

# Example Workflow

1. Upload Sysmon XML logs
2. Parse and normalize telemetry
3. Run behavioral correlation
4. Generate ATT&CK mappings
5. Build campaign relationships
6. Escalate suspicious activity
7. Investigate findings through dashboard workflows

---

# Validation & Calibration

The repository includes:

- Forensic calibration tooling
- Orchestration validation
- Threat scoring calibration
- Behavioral validation workflows
- Detection testing utilities

Located in:

```text
tools/
```

---

# Sample Telemetry

Example datasets can be stored under:

```text
sample_logs/
```

### Recommended Telemetry Examples

- Encoded PowerShell execution
- LOLBIN abuse
- WMI execution
- Persistence activity
- Suspicious command-line execution
- Lateral movement traces

---

# Current Capabilities

- Offline Sysmon analysis
- Threat hunting workflows
- Campaign reconstruction
- MITRE ATT&CK enrichment
- Timeline reconstruction
- Behavioral threat scoring
- LOLBIN analysis
- Investigation-oriented analytics
- Process lineage analysis
- Behavioral telemetry correlation

---

# Known Limitations

- Offline analysis only
- Not designed for realtime telemetry ingestion
- Requires Sysmon-generated XML telemetry
- Educational and research-focused platform
- Not intended as an enterprise-scale SIEM replacement

---

# Future Improvements

Potential future enhancements:

- Sigma rule integration
- Multi-host telemetry correlation
- Enhanced DFIR workflows
- Expanded ATT&CK enrichment
- Threat intelligence integration
- Graph-based timeline visualization
- IOC tagging workflows
- Detection tuning profiles

---

# Educational Focus

SentinelTrace was developed as a cybersecurity engineering and threat hunting platform focused on:

- Detection engineering
- Endpoint telemetry analysis
- Behavioral analytics
- MITRE ATT&CK mapping
- Threat investigation workflows
- Process lineage analysis
- DFIR investigation concepts
- SOC-oriented analytics

---

# License

This project is released for educational and portfolio purposes.

---

# Author

Developed by Lokith as a SOC-focused cybersecurity engineering and threat hunting platform project.
