# SentinelTrace Platform — Engineering Case Study

# Overview

SentinelTrace is a SOC-focused telemetry analysis and threat hunting platform designed to investigate Windows Sysmon telemetry through behavioral correlation, ATT&CK enrichment, threat scoring, and analyst-oriented workflows.

The platform was developed as a cybersecurity engineering project focused on understanding how modern SOC workflows reconstruct suspicious activity from endpoint telemetry.

Rather than building a traditional SIEM clone, the goal was to create a practical investigation-oriented platform capable of:

- Parsing Sysmon telemetry
- Reconstructing attack chains
- Correlating suspicious behaviors
- Enriching telemetry with MITRE ATT&CK
- Prioritizing escalation-worthy activity
- Supporting threat hunting workflows

---

# Problem Statement

Most beginner cybersecurity projects focus on:

- Port scanners
- Vulnerability dashboards
- Signature-only detections
- Simple malware classification
- Log viewers

These projects often fail to demonstrate how real SOC workflows operate.

Real-world analysts typically investigate:

- Process lineage
- Parent-child execution chains
- Encoded PowerShell activity
- LOLBIN abuse
- Persistence mechanisms
- Lateral movement indicators
- Behavioral relationships between events

The objective of SentinelTrace was to simulate this investigation workflow through behavioral telemetry analysis.

---

# Why Sysmon?

Sysmon provides detailed Windows endpoint telemetry that is highly valuable for:

- Process creation tracking
- Command-line visibility
- Parent-child relationships
- Network connection monitoring
- Persistence analysis
- PowerShell visibility
- Execution tracing

Compared to traditional Windows Event Logs, Sysmon offers significantly richer telemetry for behavioral investigations.

SentinelTrace uses Sysmon XML logs as the primary telemetry source for reconstruction and analysis.

---

# Design Goals

The platform was designed around several key objectives:

## 1. Behavioral Analysis Over Signature Matching

Instead of relying only on static signatures, SentinelTrace focuses on:

- Event relationships
- Sequence correlation
- Process lineage
- Execution context
- Behavioral escalation logic

The goal was to identify suspicious workflows rather than isolated events.

---

## 2. Analyst-Oriented Investigation

The platform was intentionally designed around SOC workflows:

- Threat triage
- Escalation reasoning
- ATT&CK mapping
- Timeline reconstruction
- Investigation queue analysis

This influenced both backend logic and UI design decisions.

---

## 3. Explainable Threat Escalation

Many security tools generate opaque severity scores.

SentinelTrace instead attempts to expose:

- Why telemetry was escalated
- Which behaviors contributed to scoring
- Which ATT&CK tactics were involved
- How events were correlated

This improves investigation clarity.

---

# Core Architecture

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

# Major Components

## Event Parser

The parser extracts:

- Process execution
- Parent-child relationships
- Command-line activity
- Network telemetry
- Sysmon metadata

The parser normalizes telemetry into structures usable by downstream analysis components.

---

## Behavioral Correlation Engine

The correlation engine groups suspicious telemetry into investigation campaigns based on:

- Shared processes
- Temporal proximity
- ATT&CK overlap
- Execution relationships
- Behavioral patterns

Example correlations include:

- Encoded PowerShell spawning cmd.exe
- LOLBIN execution chains
- Suspicious process ancestry
- Multi-stage execution behavior

---

## Threat Scoring Engine

Threat scoring combines:

- Execution context
- Behavioral indicators
- ATT&CK overlap
- Command-line risk
- Parent-child anomalies
- Escalation heuristics

The platform intentionally avoids simplistic single-rule severity scoring.

---

## MITRE ATT&CK Enrichment

Telemetry is mapped into ATT&CK-aligned tactics and techniques to provide:

- Investigation context
- Threat classification
- Analyst visibility
- Campaign understanding

This helps convert raw telemetry into structured investigative intelligence.

---

# Example Investigation Workflow

## Observed Process Chain

```text
WINWORD.exe
    ↓
powershell.exe -enc
    ↓
cmd.exe
    ↓
Outbound Network Activity
```

## Correlation Outcome

The platform identifies:

- Encoded execution behavior
- Suspicious scripting activity
- Abnormal process lineage
- ATT&CK tactic overlap
- Escalation-worthy telemetry

## ATT&CK Classification

| Tactic | Technique |
|---|---|
| Execution | PowerShell |
| Defense Evasion | Obfuscated Execution |
| Command & Scripting Interpreter | PowerShell |

## Threat Score

```text
82 / 100
```

## Escalation Result

```text
High Severity Investigation Queue
```

---

# Engineering Challenges

## 1. Event Correlation Complexity

One of the biggest challenges was reducing noisy correlations while still preserving investigation visibility.

Naive correlation logic quickly produced:

- Duplicate campaigns
- False-positive escalation
- Over-grouped telemetry
- Unusable investigation timelines

Several iterations were required to improve campaign grouping quality.

---

## 2. Behavioral Inflation

Execution telemetry can dominate investigation pipelines due to the high volume of:

- cmd.exe
- powershell.exe
- rundll32.exe
- LOLBIN activity

Scoring logic required calibration to reduce excessive execution inflation while preserving meaningful escalation.

---

## 3. Threat Escalation Stability

Threat scoring initially produced unstable prioritization behavior.

Additional calibration logic was introduced to improve:

- Severity consistency
- Escalation clarity
- Behavioral weighting
- Correlation quality

---

## 4. UI Investigation Flow

The dashboard originally behaved more like a telemetry viewer than an investigation platform.

The UI was redesigned to focus on:

- Analyst workflows
- Campaign reconstruction
- Timeline visibility
- Escalation reasoning
- ATT&CK analytics

---

# Validation & Testing

The project includes validation tooling for:

- Threat scoring calibration
- Behavioral validation
- Pipeline orchestration
- Correlation testing
- Investigation workflow validation

The objective was to ensure the platform remained stable under larger telemetry datasets.

---

# Key Lessons Learned

The project reinforced several important cybersecurity engineering concepts:

- Raw telemetry alone is insufficient
- Context matters more than isolated events
- Investigation workflows require correlation logic
- Threat scoring requires continuous calibration
- ATT&CK mapping improves analyst visibility
- UI clarity is critical for SOC usability

---

# Current Capabilities

SentinelTrace currently supports:

- Offline Sysmon analysis
- Threat hunting workflows
- ATT&CK enrichment
- Behavioral threat scoring
- Process lineage reconstruction
- Campaign correlation
- Timeline investigation
- LOLBIN analysis
- Escalation workflows

---

# Known Limitations

Current limitations include:

- Offline analysis only
- No realtime telemetry ingestion
- No distributed telemetry collection
- Requires Sysmon-generated XML logs
- Educational/research-focused architecture
- Not intended as an enterprise-scale SIEM replacement

---

# Future Improvements

Potential future enhancements include:

- Sigma rule integration
- Multi-host telemetry correlation
- Enhanced DFIR workflows
- IOC tagging
- Threat intelligence integration
- Graph-based investigation visualization
- Detection tuning profiles

---

# Conclusion

SentinelTrace was developed to better understand how SOC analysts investigate endpoint telemetry through behavioral reconstruction and ATT&CK-aligned workflows.

The project focuses less on isolated detection signatures and more on:

- Investigation context
- Behavioral relationships
- Threat escalation
- Analyst workflows
- Telemetry reconstruction

The overall objective was to bridge the gap between raw Sysmon telemetry and practical investigation-oriented threat hunting workflows.
