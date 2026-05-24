"""
detection_engine.py — SentinelTrace v2 Unified Detection Engine
================================================================
Wires together:
  1. YAML rule matching (from rules.yaml)
  2. Statistical baseline deviation (BaselineEngine)
  3. Graph-based correlation (CorrelationEngine)
  4. Unified risk scoring with explainability (ScoringEngine)

Replaces the old heuristic-only detection_engine.py.
Drop-in compatible with existing analysis_engine.py call sites.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# ---------------------------------------------------------------------------
# Lazy imports (avoid circular at module load time)
# ---------------------------------------------------------------------------

def _get_baseline_engine():
    from dashboard.baseline_engine import get_baseline_engine
    return get_baseline_engine()


def _get_scoring_engine():
    from dashboard.scoring_engine import get_scoring_engine
    return get_scoring_engine()


def _get_correlate_bursts():
    from dashboard.correlation_engine import correlate_bursts
    return correlate_bursts


def _get_sequence_engine():
    from dashboard.sequence_engine import get_sequence_engine
    return get_sequence_engine()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BENIGN_PARENTS = frozenset({
    "services.exe", "wininit.exe", "winlogon.exe", "lsass.exe",
    "csrss.exe", "svchost.exe", "spoolsv.exe", "explorer.exe",
    "taskhost.exe", "taskhostw.exe", "smss.exe",
})

KILL_CHAIN_ORDER = [
    "Background", "Delivery", "Execution", "Defense Evasion",
    "Persistence", "Privilege Escalation", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Actions on Objectives",
]


SOURCE_WEIGHT = {
    "sequence": 1.0,
    "rule":     0.9,
    "fallback": 0.4,
}

SEVERITY_BASE = {
    "critical": 1.0,
    "high":     0.8,
    "medium":   0.5,
    "low":      0.3,
    "info":     0.1,
}

REASON_MAP = {
    "event_id":     lambda v: f"EventID {v} matched rule criteria",
    "image":        lambda v: f"Image path '{v}' matched suspicious pattern",
    "parent":       lambda v: f"Suspicious parent process: {v}",
    "cmd":          lambda v: f"Command line contains: {v}",
    "path":         lambda v: f"Path starts with suspicious prefix: {v}",
    "reg":          lambda v: f"Registry path matched: {v}",
    "high_entropy": lambda _: "High-entropy command line detected (+15 confidence)",
    "b64":          lambda _: "Base64-encoded command detected (+10 confidence)",
}


def compute_signal_strength(d: Dict[str, Any]) -> float:
    """
    Authoritative signal strength calculation for primary detection selection.
    Weighting (Audit v2 Final): 0.6*Conf + 0.2*Source + 0.2*Severity.
    Normalized confidence (0-1.0) ensures balance.
    """
    conf = float(d.get("confidence_score", 50)) / 100.0
    src  = SOURCE_WEIGHT.get(d.get("detection_source", ""), 0.5)
    sev  = SEVERITY_BASE.get(d.get("severity", ""), 0.5)
    return (0.6 * conf) + (0.2 * src) + (0.2 * sev)


def normalize_explanation(det: Dict[str, Any]) -> List[str]:
    """
    9.7/10 Mastery: Guarantees a consistent List[str] for explainability.
    Rules out None/str/mix inconsistencies for the UI.
    """
    reason = det.get("match_reason") or det.get("explanation")

    if not reason:
        return ["No explanation available"]

    if isinstance(reason, str):
        return [reason]

    if isinstance(reason, list):
        # Ensure all elements are strings
        return [str(r) for r in reason if r]

    return [str(reason)]


def refine_attack_stage(event: Dict[str, Any], rule: Dict[str, Any]) -> str:
    """Prefer a more specific ATT&CK stage when the raw rule stage is generic."""
    stage = str(rule.get("kill_chain_stage") or rule.get("mitre_tactic") or "Execution").strip() or "Execution"
    image = str(event.get("image") or "").lower()
    parent = str(event.get("parent_image") or "").lower()
    command = str(event.get("command_line") or "").lower()
    reg_key = str(event.get("reg_key") or event.get("target_object") or event.get("file_path") or "").lower()
    rule_name = str(rule.get("name") or rule.get("rule_name") or "").lower()
    image_base = image.split("\\")[-1] if "\\" in image else image
    parent_base = parent.split("\\")[-1] if "\\" in parent else parent
    benign_admin_tools = BENIGN_PARENTS | frozenset({"splunkd.exe", "splunk.exe", "osqueryd.exe", "senseir.exe", "csfalconservice.exe", "crowdstrike.exe", "carbonblack.exe", "cb.exe", "qualysagent.exe", "rapid7agent.exe"})

    if any(token in command for token in ("-enc", "-encodedcommand", "frombase64string", "[convert]::frombase64", "invoke-expression", "iex ", "-nop")) and image_base in {"powershell.exe", "pwsh.exe"}:
        return "Execution"

    if any(token in reg_key for token in ("\\run\\", "\\runonce\\", "currentversion\\run", "appinit_dlls", "image file execution options")):
        return "Persistence"
    if any(token in rule_name for token in ("persistence", "startup", "run key", "service")):
        return "Persistence"
    if any(token in command for token in ("-enc", "frombase64string", "invoke-expression", "iex ", "-nop")):
        return "Defense Evasion"
    if any(token in command for token in ("psexec", "wmic", "winrm", "sc.exe create", "schtasks")) or image in {"psexec.exe", "wmic.exe"}:
        if "schtasks" in command or image == "schtasks.exe":
            return "Persistence"
        return "Lateral Movement"
    if event.get("destination_ip") or event.get("dst_ip") or event.get("has_net"):
        return "Command and Control"
    if parent and parent_base not in benign_admin_tools and stage == "Execution" and ("powershell" in image or "cmd.exe" in image):
        return "Execution"
    # Reduce over-attribution to Execution for generic process creations.
    # If the source image is a common system/process and there is no command
    # context, no encoding/entropy indicators, and parent is benign, treat as Background.
    common_exec_images = {"explorer.exe", "svchost.exe", "services.exe", "spoolsv.exe", "taskhost.exe", "cmd.exe", "powershell.exe", "pwsh.exe"}
    if stage == "Execution":
        suspicious_cmd_tokens = ("-enc", "frombase64string", "invoke-expression", "iex ", "-nop")
        has_suspicious_cmd = any(tok in command for tok in suspicious_cmd_tokens)
        has_reg_persistence = any(token in reg_key for token in ("\\run\\", "\\runonce\\", "currentversion\\run", "appinit_dlls"))
        if (image_base in common_exec_images and not has_suspicious_cmd and not has_reg_persistence and (not parent or parent_base in benign_admin_tools)):
            return "Background"
    return stage


def _refine_attack_metadata(event: Dict[str, Any], rule: Dict[str, Any], refined_stage: str) -> Dict[str, Any]:
    image = str(event.get("image") or "").lower()
    parent = str(event.get("parent_image") or "").lower()
    command = str(event.get("command_line") or "").lower()
    reg_key = str(event.get("reg_key") or event.get("target_object") or event.get("file_path") or "").lower()
    image_base = image.split("\\")[-1] if "\\" in image else image
    parent_base = parent.split("\\")[-1] if "\\" in parent else parent
    rule_mitre_id = rule.get("mitre_id")
    rule_tactic = rule.get("mitre_tactic")

    has_encoded = event.get("cmd_has_encoded_flag") or event.get("has_encoded_flag") or any(token in command for token in ("-enc", "-encodedcommand", "frombase64string", "[convert]::frombase64", "invoke-expression", "iex ", "-nop"))
    has_persistence = any(token in reg_key for token in ("\\run\\", "\\runonce\\", "currentversion\\run", "appinit_dlls", "image file execution options")) or any(token in command for token in ("schtasks", "runonce", "currentversion\\run", "startup"))
    has_remote_exec = any(token in command for token in ("psexec", "wmic", "winrm", "sc.exe create", "service create"))
    suspicious_parent = parent_base and parent_base not in BENIGN_PARENTS

    if image_base in {"powershell.exe", "pwsh.exe"} and has_encoded:
        return {"mitre_id": "T1059.001", "mitre_tactic": rule_tactic or "Execution", "kill_chain_stage": "Execution"}
    if image_base == "cmd.exe" and has_persistence:
        return {"mitre_id": "T1053.005", "mitre_tactic": "Persistence", "kill_chain_stage": "Persistence"}
    if image_base == "cmd.exe" and has_remote_exec:
        return {"mitre_id": "T1021.002", "mitre_tactic": "Lateral Movement", "kill_chain_stage": "Lateral Movement"}
    if image_base == "schtasks.exe" or "schtasks" in command:
        return {"mitre_id": "T1053.005", "mitre_tactic": "Persistence", "kill_chain_stage": "Persistence"}
    if image_base == "regsvr32.exe":
        return {"mitre_id": "T1218.010", "mitre_tactic": "Defense Evasion", "kill_chain_stage": "Defense Evasion"}
    if image_base == "rundll32.exe":
        return {"mitre_id": "T1218.011", "mitre_tactic": "Defense Evasion", "kill_chain_stage": "Defense Evasion"}
    if image_base == "mshta.exe":
        return {"mitre_id": "T1218.005", "mitre_tactic": "Defense Evasion", "kill_chain_stage": "Execution"}
    if image_base in {"wmic.exe", "wmiprvse.exe"} or has_remote_exec:
        tactic = "Lateral Movement" if suspicious_parent or has_remote_exec else "Discovery"
        return {"mitre_id": "T1047", "mitre_tactic": tactic, "kill_chain_stage": tactic}
    # Parent-aware lateral fallback: favor explicit lateral movement when parent is suspicious
    if parent_base and parent_base not in BENIGN_PARENTS and any(token in command for token in ("psexec", "wmic", "winrm", "sc.exe create", "service create", "wmiprvse")):
        return {"mitre_id": "T1021.002", "mitre_tactic": "Lateral Movement", "kill_chain_stage": "Lateral Movement"}
    if refined_stage == "Background" and image_base in {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"} and not has_encoded and not has_persistence and not has_remote_exec and not suspicious_parent:
        return {"mitre_id": rule_mitre_id, "mitre_tactic": rule_tactic, "kill_chain_stage": "Background"}
    # Download/staging heuristic: map common download utilities to T1105 to reduce unmapped labels
    if any(token in command for token in ("certutil", "bitsadmin", "invoke-webrequest", "curl ", "wget ")) or event.get("has_download_url"):
        return {"mitre_id": "T1105", "mitre_tactic": "Command and Control", "kill_chain_stage": "Command and Control"}
    if rule_mitre_id or rule_tactic:
        return {"mitre_id": rule_mitre_id, "mitre_tactic": rule_tactic, "kill_chain_stage": refined_stage}
    return {"mitre_id": None, "mitre_tactic": None, "kill_chain_stage": refined_stage}


def pick_primary_detection(detections: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Select the authoritative primary detection using weighted signal strength.
    Tie-breaks: Strength > Severity > Source Weight > Raw Confidence.
    """
    if not detections:
        return None

    def tie_break_key(d):
        return (
            compute_signal_strength(d),
            SEVERITY_BASE.get(d.get("severity", ""), 0.5),
            SOURCE_WEIGHT.get(d.get("detection_source", ""), 0.5),
            int(d.get("confidence_score", 0)),
        )

    return max(detections, key=tie_break_key)


# ---------------------------------------------------------------------------
# YAML Rule Loading
# ---------------------------------------------------------------------------

_RULES_CACHE: Optional[List[Dict]] = None


def load_yaml_rules(rules_path: Optional[Path] = None) -> List[Dict]:
    """Load detection rules from rules.yaml with auto-discovery."""
    global _RULES_CACHE
    if _RULES_CACHE is not None and rules_path is None:
        return _RULES_CACHE

    search_paths = []
    if rules_path:
        search_paths.append(Path(rules_path))

    base = Path(__file__).resolve().parent
    search_paths += [
        base.parent / "rules.yaml",
        base / "rules.yaml",
        Path("rules.yaml"),
    ]

    for p in search_paths:
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                rules = data.get("rules", []) if data else []
                _RULES_CACHE = rules
                print(f"[DetectionEngine] Loaded {len(rules)} rules from {p}")
                return rules
            except Exception as e:
                print(f"[DetectionEngine] Failed to load {p}: {e}")

    print("[DetectionEngine] No rules.yaml found — using heuristic fallback")
    _RULES_CACHE = []
    return []


def invalidate_rules_cache() -> None:
    global _RULES_CACHE
    _RULES_CACHE = None


# ---------------------------------------------------------------------------
# Single-event YAML rule matching
# ---------------------------------------------------------------------------

def _safe_lower(v: Any) -> str:
    s = str(v) if v is not None else ""
    return s.lower() if s not in ("None", "nan", "") else ""


def match_rules(event: Dict[str, Any], rules: Optional[List[Dict]] = None) -> List[Dict[str, Any]]:
    """
    Test a single event dict against all loaded YAML rules.
    Returns a list of hit dicts (one per matched rule).

    Supports rule fields:
      event_id, image_contains, image_any, parent_any,
      cmd_any, path_prefix_any, severity_required, filter_benign_parent
    """
    if rules is None:
        rules = load_yaml_rules()
    hits = []
    # Force int conversion for robust matching
    try:
        eid_raw = event.get("event_id")
        if isinstance(eid_raw, list):
            eid_raw = eid_raw[0] if eid_raw else None
        eid = int(float(str(eid_raw).strip()))
    except (TypeError, ValueError):
        eid = 0

    image   = _safe_lower(event.get("image"))
    cmd     = _safe_lower(event.get("command_line") or event.get("commandline"))
    parent  = _safe_lower(event.get("parent_image"))
    fpath   = _safe_lower(
        event.get("file_path") or event.get("target_filename")
        or event.get("reg_key") or ""
    )

    # Normalize Sysmon registry paths (\REGISTRY\MACHINE\ -> hklm\)
    if fpath.startswith("\\registry\\machine\\"):
        fpath = "hklm\\" + fpath[len("\\registry\\machine\\"):]
    elif fpath.startswith("\\registry\\user\\"):
        fpath = "hkcu\\" + fpath[len("\\registry\\user\\"):]
    
    sev     = _safe_lower(event.get("severity"))

    for rule in rules:
        # EventID filter
        rule_eids = rule.get("event_id", [])
        if rule_eids and eid not in rule_eids:
            continue

        # image_contains
        ic = rule.get("image_contains")
        if ic and ic.lower() not in image:
            continue

        # image_any (basename match)
        ia = rule.get("image_any", [])
        if ia and not any(x.lower() in image for x in ia):
            continue

        # parent_any
        pa = rule.get("parent_any", [])
        if pa and not any(x.lower() in parent for x in pa):
            continue

        # cmd_any
        ca = rule.get("cmd_any", [])
        if ca and not any(s.lower() in cmd for s in ca):
            continue

        # path_prefix_any
        pp = rule.get("path_prefix_any", [])
        if pp and not any(fpath.startswith(x.lower()) for x in pp):
            continue

        # severity_required
        sr = rule.get("severity_required")
        if sr and sev != sr.lower():
            continue

        # filter_benign_parent
        if rule.get("filter_benign_parent"):
            parent_name = parent.split("\\")[-1] if "\\" in parent else parent
            if parent_name in BENIGN_PARENTS:
                continue

        # Compute per-hit confidence boost from entropy / encoding signals
        conf = int(rule.get("confidence", 50))
        if event.get("cmd_high_entropy"):
            conf = min(conf + 15, 100)
        if event.get("cmd_b64_detected") or event.get("cmd_has_encoded_flag"):
            conf = min(conf + 10, 100)

        # --- Build explainability reason list ---
        reason: List[str] = []
        mf: Dict[str, Any] = {"event_id": eid}

        if rule_eids:
            reason.append(REASON_MAP["event_id"](eid))
        if ic:
            reason.append(REASON_MAP["image"](ic))
            mf["image_contains"] = ic
        if ia:
            matched_ia = [x for x in ia if x.lower() in image]
            reason.append(REASON_MAP["image"](", ".join(matched_ia)))
            mf["image_any"] = matched_ia
        if pa:
            matched_pa = [x for x in pa if x.lower() in parent]
            reason.append(REASON_MAP["parent"](", ".join(matched_pa)))
            mf["parent_any"] = matched_pa
        if ca:
            matched_ca = [s for s in ca if s.lower() in cmd]
            reason.append(REASON_MAP["cmd"](", ".join(matched_ca)))
            mf["cmd_any"] = matched_ca
        if pp:
            matched_pp = [x for x in pp if fpath.startswith(x.lower())]
            reason.append(REASON_MAP["path"](", ".join(matched_pp)))
            mf["path_prefix_any"] = matched_pp
        if event.get("cmd_b64_detected"):
            reason.append(REASON_MAP["b64"](None))
        if event.get("cmd_high_entropy"):
            reason.append(REASON_MAP["high_entropy"](None))

        refined_stage = refine_attack_stage(event, rule)
        refined_context = _refine_attack_metadata(event, rule, refined_stage)

        hit = {
            "rule_id":          rule.get("rule_id"),
            "rule_name":        rule.get("name"),
            "mitre_id":         refined_context.get("mitre_id"),
            "mitre_tactic":     refined_context.get("mitre_tactic"),
            "kill_chain_stage": refined_context.get("kill_chain_stage") or refined_stage,
            "severity":         rule.get("severity", "medium"),
            "confidence_score": conf,
            "description":      rule.get("description", ""),
            # ── Explainability ──────────────────────────────────────────
            "detection_source": "rule",
            "match_reason":     reason,
            "matched_fields": {
                **mf,
                "image":        event.get("image"),
                "parent_image": event.get("parent_image"),
                "command_line": event.get("command_line"),
                "reg_key":      event.get("reg_key") or event.get("targetobject"),
                "file_path":    event.get("file_path") or event.get("target_filename"),
            },
            # ── Event context ───────────────────────────────────────────
            "utc_time":         event.get("utc_time") or event.get("event_time"),
            "event_time":       event.get("event_time") or event.get("utc_time"),
            "image":            event.get("image"),
            "event_id":         eid,
            "computer":         event.get("computer"),
            "process_id":       event.get("pid") or event.get("process_id"),
            "parent_process_id":event.get("ppid") or event.get("parent_process_id"),
            "parent_image":     event.get("parent_image"),
            "source_ip":        event.get("src_ip") or event.get("source_ip"),
            "source_port":      event.get("source_port"),
            "destination_ip":   event.get("dst_ip") or event.get("destination_ip"),
            "destination_port": event.get("dst_port") or event.get("destination_port"),
            "target_filename":  event.get("file_path") or event.get("target_filename"),
            "command_line":     event.get("command_line"),
        }
        # Final Mastery Normalization
        hit["explanation"] = normalize_explanation(hit)
        hits.append(hit)

    if not hits:
        import logging as _log
        _det_log = _log.getLogger("detection_engine")

        # Known-benign reg key fragments — suppress fallback for these
        _BENIGN_NOISE = frozenset([
            "\\clsid\\", "\\typelib\\", "\\interface\\", "\\wow6432node\\clsid",
            "\\installedsdb\\", "\\mui\\", "\\capabilities\\",
        ])

        # Persistence fallback table: (keywords, rule_id, rule_name, mitre_id, confidence, severity)
        _PERSIST_RULES: List = [
            (["\\run\\", "\\runonce\\", "currentversion\\run", "policies\\explorer\\run"],
             "FB-RUN", "Registry Run key persistence (fallback)", "T1547.001", 75, "high"),
            (["image file execution options"],
             "FB-IFEO", "IFEO Debugger persistence (fallback)", "T1546.012", 80, "high"),
            (["appinit_dlls"],
             "FB-APPINIT", "AppInit_DLLs persistence (fallback)", "T1546.010", 80, "high"),
            (["\\services\\"],
             "FB-SVC", "Suspicious service registry key (fallback)", "T1543.003", 65, "medium"),
            (["\\microsoft\\windows\\currentversion\\run", "\\software\\microsoft\\windows nt\\currentversion\\winlogon"],
             "FB-WINLOGON", "Winlogon persistence (fallback)", "T1547.004", 75, "high"),
            (["\\microsoft\\windows\\currentversion\\explorer\\shell folders",
              "\\microsoft\\windows\\currentversion\\explorer\\user shell folders"],
             "FB-SHELLFOLDER", "Shell folder hijack (fallback)", "T1547.001", 70, "medium"),
            (["\\environment", "\\userinitmprlogonscript"],
             "FB-LOGINSCRIPT", "Logon script persistence (fallback)", "T1037.001", 70, "medium"),
            (["\\currentcontrolset\\control\\session manager"],
             "FB-BOOTEXEC", "Boot execution persistence (fallback)", "T1547.006", 70, "medium"),
        ]

        if eid in (12, 13, 14) and fpath:
            if not any(noise in fpath for noise in _BENIGN_NOISE):
                for kws, rid, rname, mid, conf, sev in _PERSIST_RULES:
                    if any(k in fpath for k in kws):
                        matched_kws = [k for k in kws if k in fpath]
                        hit = {
                            "rule_id":          rid,
                            "rule_name":        rname,
                            "mitre_id":         mid,
                            "mitre_tactic":     "Persistence",
                            "kill_chain_stage": "Persistence",
                            "severity":         sev,
                            "confidence_score": min(conf, 70),  # Fallback cap (Audit v2 Final)
                            "description":      f"{rname}: {fpath}",
                            # ── Explainability ──────────────────────────────
                            "detection_source": "fallback",
                            "match_reason": [
                                REASON_MAP["event_id"](eid),
                                REASON_MAP["reg"](", ".join(matched_kws)),
                                f"Full registry key: {fpath}",
                            ],
                            "matched_fields": {
                                "event_id":     eid,
                                "matched_keywords": matched_kws,
                                "reg_key":      event.get("reg_key") or event.get("targetobject") or fpath,
                                "image":        event.get("image"),
                                "parent_image": event.get("parent_image"),
                                "command_line": event.get("command_line"),
                                "file_path":    fpath,
                            },
                            # ── Event context ────────────────────────────────
                            "utc_time":         event.get("utc_time") or event.get("event_time"),
                            "event_time":       event.get("event_time") or event.get("utc_time"),
                            "image":            event.get("image"),
                            "event_id":         eid,
                            "computer":         event.get("computer"),
                            "process_id":       event.get("pid") or event.get("process_id"),
                            "parent_process_id":event.get("ppid") or event.get("parent_process_id"),
                            "parent_image":     event.get("parent_image"),
                            "source_ip":        event.get("src_ip") or event.get("source_ip"),
                            "source_port":      event.get("source_port"),
                            "destination_ip":   event.get("dst_ip") or event.get("destination_ip"),
                            "destination_port": event.get("dst_port") or event.get("destination_port"),
                            "target_filename":  event.get("file_path") or event.get("target_filename") or event.get("reg_key"),
                            "command_line":     event.get("command_line"),
                        }
                        # Final Mastery Normalization
                        hit["explanation"] = normalize_explanation(hit)
                        hits.append(hit)
                        break  # one hit per event is enough

    return hits


# ---------------------------------------------------------------------------
# DataFrame-level detection (used by analysis_engine.ingest_upload)
# ---------------------------------------------------------------------------

DETECTION_OUTPUT_COLS = [
    "rule_id", "rule_name", "mitre_id", "mitre_tactic", "kill_chain_stage",
    "utc_time", "event_time", "image", "event_id", "description", "severity",
    "computer", "process_id", "parent_process_id", "parent_image",
    "source_ip", "source_port", "destination_ip", "destination_port",
    "target_filename", "command_line", "confidence_score",
]


def find_detections(
    df: 'pd.DataFrame',
    rules: Optional[List[Dict]] = None,
) -> 'pd.DataFrame':
    """
    Run YAML rule matching across a DataFrame of events.
    Falls back to heuristic EID mapping if no rules supplied.
    """
    import pandas as pd
    if df.empty:
        return pd.DataFrame(columns=DETECTION_OUTPUT_COLS)

    if rules is None:
        rules = load_yaml_rules()

    if not rules:
        return _heuristic_detections(df)

    hits = []
    for _, row in df.iterrows():
        ev = row.to_dict()
        for hit in match_rules(ev, rules):
            hits.append(hit)

    # --- SEQUENCE DETECTION (Issue 1) ---
    try:
        seq_engine = _get_sequence_engine()
        # Ensure time column exists for sequence engine
        df_seq = df.copy()
        if "event_time" not in df_seq.columns and "utc_time" in df_seq.columns:
            df_seq["event_time"] = df_seq["utc_time"]
            
        sequence_hits = seq_engine.process_dataframe(df_seq)
        for seq in sequence_hits:
            # Map sequence detection to main detection schema
            hits.append({
                "rule_id":          seq.get("rule_id"),
                "rule_name":        seq.get("rule_name"),
                "mitre_id":         seq.get("mitre_id"),
                "mitre_tactic":     seq.get("mitre_tactic"),
                "kill_chain_stage": seq.get("kill_chain_stage"),
                "severity":         seq.get("severity") or "high",
                "confidence_score": seq.get("confidence_score") or 85,
                "description":      seq.get("description"),
                "detection_source": "sequence",
                "match_reason":     [f"Sequence pattern matched: {seq.get('rule_name')}"],
                "image":            seq.get("image"),
                "event_time":       seq.get("event_time"),
                "utc_time":         seq.get("utc_time"),
                "computer":         seq.get("computer"),
                "is_sequence":      True
            })
    except Exception as e:
        print(f"[WARN] Sequence detection failed in find_detections: {e}")

    if not hits:
        return pd.DataFrame(columns=DETECTION_OUTPUT_COLS)

    result = pd.DataFrame(hits)
    for col in DETECTION_OUTPUT_COLS:
        if col not in result.columns:
            result[col] = None
    return result[DETECTION_OUTPUT_COLS]


def _heuristic_detections(df: 'pd.DataFrame') -> 'pd.DataFrame':
    """Minimal EID-based detection when no rules.yaml is available."""
    import pandas as pd
    EID_MAP = {
        1:  ("T1059",     "Execution",           "Execution",           "Process Create"),
        3:  ("T1071",     "Command and Control",  "Command and Control",  "Network Connection"),
        8:  ("T1055",     "Privilege Escalation", "Privilege Escalation", "CreateRemoteThread"),
        10: ("T1003",     "Credential Access",    "Credential Access",   "LSASS Access"),
        11: ("T1105",     "Command and Control",  "Command and Control",  "FileCreate"),
        12: ("T1112",     "Defense Evasion",      "Persistence",         "Registry Create"),
        13: ("T1112",     "Defense Evasion",      "Persistence",         "Registry Set"),
        22: ("T1071.004", "Command and Control",  "Command and Control",  "DNSEvent"),
        25: ("T1055.012", "Defense Evasion",      "Privilege Escalation", "ProcessTampering"),
    }
    hits = []
    for _, row in df.iterrows():
        try:
            eid = int(float(row.get("event_id") or 0))
        except Exception:
            continue
        if eid not in EID_MAP:
            continue
        mitre_id, tactic, stage, desc = EID_MAP[eid]
        hit = {
            "rule_id":          f"HEUR-{eid}",
            "rule_name":        f"Heuristic EID {eid}: {desc}",
            "mitre_id":         mitre_id,
            "mitre_tactic":     tactic,
            "kill_chain_stage": stage,
            "utc_time":         row.get("utc_time") or row.get("event_time"),
            "event_time":       row.get("event_time") or row.get("utc_time"),
            "image":            row.get("image"),
            "event_id":         eid,
            "description":      desc,
            "severity":         row.get("severity") or "medium",
            "computer":         row.get("computer"),
            "process_id":       row.get("pid") or row.get("process_id"),
            "parent_process_id":row.get("ppid") or row.get("parent_process_id"),
            "parent_image":     row.get("parent_image"),
            "source_ip":        row.get("src_ip") or row.get("source_ip"),
            "source_port":      row.get("source_port"),
            "destination_ip":   row.get("dst_ip") or row.get("destination_ip"),
            "destination_port": row.get("dst_port") or row.get("destination_port"),
            "target_filename":  row.get("file_path") or row.get("target_filename"),
            "command_line":     row.get("command_line"),
            "confidence_score": 40,
        }
        # Final Mastery Normalization
        hit["explanation"] = normalize_explanation(hit)
        hits.append(hit)

    if not hits:
        import pandas as pd
        return pd.DataFrame(columns=DETECTION_OUTPUT_COLS)
    import pandas as pd
    result = pd.DataFrame(hits)
    for col in DETECTION_OUTPUT_COLS:
        if col not in result.columns:
            result[col] = None
    return result[DETECTION_OUTPUT_COLS]


# ---------------------------------------------------------------------------
# Burst-level full analysis pipeline
# (used by analysis_engine.run_full_analysis)
# ---------------------------------------------------------------------------

def analyze_burst_batch(
    bursts: List[Dict[str, Any]],
    run_id: str,
    rules: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """
    Full analysis pipeline for a batch of burst dicts:

    1. YAML rule detection per burst event summary
    2. Baseline deviation scoring
    3. Graph correlation
    4. Unified risk scoring
    5. Kill-chain and severity assignment

    Returns:
        {
          "bursts":     List[Dict] — mutated bursts with all scores
          "campaigns":  List[Dict] — correlation campaigns
          "detections": List[Dict] — flat detection hits
        }
    """
    if not bursts:
        return {"bursts": [], "campaigns": [], "detections": []}

    if rules is None:
        rules = load_yaml_rules()

    baseline  = _get_baseline_engine()
    scorer    = _get_scoring_engine()
    try:
        correlate = _get_correlate_bursts()
    except Exception as _ce:
        print(f"[DetectionEngine] correlation_engine import failed: {_ce} — skipping correlation")
        correlate = lambda bursts, run_id, persist=True: (bursts, [])

    # ── Step 1: Baseline scoring (mutates bursts in-place) ─────────────
    baseline.process_burst_batch(bursts)

    # ── Step 2: YAML rule matching per burst ───────────────────────────
    all_detection_hits: List[Dict[str, Any]] = []
    for burst in bursts:
        # ── Build rich event context — preserve all available fields ────
        # The old "synthetic_event" summarized bursts into a thin dict,
        # losing raw fields like grandparent_image, integrity_level,
        # target_object, and per-event cmd context.
        # We now pass the full burst dict enriched with derived fields.
        rich_event = {
            # Core identity
            "event_id":         (burst.get("event_ids") or [1])[0],
            "image":            burst.get("image"),
            "parent_image":     burst.get("parent_image"),
            "grandparent_image": burst.get("grandparent_image"),    # trigram support
            "computer":         burst.get("computer"),
            "user":             burst.get("user"),
            # Command context — prefer full commandline over concatenated descriptions
            "command_line": (
                burst.get("command_line")
                or burst.get("commandline")
                or " ".join(str(d) for d in (burst.get("descriptions") or []) if d)
            ),
            # File / registry paths
            "file_path":       burst.get("target_filename"),
            "target_object":   burst.get("target_object"),
            "target_filename": burst.get("target_filename"),
            "reg_key":         burst.get("reg_key") or burst.get("target_object"),
            # Severity + time
            "severity":   burst.get("severity") or "low",
            "utc_time":   burst.get("start_time"),
            "event_time": burst.get("start_time"),
            # Entropy signals (from parser enrichment)
            "cmd_high_entropy":      burst.get("cmd_high_entropy", False),
            "cmd_has_encoded_flag":  burst.get("cmd_has_encoded_flag", False),
            "cmd_b64_detected":      burst.get("cmd_b64_detected", False),
            "has_encoded_flag":      burst.get("cmd_has_encoded_flag", False),
            "cmd_entropy":           burst.get("cmd_entropy", 0.0),
            # Network
            "src_ip":           burst.get("source_ip"),
            "dst_ip":           burst.get("destination_ip"),
            "dst_port":         burst.get("destination_port"),
            "destination_ip":   burst.get("destination_ip"),
            "destination_port": burst.get("destination_port"),
            # Process IDs
            "pid":  burst.get("process_id"),
            "ppid": burst.get("parent_process_id"),
            # Behavioral flags from prior pipeline stages
            "has_persistence": burst.get("has_persistence", False),
            "has_injection":   burst.get("has_injection",   False),
            "has_net":         burst.get("has_net",         False),
            # Baseline sequence depth: how many hops deep is this in a
            # known-anomalous chain?  Used for real chain_depth calculation.
            "_seq_anomaly":    burst.get("baseline_sub_scores", {}).get("sequence", 0.0),
        }

        hits = match_rules(rich_event, rules)
        
        # ── Step 2.1: Authoritative Primary Detection Selection ──────────
        primary = None
        supporting = []
        if hits:
            # Align confidence: primary adopts max confidence across all hits
            # But preserves its own original_conf for explainability (Audit v2 Final)
            max_conf = max(h.get("confidence_score", 0) for h in hits)
            primary = pick_primary_detection(hits)
            if primary:
                primary["supporting_max_conf"] = max_conf
                supporting = [h for h in hits if h is not primary]

        burst["primary_detection"] = primary
        burst["supporting_detections"] = supporting
        burst["_detection_hits"] = hits  # keep for internal scoring
        all_detection_hits.extend(hits)

        # Persistence / injection flags from detection hits
        for h in hits:
            stage = h.get("kill_chain_stage") or ""
            mitre = h.get("mitre_id") or ""
            if "Persistence" in stage:
                burst["has_persistence"] = True
            if mitre in ("T1055", "T1055.001", "T1055.012", "T1134", "T1134.001"):
                burst["has_injection"] = True
            # Credential access is also escalation-worthy
            if "Credential" in stage:
                burst["has_credential_access"] = True

    # ── Step 3: Kill-chain assignment ──────────────────────────────────
    for burst in bursts:
        hits   = burst.get("_detection_hits", [])
        stages = [h.get("kill_chain_stage") for h in hits if h.get("kill_chain_stage")]
        if stages:
            highest = max(stages, key=lambda s: KILL_CHAIN_ORDER.index(s) if s in KILL_CHAIN_ORDER else 0)
            # Store mult-stage context (Audit v2 Final)
            burst["kill_chain_stages"] = sorted(list(set(stages)), key=lambda s: KILL_CHAIN_ORDER.index(s) if s in KILL_CHAIN_ORDER else 0)
            burst["kill_chain_stage"] = highest
        elif not burst.get("kill_chain_stage"):
            burst["kill_chain_stage"] = "Execution"

    # ── Step 4: Graph correlation ───────────────────────────────────────
    bursts, campaigns = correlate(bursts, run_id, persist=True)

    # ── Step 5: Unified risk scoring ────────────────────────────────────
    # Compute adaptive per-host noise threshold before scoring.
    # Hosts with many low-severity events have a higher inherent noise floor,
    # so a moderate score there is less meaningful than on a quiet host.
    host_noise: Dict[str, int] = {}
    for b in bursts:
        host = (b.get("computer") or "unknown").lower()
        host_noise[host] = host_noise.get(host, 0) + int(b.get("count") or 1)

    for burst in bursts:
        dev_score = float(burst.get("deviation_score") or 0.0)

        # ── Real chain depth calculation ───────────────────────────────────
        # v1 heuristic: "if baseline flagged anything → chain_depth = 2" — wrong.
        # Real chain depth = distinct kill-chain stages from detection hits
        # PLUS a +1 bonus when the baseline sequence model found a rare
        # multi-hop transition (sequence anomaly > 0.7 means the n-gram model
        # hasn't seen this parent→child chain in normal behavior).
        kc_set = set()
        for hit in burst.get("_detection_hits", []):
            s = hit.get("kill_chain_stage")
            if s and s in KILL_CHAIN_ORDER:
                kc_set.add(s)

        seq_anomaly = float(burst.get("baseline_sub_scores", {}).get("sequence", 0.0))
        chain_depth = max(len(kc_set), 1)
        if seq_anomaly > 0.7 and chain_depth < 3:
            # Rare sequence transition — promote chain depth by 1 to reflect
            # the multi-hop behavioral signal from the n-gram model
            chain_depth += 1

        if burst.get("has_correlation"):
            chain_depth = max(chain_depth, 2)   # Correlated events always ≥ 2

        result = scorer.score_burst(
            burst,
            detections=burst.get("_detection_hits"),
            behavior_score=dev_score,
            chain_depth=chain_depth,
        )

        burst["risk_score"]          = int(round(result.score))
        burst["score_ledger"]        = [e.to_dict() for e in result.ledger]
        burst["confidence_reasons"]  = result.to_dict()["why"]
        burst["stage_cap"]           = int(result.stage_cap)
        burst["chain_multiplier"]    = result.chain_multiplier

        # ── Adaptive threshold: noisy hosts require higher score to alert ──
        host       = (burst.get("computer") or "unknown").lower()
        host_total = host_noise.get(host, 1)
        # If host generates >10 000 events in this batch, raise alert bar by 5 pts
        # Dynamic scale logic (Audit v2 Final): correct ordering + max cap
        adaptive_floor = 40
        if host_total > 50_000:
            adaptive_floor = 50
        elif host_total > 10_000:
            adaptive_floor = 45
        adaptive_floor = min(60, adaptive_floor)

        # ── Slow-attack penalty carry-through ─────────────────────────────
        # If baseline flagged a stealthy pattern, ensure score doesn't drop
        # below 40 even if raw signal is weak — the behavioral signal is real.
        if burst.get("baseline_anomalies") and len(burst["baseline_anomalies"]) >= 2:
            burst["risk_score"] = max(burst["risk_score"], 35)

        # Severity classification
        stage = burst.get("kill_chain_stage", "Execution")
        score = burst["risk_score"]
        if stage in ("Actions on Objectives", "Command and Control",
                     "Persistence", "Privilege Escalation", "Credential Access"):
            burst["severity"] = "high"
        elif score >= 60:
            burst["severity"] = "high"
        elif score >= 40:
            burst["severity"] = "medium"
        else:
            burst["severity"] = "low"

        # Classification (uses adaptive floor)
        burst["classification"] = (
            "attack_candidate" if (
                score >= adaptive_floor
                or burst.get("has_persistence")
                or burst.get("has_injection")
                or burst.get("has_correlation")
            ) else "background_activity"
        )

        # ── Feedback loop: high-risk events MUST NOT poison the baseline ──
        # Mark bursts that scored above 80 so BaselineEngine.should_learn()
        # will reject them — prevents attackers from training the model.
        if score > 80:
            burst["_never_learn"] = True

        # Clean temp field
        burst.pop("_detection_hits", None)

    # ── Step 6: Baseline save handled by analysis_engine.persist_behavior_baseline()
    # Do NOT call baseline.save_to_db() here — analysis_engine manages that
    # after all scoring is complete, preventing double-writes.

    return {
        "bursts":     bursts,
        "campaigns":  campaigns,
        "detections": all_detection_hits,
    }


# ---------------------------------------------------------------------------
# Legacy DetectionRule / DetectionEngine classes
# (kept for backward compatibility with existing soc_verdict / app imports)
# ---------------------------------------------------------------------------

class DetectionRule:
    """Legacy rule wrapper — kept for backward compatibility."""

    def __init__(
        self,
        name: str,
        event_ids: List[str],
        severity: str,
        confidence: int,
        mitre_id: str,
        mitre_tactic: str,
        explanation: str,
        check_func,
        rule_id: Optional[str] = None,
        version: int = 1,
        enabled: bool = True,
    ):
        self.name         = name
        self.event_ids    = event_ids
        self.severity     = severity
        self.confidence   = confidence
        self.mitre_id     = mitre_id
        self.mitre_tactic = mitre_tactic
        self.explanation  = explanation
        self.check_func   = check_func
        self.rule_id      = rule_id or name.lower().replace(" ", "_")
        self.version      = version
        self.enabled      = enabled

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        eid = str(event.get("event_id", "")).strip()
        if eid not in self.event_ids:
            return None
        try:
            if not self.check_func(event):
                return None
        except Exception:
            return None

        return {
            "rule_name":        self.name,
            "rule_id":          self.rule_id,
            "severity":         self.severity,
            "confidence_score": self.confidence,
            "mitre_id":         self.mitre_id,
            "mitre_tactic":     self.mitre_tactic,
            "description":      self.explanation,
            "kill_chain_stage": self._tactic_to_stage(self.mitre_tactic),
            "rule_version":     self.version,
            "event_id":         event.get("event_id"),
            "utc_time":         event.get("utc_time"),
            "image":            event.get("image"),
            "computer":         event.get("computer"),
            "process_id":       event.get("pid"),
            "parent_process_id":event.get("ppid"),
            "source_ip":        event.get("src_ip"),
            "destination_ip":   event.get("dst_ip"),
            "target_filename":  event.get("file_path") or event.get("target_filename"),
        }

    @staticmethod
    def _tactic_to_stage(tactic: str) -> str:
        mapping = {
            "Initial Access":       "Delivery",
            "Execution":            "Execution",
            "Persistence":          "Persistence",
            "Privilege Escalation": "Privilege Escalation",
            "Defense Evasion":      "Defense Evasion",
            "Credential Access":    "Credential Access",
            "Discovery":            "Discovery",
            "Lateral Movement":     "Lateral Movement",
            "Collection":           "Collection",
            "Command and Control":  "Command and Control",
            "Exfiltration":         "Exfiltration",
            "Impact":               "Actions on Objectives",
        }
        return mapping.get(tactic, "Execution")


class DetectionEngine:
    """
    Legacy class — wraps YAML rule matching for backward compatibility.
    New code should call match_rules() / find_detections() / analyze_burst_batch() directly.
    """

    def __init__(self):
        self.rules_yaml = load_yaml_rules()

    def run_detections(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        return match_rules(event, self.rules_yaml)
