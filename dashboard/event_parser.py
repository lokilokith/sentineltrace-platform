"""
event_parser.py — SentinelTrace v2.2
=====================================
Every parsed event is now fully enriched with computed signal fields
before leaving the parser. Downstream engines receive consistent,
pre-computed signals rather than having to recompute them ad-hoc.

New fields added to every event:
  cmd_entropy         float   Shannon entropy of command line
  is_high_entropy     bool    entropy > 4.5
  has_encoded_flag    bool    -enc/-encodedcommand/frombase64string
  has_download_url    bool    http:// or https:// in cmd
  b64_detected        bool    base64 blob in cmd
  b64_preview         str     decoded preview (first 80 chars)
  cmd_length          int     len(command_line)
  is_lolbin           bool    image in LOLBin set
  lolbin_weight       float   0.5-1.0 risk weight for this LOLBin
  is_external_ip      bool    dst_ip is non-RFC1918
  is_suspicious_chain bool    parent not in known-benign set
  is_system_process   bool    image is a known system process
  process_depth       int     hop count from a benign root (0=benign, 3=unknown)
"""
from __future__ import annotations

import base64
import hashlib
import logging
import math
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional


log = logging.getLogger("event_parser")

# ---------------------------------------------------------------------------
# MITRE mapping
# ---------------------------------------------------------------------------
EID_MITRE_MAP: Dict[int, Dict[str, str]] = {
    1:  {"mitre_id": "T1059",     "tactic": "Execution",            "stage": "Execution",             "desc": "Process Create"},
    2:  {"mitre_id": "T1070.006", "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "File Creation Time Changed"},
    3:  {"mitre_id": "T1071",     "tactic": "Command and Control",  "stage": "Command and Control",   "desc": "Network Connection"},
    4:  {"mitre_id": "T1562.001", "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "Sysmon Service State Changed"},
    5:  {"mitre_id": "T1057",     "tactic": "Discovery",            "stage": "Execution",             "desc": "Process Terminated"},
    6:  {"mitre_id": "T1014",     "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "Driver Loaded"},
    7:  {"mitre_id": "T1574.002", "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "Image Loaded"},
    8:  {"mitre_id": "T1055",     "tactic": "Privilege Escalation", "stage": "Privilege Escalation",  "desc": "CreateRemoteThread"},
    9:  {"mitre_id": "T1055",     "tactic": "Privilege Escalation", "stage": "Privilege Escalation",  "desc": "RawAccessRead"},
    10: {"mitre_id": "T1003",     "tactic": "Credential Access",    "stage": "Privilege Escalation",  "desc": "ProcessAccess (LSASS)"},
    11: {"mitre_id": "T1105",     "tactic": "Command and Control",  "stage": "Command and Control",   "desc": "FileCreate"},
    12: {"mitre_id": "T1112",     "tactic": "Defense Evasion",      "stage": "Persistence",           "desc": "Registry Create/Delete"},
    13: {"mitre_id": "T1112",     "tactic": "Defense Evasion",      "stage": "Persistence",           "desc": "Registry Set Value"},
    14: {"mitre_id": "T1112",     "tactic": "Defense Evasion",      "stage": "Persistence",           "desc": "Registry Rename"},
    15: {"mitre_id": "T1096",     "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "FileCreateStreamHash (ADS)"},
    16: {"mitre_id": "T1562.001", "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "Sysmon Config Change"},
    17: {"mitre_id": "T1559",     "tactic": "Execution",            "stage": "Execution",             "desc": "PipeEvent Create"},
    18: {"mitre_id": "T1559",     "tactic": "Execution",            "stage": "Execution",             "desc": "PipeEvent Connect"},
    19: {"mitre_id": "T1546.003", "tactic": "Privilege Escalation", "stage": "Privilege Escalation",  "desc": "WmiEvent Filter"},
    20: {"mitre_id": "T1546.003", "tactic": "Privilege Escalation", "stage": "Privilege Escalation",  "desc": "WmiEvent Consumer"},
    21: {"mitre_id": "T1546.003", "tactic": "Privilege Escalation", "stage": "Privilege Escalation",  "desc": "WmiEvent Binding"},
    22: {"mitre_id": "T1071.004", "tactic": "Command and Control",  "stage": "Command and Control",   "desc": "DNSEvent"},
    23: {"mitre_id": "T1107",     "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "FileDelete"},
    24: {"mitre_id": "T1115",     "tactic": "Collection",           "stage": "Actions on Objectives", "desc": "ClipboardChange"},
    25: {"mitre_id": "T1055.012", "tactic": "Defense Evasion",      "stage": "Privilege Escalation",  "desc": "ProcessTampering"},
    26: {"mitre_id": "T1485",     "tactic": "Impact",               "stage": "Actions on Objectives", "desc": "FileDeleteDetected"},
    27: {"mitre_id": "T1036.005", "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "FileBlockExecutable"},
}

BENIGN_PARENTS = frozenset({
    "services.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "csrss.exe",
    "svchost.exe", "spoolsv.exe", "explorer.exe", "taskhost.exe",
    "taskhostw.exe", "smss.exe",
})

SYSTEM_PROCESSES = frozenset({
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "spoolsv.exe",
    "explorer.exe", "taskhost.exe", "taskhostw.exe",
})

# Risk weight per LOLBin: higher = more suspicious in unusual context
LOLBIN_WEIGHTS: Dict[str, float] = {
    "mshta.exe":       1.0,
    "regsvr32.exe":    1.0,
    "cmstp.exe":       1.0,
    "psexec.exe":      1.0,
    "psexec64.exe":    1.0,
    "wmic.exe":        0.9,
    "certutil.exe":    0.9,
    "bitsadmin.exe":   0.9,
    "installutil.exe": 0.9,
    "msbuild.exe":     0.9,
    "hh.exe":          0.9,
    "rundll32.exe":    0.8,
    "wscript.exe":     0.8,
    "cscript.exe":     0.8,
    "at.exe":          0.8,
    "powershell.exe":  0.7,
    "pwsh.exe":        0.7,
    "schtasks.exe":    0.6,
    "cmd.exe":         0.5,
}
LOLBIN_SET = frozenset(LOLBIN_WEIGHTS.keys())

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_B64_RE = re.compile(
    r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
)
_PRIVATE_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "127.", "::1", "fe80:",
)


def _is_external_ip(ip: str) -> bool:
    return bool(ip) and not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _clean_lineage_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        if math.isnan(value):
            return ""
        return str(value)
    text = str(value).strip()
    if text.lower() in ("", "none", "nan"):
        return ""
    return text


def _basename_lower(value: Any) -> str:
    text = _clean_lineage_text(value).lower()
    return text.rsplit("\\", 1)[-1] if "\\" in text else text


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def score_command_entropy(cmd: Optional[str]) -> Dict[str, Any]:
    if not cmd:
        return {
            "entropy": 0.0, "is_high_entropy": False,
            "b64_detected": False, "b64_preview": None,
            "has_encoded_flag": False, "has_download_url": False,
        }
    # Cap length before regex to prevent catastrophically slow scans on huge cmds
    cmd = cmd[:4096]
    lower = cmd.lower()
    entropy = _shannon_entropy(cmd)
    b64_matches = _B64_RE.findall(cmd)
    b64_detected = bool(b64_matches)
    b64_preview  = None
    for m in b64_matches:
        for enc in ("utf-16-le", "utf-8"):
            try:
                dec = base64.b64decode(m + "==").decode(enc, "replace").strip()
                if len(dec) > 4:
                    b64_preview = dec[:80]
                    break
            except Exception:
                pass
        if b64_preview:
            break
    # Broadened: includes -ec shorthand, frombase64string, [convert]::frombase64
    has_encoded_flag = any(x in lower for x in [
        "-enc ", "-encodedcommand", " -e ", "-ec ",
        "frombase64string", "[convert]::frombase64", "::frombase64",
    ])
    # Adaptive Threshold (Audit v2 Final): 4.5 baseline + length-scaled penalty
    # Penalizes long cmd lines more strictly while ignoring trivial noise (<20 chars)
    is_high_entropy = False
    if len(cmd) >= 20:
        threshold = 4.5 + min(1.5, len(cmd) / 500)
        is_high_entropy = entropy > threshold

    return {
        "entropy":          round(entropy, 3),
        "is_high_entropy":  is_high_entropy,
        "b64_detected":     b64_detected,
        "b64_preview":      b64_preview,
        "has_encoded_flag": has_encoded_flag,
        "has_download_url": "http://" in lower or "https://" in lower,
    }


def _normalize_command_text(value: Optional[str]) -> str:
    return re.sub(r"\s+", " ", str(value or "").lower()).strip()


def _refine_attack_context(evt: Dict[str, Any]) -> Dict[str, Any]:
    image = str(evt.get("image") or "").lower()
    image_base = image.split("\\")[-1] if "\\" in image else image
    parent = str(evt.get("parent_image") or "").lower()
    parent_base = parent.split("\\")[-1] if "\\" in parent else parent
    command = _normalize_command_text(evt.get("command_line"))
    reg_key = _normalize_command_text(evt.get("reg_key") or evt.get("target_object") or evt.get("file_path"))
    benign_admin_tools = BENIGN_PARENTS | frozenset({"splunkd.exe", "splunk.exe", "osqueryd.exe", "senseir.exe", "csfalconservice.exe", "crowdstrike.exe", "carbonblack.exe", "cb.exe", "qualysagent.exe", "rapid7agent.exe"})

    has_encoded = any(token in command for token in ("-enc", "-encodedcommand", "frombase64string", "[convert]::frombase64", "invoke-expression", "iex ", "-nop"))
    has_persistence = any(token in command for token in ("schtasks", "currentversion\\run", "currentversion\\runonce", "runonce", "startup", "autorun")) or any(token in reg_key for token in ("\\run\\", "\\runonce\\", "currentversion\\run", "appinit_dlls", "image file execution options"))
    has_remote_exec = any(token in command for token in ("psexec", "wmic", "winrm", "sc.exe create", "service create", "wmiprvse"))
    has_lolbin = image_base in {"cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "wmiprvse.exe", "schtasks.exe"}

    if image_base in {"powershell.exe", "pwsh.exe"}:
        if has_encoded:
            return {"mitre_id": "T1059.001", "mitre_tactic": "Execution", "kill_chain_stage": "Execution"}
        if evt.get("has_download_url"):
            return {"mitre_id": "T1105", "mitre_tactic": "Command and Control", "kill_chain_stage": "Command and Control"}
        return {"mitre_id": "T1059.001", "mitre_tactic": "Execution", "kill_chain_stage": "Execution"}

    if image_base in {"psexec.exe", "psexec64.exe"}:
        return {"mitre_id": "T1021.002", "mitre_tactic": "Lateral Movement", "kill_chain_stage": "Lateral Movement"}

    if image_base in {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"} and parent_base in benign_admin_tools:
        suspicious_tokens = ("-enc", "-encodedcommand", "frombase64string", "invoke-expression", "iex ", "-nop", "psexec", "wmic", "winrm", "schtasks", "reg add", "currentversion\\run")
        if not any(token in command for token in suspicious_tokens) and not has_persistence and not has_remote_exec:
            return {"mitre_id": None, "mitre_tactic": None, "kill_chain_stage": "Background"}

        # Parent-aware fallback: if parent is non-benign and command shows remote-exec markers,
        # prefer lateral-movement mapping rather than leaving event unmapped.
        if parent_base and parent_base not in benign_admin_tools and parent_base not in {"", "unknown"}:
            if any(token in command for token in ("psexec", "wmic", "winrm", "sc.exe create", "service create", "wmiprvse")):
                return {"mitre_id": "T1021.002", "mitre_tactic": "Lateral Movement", "kill_chain_stage": "Lateral Movement"}

        # Download / staging indicators: map to T1105 (Ingress Tool Transfer) when evidence exists.
        if evt.get("has_download_url") or any(token in command for token in ("certutil", "bitsadmin", "invoke-webrequest", "curl ", "wget ")):
            return {"mitre_id": "T1105", "mitre_tactic": "Command and Control", "kill_chain_stage": "Command and Control"}

    if image_base == "cmd.exe":
        if has_persistence:
            return {"mitre_id": "T1053.005", "mitre_tactic": "Persistence", "kill_chain_stage": "Persistence"}
        if has_remote_exec:
            return {"mitre_id": "T1021.002", "mitre_tactic": "Lateral Movement", "kill_chain_stage": "Lateral Movement"}
        return {"mitre_id": "T1059.003", "mitre_tactic": "Execution", "kill_chain_stage": "Execution"}

    if image_base == "schtasks.exe" or "schtasks" in command:
        return {"mitre_id": "T1053.005", "mitre_tactic": "Persistence", "kill_chain_stage": "Persistence"}

    if image_base == "regsvr32.exe":
        return {"mitre_id": "T1218.010", "mitre_tactic": "Defense Evasion", "kill_chain_stage": "Defense Evasion"}

    if image_base == "rundll32.exe":
        return {"mitre_id": "T1218.011", "mitre_tactic": "Defense Evasion", "kill_chain_stage": "Defense Evasion"}

    if image_base == "mshta.exe":
        return {"mitre_id": "T1218.005", "mitre_tactic": "Defense Evasion", "kill_chain_stage": "Execution"}

    if image_base in {"wmic.exe", "wmiprvse.exe"} or has_remote_exec:
        if parent_base and parent_base not in benign_admin_tools:
            return {"mitre_id": "T1047", "mitre_tactic": "Lateral Movement", "kill_chain_stage": "Lateral Movement"}
        return {"mitre_id": "T1047", "mitre_tactic": "Discovery", "kill_chain_stage": "Discovery"}

    if has_lolbin and has_encoded:
        return {"mitre_id": "T1059", "mitre_tactic": "Execution", "kill_chain_stage": "Execution"}

    return {}


# ---------------------------------------------------------------------------
# Core enrichment — runs on every event
# ---------------------------------------------------------------------------

def enrich_event(evt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add computed signal fields to a parsed event dict in-place.
    Called at parse time so all downstream code sees consistent signals.
    Idempotent: second call on the same dict is a no-op.
    """
    # Guard against double-enrichment (parse_event + ingest_upload both call this)
    if evt.get("_enriched"):
        return evt
    evt["_enriched"] = True

    cmd        = str(evt.get("command_line") or "")
    image      = (evt.get("image") or "").lower()
    image_base = image.split("\\")[-1] if "\\" in image else image
    parent     = (evt.get("parent_image") or "").lower()
    parent_base = parent.split("\\")[-1] if "\\" in parent else parent
    dst_ip     = evt.get("dst_ip") or evt.get("destination_ip") or ""

    ea = score_command_entropy(cmd or None)

    # Entropy signals — dual names (new canonical + old compat)
    evt["cmd_entropy"]          = ea["entropy"]
    evt["is_high_entropy"]      = ea["is_high_entropy"]
    evt["cmd_high_entropy"]     = ea["is_high_entropy"]
    evt["has_encoded_flag"]     = ea["has_encoded_flag"]
    evt["cmd_has_encoded_flag"] = ea["has_encoded_flag"]
    evt["has_download_url"]     = ea["has_download_url"]
    evt["cmd_has_download_url"] = ea["has_download_url"]
    evt["b64_detected"]         = ea["b64_detected"]
    evt["cmd_b64_detected"]     = ea["b64_detected"]
    evt["b64_preview"]          = ea["b64_preview"]
    evt["cmd_b64_preview"]      = ea["b64_preview"]
    evt["cmd_length"]           = len(cmd)

    # LOLBin signals
    evt["is_lolbin"]     = image_base in LOLBIN_SET
    evt["lolbin_weight"] = LOLBIN_WEIGHTS.get(image_base, 0.0)

    # Network signals
    evt["is_external_ip"] = _is_external_ip(dst_ip)

    attack_context = _refine_attack_context(evt)
    if attack_context:
        if attack_context.get("kill_chain_stage") == "Background" and evt.get("kill_chain_stage") not in (None, "Execution", "Unclassified"):
            pass
        else:
            for key, value in attack_context.items():
                if value is not None:
                    evt[key] = value

    # Process-chain signals
    evt["is_suspicious_chain"] = bool(parent_base) and parent_base not in BENIGN_PARENTS
    evt["is_system_process"]   = image_base in SYSTEM_PROCESSES

    return evt


# ---------------------------------------------------------------------------
# XML parsing helpers
# ---------------------------------------------------------------------------

def _get_text(elem: Optional[ET.Element]) -> Optional[str]:
    if elem is None:
        return None
    t = elem.text
    return t.strip() if t else None


def _find(root: ET.Element, tag: str) -> Optional[ET.Element]:
    return root.find(tag) or root.find(f"{_NS}{tag}")


def _find_all(root: ET.Element, tag: str) -> List[ET.Element]:
    return list({id(e): e for e in root.findall(tag) + root.findall(f"{_NS}{tag}")}.values())


def _compute_event_uid(computer, time_created, event_id, image, pid, ppid, command_line) -> str:
    parts = [
        computer or "", time_created or "", str(event_id or ""),
        image or "", pid or "", ppid or "", (command_line or "")[:256],
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8", "ignore")).hexdigest()


def parse_event(ev: ET.Element) -> Dict[str, Any]:
    system = _find(ev, "System")
    event_id = time_created = computer = None
    if system is not None:
        eid_elem = _find(system, "EventID")
        try:
            event_id = int(_get_text(eid_elem) or "0") or None
        except Exception:
            pass
        tc = _find(system, "TimeCreated")
        if tc is not None:
            time_created = tc.attrib.get("SystemTime") or tc.attrib.get("systemTime")
        computer = _get_text(_find(system, "Computer"))

    event_data = _find(ev, "EventData")
    data_map: Dict[str, Optional[str]] = {}
    if event_data is not None:
        for d in _find_all(event_data, "Data"):
            name = d.attrib.get("Name")
            if name:
                data_map[name.lower()] = _get_text(d)

    raw_image    = data_map.get("image") or data_map.get("processimage")
    raw_parent   = data_map.get("parentimage")
    image        = Path(raw_image).name.lower()  if raw_image  else None
    parent_image = Path(raw_parent).name.lower() if raw_parent else None
    command_line = data_map.get("commandline") or data_map.get("cmdline")
    user         = data_map.get("user") or data_map.get("username")
    pid          = data_map.get("processid") or data_map.get("pid")
    ppid         = data_map.get("parentprocessid") or data_map.get("ppid")
    src_ip       = data_map.get("sourceip") or data_map.get("src_ip")
    dst_ip       = data_map.get("destinationip") or data_map.get("dst_ip")
    dst_port     = data_map.get("destinationport") or data_map.get("dst_port")
    file_path    = data_map.get("targetfilename") or data_map.get("filepath")
    reg_key      = data_map.get("targetobject") or data_map.get("details")
    dns_query    = data_map.get("queryname")
    hashes       = data_map.get("hashes")

    eid_info = EID_MITRE_MAP.get(event_id or 0, {})
    severity = (
        "high"   if event_id in {1, 8, 9, 12, 13, 14, 19, 25}
        else "medium" if event_id in {3, 7, 10, 11, 22, 23}
        else "low"
    )

    evt: Dict[str, Any] = {
        "event_uid":         _compute_event_uid(computer, time_created, event_id, image, pid, ppid, command_line),
        "event_time":        time_created,
        "utc_time":          time_created,
        "event_id":          event_id,
        "image":             image,
        "parent_image":      parent_image,
        "command_line":      command_line,
        "user":              user,
        "pid":               pid,
        "ppid":              ppid,
        "src_ip":            src_ip,
        "dst_ip":            dst_ip,
        "dst_port":          dst_port,
        "file_path":         file_path,
        "severity":          severity,
        "computer":          computer,
        "reg_key":           reg_key,
        "dns_query":         dns_query,
        "hashes":            hashes,
        "mitre_id":          eid_info.get("mitre_id"),
        "mitre_tactic":      eid_info.get("tactic"),
        "description":       eid_info.get("desc", ""),
        "kill_chain_stage":  eid_info.get("stage"),
        "destination_ip":    dst_ip,
        "source_ip":         src_ip,
        "source_port":       None,
        "target_filename":   file_path,
        "process_id":        pid,
        "parent_process_id": ppid,
        "tags":              None,
        "parser_version":    "2.2.0",
    }

    # Ensure event_id is int or None (never string "None" or "0")
    if evt["event_id"] is not None:
        try:
            evt["event_id"] = int(evt["event_id"])
            if evt["event_id"] == 0:
                evt["event_id"] = None
        except (TypeError, ValueError):
            evt["event_id"] = None

    # Enrich every event at parse time
    enrich_event(evt)
    return evt


# ---------------------------------------------------------------------------
# Batch loading
# ---------------------------------------------------------------------------

def load_all_sources_from_xml(xml_path) -> List[Dict[str, Any]]:
    import time

    xml_path = Path(xml_path)
    if not xml_path.exists():
        raise FileNotFoundError(f"Sysmon XML not found: {xml_path}")

    t_total = time.perf_counter()
    t0 = time.perf_counter()
    tree   = ET.parse(xml_path)
    root   = tree.getroot()
    t_parse = time.perf_counter() - t0

    t0 = time.perf_counter()
    events = list({
        id(e): e
        for e in root.findall(f".//{_NS}Event") + root.findall(".//Event")
    }.values())
    t_collect = time.perf_counter() - t0
    if not events:
        raise RuntimeError("No <Event> elements found in XML.")
    log.info("Parsed %d raw XML events from %s", len(events), xml_path.name)
    log.info(
        "[INGEST_PROBE] stage=xml_parse_tree elapsed_sec=%.3f file=%s",
        t_parse,
        xml_path.name,
    )
    log.info(
        "[INGEST_PROBE] stage=xml_event_collection elapsed_sec=%.3f events=%d",
        t_collect,
        len(events),
    )

    t0 = time.perf_counter()
    parsed = []
    errors = 0
    for ev in events:
        try:
            parsed.append(parse_event(ev))
        except Exception as _pe:
            errors += 1
            if errors <= 5:  # log first 5 to avoid spam
                log.warning("parse_event failed for event: %s", _pe)
    if errors > 0:
        log.warning("[event_parser] %d events failed to parse (skipped)", errors)
    t_iter = time.perf_counter() - t0
    log.info(
        "[INGEST_PROBE] stage=xml_event_iteration elapsed_sec=%.3f parsed=%d errors=%d",
        t_iter,
        len(parsed),
        errors,
    )
    log.info(
        "[INGEST_PROBE] stage=load_all_sources_total elapsed_sec=%.3f parsed=%d",
        time.perf_counter() - t_total,
        len(parsed),
    )
    return parsed


def parse_xml_to_dataframe(xml_path) -> 'pd.DataFrame':
    import pandas as pd
    return pd.DataFrame(load_all_sources_from_xml(xml_path))


# ---------------------------------------------------------------------------
# Parent-chain enrichment
# ---------------------------------------------------------------------------

def enrich_parent_chains(df: 'pd.DataFrame') -> 'pd.DataFrame':
    if df.empty or "ppid" not in df.columns:
        return df
    working = df.copy()

    phase_started = time.perf_counter()
    pid_to_image: Dict[tuple, str] = {}
    first_ppid_by_image: Dict[tuple, str] = {}
    repeated_parent_keys = 0
    repeated_image_keys = 0
    for row in working.itertuples(index=False):
        comp = _clean_lineage_text(getattr(row, "computer", None)) or "unknown"
        pid = _clean_lineage_text(getattr(row, "pid", None))
        image = _clean_lineage_text(getattr(row, "image", None))
        ppid = _clean_lineage_text(getattr(row, "ppid", None))

        if pid and image:
            key = (comp, pid)
            if key in pid_to_image:
                repeated_parent_keys += 1
            pid_to_image[key] = image

        if image:
            image_key = (comp, image)
            if image_key in first_ppid_by_image:
                repeated_image_keys += 1
            else:
                first_ppid_by_image[image_key] = ppid
    t_lookup_maps = time.perf_counter() - phase_started

    phase_started = time.perf_counter()
    grandparent_images: List[Optional[str]] = []
    parent_lookup_count = 0
    grandparent_lookup_count = 0
    resolved_grandparent_count = 0
    for row in working.itertuples(index=False):
        comp = _clean_lineage_text(getattr(row, "computer", None)) or "unknown"
        ppid = _clean_lineage_text(getattr(row, "ppid", None))
        grandparent_image: Optional[str] = None

        if ppid:
            parent_lookup_count += 1
            parent_image = pid_to_image.get((comp, ppid))
            if parent_image:
                grandparent_lookup_count += 1
                next_ppid = first_ppid_by_image.get((comp, parent_image))
                if next_ppid:
                    grandparent_image = pid_to_image.get((comp, next_ppid))
                    if grandparent_image:
                        resolved_grandparent_count += 1

        grandparent_images.append(grandparent_image)
    t_grandparent = time.perf_counter() - phase_started

    phase_started = time.perf_counter()
    working["grandparent_image"] = grandparent_images
    working["process_chain"] = [
        " → ".join(
            part for part in (
                _clean_lineage_text(grandparent_image),
                _clean_lineage_text(getattr(row, "parent_image", None)),
                _clean_lineage_text(getattr(row, "image", None)),
            )
            if part
        )
        for row, grandparent_image in zip(working.itertuples(index=False), grandparent_images)
    ]
    t_chain = time.perf_counter() - phase_started

    phase_started = time.perf_counter()
    process_depths: List[int] = []
    max_depth = 0
    for row, grandparent_image in zip(working.itertuples(index=False), grandparent_images):
        img_b = _basename_lower(getattr(row, "image", None))
        par_b = _basename_lower(getattr(row, "parent_image", None))
        gp_b = _basename_lower(grandparent_image)
        if img_b in BENIGN_PARENTS:
            depth = 0
        elif par_b in BENIGN_PARENTS:
            depth = 1
        elif gp_b in BENIGN_PARENTS:
            depth = 2
        else:
            depth = 3
        process_depths.append(depth)
        if depth > max_depth:
            max_depth = depth
    working["process_depth"] = process_depths
    t_depth = time.perf_counter() - phase_started

    phase_timings = [
        {"phase": "lookup_maps", "elapsed_seconds": round(t_lookup_maps, 6)},
        {"phase": "grandparent_resolution", "elapsed_seconds": round(t_grandparent, 6)},
        {"phase": "process_chain_build", "elapsed_seconds": round(t_chain, 6)},
        {"phase": "process_depth_eval", "elapsed_seconds": round(t_depth, 6)},
    ]
    cumulative_seconds = round(sum(item["elapsed_seconds"] for item in phase_timings), 6)
    slowest_phases = sorted(phase_timings, key=lambda item: item["elapsed_seconds"], reverse=True)
    working.attrs["parent_chain_metrics"] = {
        "event_cardinality": len(working),
        "lineage_traversal_count": parent_lookup_count + grandparent_lookup_count,
        "parent_lookup_count": parent_lookup_count,
        "grandparent_lookup_count": grandparent_lookup_count,
        "resolved_grandparent_count": resolved_grandparent_count,
        "recursion_depth_max": max_depth,
        "dataframe_merge_count": 0,
        "unique_parent_keys": len(pid_to_image),
        "unique_parent_image_keys": len(first_ppid_by_image),
        "repeated_parent_keys": repeated_parent_keys,
        "repeated_parent_image_keys": repeated_image_keys,
        "repeated_query_count": repeated_parent_keys + repeated_image_keys,
        "phase_timings": phase_timings,
        "cumulative_seconds": cumulative_seconds,
        "top_slowest_phases": slowest_phases[:3],
    }
    return working


# ---------------------------------------------------------------------------
# Rule matching (kept for backward compat)
# ---------------------------------------------------------------------------

def _match_rule(event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    raw = event.get("event_id")
    try:
        eid = int(float(raw)) if raw is not None and str(raw) not in ("", "None", "nan") else None
    except (ValueError, TypeError):
        eid = None
    rule_eids = rule.get("event_id", [])
    if rule_eids and eid not in rule_eids:
        return False

    def _sl(v: Any) -> str:
        return str(v).lower() if v and str(v) not in ("", "None", "nan") else ""

    image  = _sl(event.get("image"))
    cmd    = _sl(event.get("command_line"))
    parent = _sl(event.get("parent_image"))
    fpath  = _sl(event.get("file_path") or event.get("target_filename") or event.get("reg_key"))

    if ic := rule.get("image_contains"):
        if ic.lower() not in image:
            return False
    if ia := rule.get("image_any"):
        if image not in [x.lower() for x in ia]:
            return False
    if ca := rule.get("cmd_any"):
        if not any(s.lower() in cmd for s in ca):
            return False
    if pa := rule.get("parent_any"):
        if parent not in [x.lower() for x in pa]:
            return False
    if pp := rule.get("path_prefix_any"):
        if not any(fpath.startswith(x.lower()) for x in pp):
            return False
    if rule.get("filter_benign_parent") and parent in BENIGN_PARENTS:
        return False
    return True
