"""
soc_verdict.py — SentinelTrace v2 Phase 3
==========================================
SOC Analyst Verdict System:
  - Incident state machine with valid transitions + SLA timers
  - Structured verdict with mandatory reason
  - IOC extraction from events
  - Analyst audit trail
  - Risk score breakdown/explainability
"""
from __future__ import annotations
import datetime, hashlib, re, uuid
from typing import Any, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# 1. INCIDENT STATE MACHINE
# ─────────────────────────────────────────────────────────────────────────────

# Valid status transitions: current_status → set of allowed next statuses
VALID_TRANSITIONS: Dict[str, set] = {
    "New":                  {"Triage", "Closed - False Positive"},
    "Triage":               {"Investigating", "Closed - False Positive", "Closed - Benign"},
    "Investigating":        {"Escalated", "Closed - True Positive", "Closed - False Positive", "Closed - Benign"},
    "Escalated":            {"Closed - True Positive", "Closed - False Positive"},
    "Closed - True Positive":  set(),   # terminal
    "Closed - False Positive": set(),   # terminal
    "Closed - Benign":         set(),   # terminal
}

# ── [10/10] Exhaustive Immutable Status Set ───────────────────────────────
VALID_STATUSES = frozenset(
    set(VALID_TRANSITIONS.keys()) |
    {s for v in VALID_TRANSITIONS.values() for s in v}
)

# SLA deadlines by priority (hours until breach)
SLA_HOURS: Dict[str, int] = {
    "P1": 1,    # Critical — 1 hour
    "P2": 4,    # High — 4 hours
    "P3": 24,   # Medium — 24 hours
    "P4": 72,   # Low — 72 hours
}

# Confidence → priority mapping
def score_to_priority(confidence: int) -> str:
    if confidence >= 80: return "P1"
    if confidence >= 60: return "P2"
    if confidence >= 40: return "P3"
    return "P4"


def validate_transition(current: str, next_status: str) -> Tuple[bool, str]:
    """
    Validate a status transition.
    Returns (is_valid, error_message).
    """
    allowed = VALID_TRANSITIONS.get(current, set())
    if next_status in allowed:
        return True, ""
    if not allowed:
        return False, f"'{current}' is a terminal state — no further transitions allowed."
    return False, (
        f"Cannot transition from '{current}' to '{next_status}'. "
        f"Allowed: {', '.join(sorted(allowed))}"
    )


def compute_sla_deadline(priority: str, created_at: Optional[datetime.datetime] = None) -> datetime.datetime:
    if created_at is None:
        created_at = datetime.datetime.now(tz=datetime.timezone.utc)
    hours = SLA_HOURS.get(priority, 72)
    return created_at + datetime.timedelta(hours=hours)


def sla_status(deadline: datetime.datetime) -> Dict[str, Any]:
    """Return SLA status dict for display."""
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if deadline.tzinfo is None or deadline.tzinfo.utcoffset(deadline) is None:
        deadline = deadline.replace(tzinfo=datetime.timezone.utc)
    remaining = deadline - now
    breached  = remaining.total_seconds() < 0
    hours_rem = abs(remaining.total_seconds()) / 3600
    return {
        "breached":      breached,
        "deadline":      deadline.isoformat(),
        "hours_remaining": round(hours_rem, 1) if not breached else 0,
        "hours_overdue":   round(hours_rem, 1) if breached else 0,
        "label":          ("BREACHED" if breached
                           else f"{hours_rem:.1f}h remaining"),
        "color":          ("red" if breached
                           else "orange" if hours_rem < 2
                           else "yellow" if hours_rem < 8
                           else "green"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2. STRUCTURED VERDICT
# ─────────────────────────────────────────────────────────────────────────────

# ── [10/10] Immutable Verdict Definitions ───────────────────────────────
VERDICT_OPTIONS = (
    "True Positive — Confirmed Attack",
    "True Positive — Attempted Attack",
    "False Positive — Legitimate Activity",
    "False Positive — Misconfigured Rule",
    "Benign — Known Tool",
    "Benign — Authorized Test",
    "Insufficient Evidence",
)

REMEDIATION_CHECKLIST = {
    "True Positive — Confirmed Attack": [
        "Isolate affected host from network",
        "Preserve disk image and memory dump",
        "Reset credentials for affected users",
        "Block IOCs at firewall and DNS",
        "Notify security management",
        "File incident report",
        "Initiate threat hunting on lateral movement",
    ],
    "True Positive — Attempted Attack": [
        "Block source IPs/domains at perimeter",
        "Review similar hosts for same indicators",
        "Tune detection rule confidence",
        "Document attack vector for lessons learned",
    ],
    "False Positive — Legitimate Activity": [
        "Update rule exclusion for this host/user",
        "Document baseline deviation reason",
    ],
    "False Positive — Misconfigured Rule": [
        "Disable or tune the triggering rule",
        "Submit rule improvement to threat intel team",
    ],
    "Benign — Known Tool": [
        "Whitelist process/host combination",
        "Update baseline model",
    ],
    "Benign — Authorized Test": [
        "Document test window and scope",
        "No action required",
    ],
}


def create_verdict(
    incident_id: str,
    analyst_id: str,
    verdict: str,
    reason: str,
    evidence_event_uids: Optional[List[str]] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a structured verdict record.
    Validates that mandatory reason is provided.
    """
    if verdict not in VERDICT_OPTIONS:
        raise ValueError(
            f"Invalid verdict '{verdict}'. "
            f"Must be one of: {VERDICT_OPTIONS}"
        )
    if not reason or len(reason.strip()) < 10:
        raise ValueError(
            "Verdict reason is mandatory and must be at least 10 characters. "
            "Describe WHY this is the conclusion."
        )

    checklist = REMEDIATION_CHECKLIST.get(verdict, [])
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    return {
        "verdict_id":       f"VRD-{uuid.uuid4().hex[:8].upper()}",
        "incident_id":      incident_id,
        "analyst_id":       analyst_id,
        "verdict":          verdict,
        "reason":           reason.strip(),
        "evidence_uids":    evidence_event_uids or [],
        "notes":            (notes or "").strip(),
        "remediation":      checklist,
        "created_at":       now.isoformat(),
        "is_true_positive": verdict.startswith("True Positive"),
        "is_false_positive": verdict.startswith("False Positive"),
        "requires_action":  verdict.startswith("True Positive"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 3. IOC EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

# Regex patterns for IOC types
_IPV4_RE    = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_DOMAIN_RE  = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|cc|xyz|top|info|biz|club|online|site|store|pw|me|co)\b', re.IGNORECASE)
_MD5_RE     = re.compile(r'\b[0-9a-fA-F]{32}\b')
_SHA1_RE    = re.compile(r'\b[0-9a-fA-F]{40}\b')
_SHA256_RE  = re.compile(r'\b[0-9a-fA-F]{64}\b')
_URL_RE     = re.compile(r'https?://[^\s\'">\]]+', re.IGNORECASE)

# Known safe IPs (don't extract these)
_SAFE_IPS = frozenset({
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
})

# RFC-1918 private ranges (don't extract as external IOCs)
def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168) or
                a == 127)
    except ValueError:
        return False


def extract_iocs(events: List[Dict[str, Any]], run_id: str = "") -> List[Dict[str, Any]]:
    """
    Extract IOCs from a list of event dicts.

    Extracts: IP addresses, domains, file hashes (MD5/SHA1/SHA256), URLs.
    De-duplicates by (type, value).
    Excludes private/safe IPs.

    Returns list of IOC dicts.
    """
    seen: set = set()
    iocs: List[Dict] = []

    def _add(ioc_type: str, value: str, source_event_uid: str, source_field: str):
        key = (ioc_type, value.lower())
        if key in seen:
            return
        seen.add(key)
        iocs.append({
            "ioc_id":       f"IOC-{hashlib.sha256(f'{ioc_type}:{value}'.encode()).hexdigest()[:12]}",
            "ioc_type":     ioc_type,
            "ioc_value":    value,
            "source_uid":   source_event_uid,
            "source_field": source_field,
            "run_id":       run_id,
            "confidence":   70,
            "first_seen":   datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
        })

    for ev in events:
        uid = ev.get("event_uid", "")

        # IP addresses
        for field in ("destination_ip", "dst_ip", "source_ip", "src_ip"):
            ip = str(ev.get(field) or "").strip()
            if ip and ip not in _SAFE_IPS and not _is_private(ip):
                if _IPV4_RE.match(ip):
                    _add("ip", ip, uid, field)

        # Hashes
        hashes_str = str(ev.get("hashes") or "")
        for h in _SHA256_RE.findall(hashes_str): _add("sha256", h.lower(), uid, "hashes")
        for h in _SHA1_RE.findall(hashes_str):   _add("sha1",   h.lower(), uid, "hashes")
        for h in _MD5_RE.findall(hashes_str):    _add("md5",    h.lower(), uid, "hashes")

        # URLs and domains in command_line
        cmd = str(ev.get("command_line") or "")
        for url in _URL_RE.findall(cmd):
            _add("url", url, uid, "command_line")

        for domain in _DOMAIN_RE.findall(cmd):
            if len(domain) > 4 and "." in domain:
                _add("domain", domain.lower(), uid, "command_line")

        # Domains in dns_query field
        dns = str(ev.get("dns_query") or "")
        if dns and len(dns) > 4 and "." in dns:
            for domain in _DOMAIN_RE.findall(dns):
                _add("domain", domain.lower(), uid, "dns_query")

    return sorted(iocs, key=lambda x: x["ioc_type"])


# ─────────────────────────────────────────────────────────────────────────────
# 4. RISK SCORE BREAKDOWN (explainability)
# ─────────────────────────────────────────────────────────────────────────────

def explain_risk_score(burst: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decompose a burst risk score into contributing factors.

    v2: When `score_ledger` is present (written by scoring_engine.ScoringEngine),
    we use the authoritative ledger directly — no reconstruction guesswork.
    v1 fallback: manual factor reconstruction for legacy bursts without ledger.

    Returns a breakdown dict consumed by /api/score-breakdown/<run_id> and
    the dashboard burst detail panels.
    """
    score      = int(burst.get("risk_score", 0) or 0)
    deviation  = float(burst.get("deviation_score", 0.0) or 0.0)
    stage      = burst.get("kill_chain_stage", "Execution") or "Execution"
    reasons    = burst.get("confidence_reasons", []) or []
    chain_depth = int(burst.get("chain_depth") or burst.get("chain_multiplier") or 1)

    # ── v2 path: authoritative score_ledger from ScoringEngine ──────────
    score_ledger = burst.get("score_ledger")
    if score_ledger:
        factors = []
        for entry in score_ledger:
            delta = float(entry.get("delta", 0) or 0)
            label = str(entry.get("label", ""))
            reason_txt = str(entry.get("reason", ""))
            if delta == 0:
                continue   # informational entries (multipliers, caps) shown in reasons
            color = "red" if delta >= 20 else "orange" if delta >= 10 else "yellow" if delta >= 5 else "green"
            if delta < 0:
                color = "gray"   # cap / suppression
            factors.append({"label": label, "value": round(delta, 1), "color": color})

        sub_scores  = burst.get("baseline_sub_scores", {}) or {}
        anomalies   = burst.get("baseline_anomalies", []) or []
        suggestions = []
        if not burst.get("has_persistence"):
            suggestions.append("Persistence indicator would raise stage cap and add +15")
        if not burst.get("has_injection"):
            suggestions.append("Process injection evidence adds +25 directly")
        if deviation < 0.6:
            suggestions.append("Higher behavioral deviation lifts score ceiling")
        if not burst.get("has_correlation"):
            suggestions.append("Multi-stage correlation enables chain depth multiplier")
        if chain_depth < 2:
            suggestions.append("Second kill-chain stage triggers nonlinear interaction bonus (+8–15)")

        return {
            "score":        score,
            "stage":        stage,
            "stage_cap":    int(burst.get("stage_cap") or 100),
            "deviation":    round(deviation, 3),
            "chain_depth":  chain_depth,
            "factors":      factors,
            "factor_sum":   sum(f["value"] for f in factors if f["value"] > 0),
            "suggestions":  suggestions,
            "reasons":      reasons,
            "anomalies":    anomalies,
            "sub_scores":   sub_scores,   # frequency/parent/sequence/entropy/time/network
            "alertable":    score >= 40,
            "source":       "v2_ledger",
        }

    # ── v1 fallback: manual reconstruction ───────────────────────────────
    exec_count      = int(burst.get("exec_event_count", burst.get("count", 0)) or 0)
    has_persistence = bool(burst.get("has_persistence"))
    has_injection   = bool(burst.get("has_injection"))
    has_net         = bool(burst.get("has_net"))
    has_correlation = bool(burst.get("has_correlation"))

    factors = []
    if exec_count >= 1000:
        factors.append({"label": "Event volume (1000+)", "value": 20, "color": "red"})
    elif exec_count >= 100:
        factors.append({"label": f"Event volume ({exec_count})", "value": 15, "color": "orange"})
    elif exec_count >= 10:
        factors.append({"label": f"Event volume ({exec_count})", "value": 10, "color": "yellow"})
    elif exec_count >= 1:
        factors.append({"label": f"Event volume ({exec_count})", "value": 5, "color": "green"})

    if deviation >= 0.8:
        factors.append({"label": f"Deviation score ({deviation:.2f})", "value": 25, "color": "red"})
    elif deviation >= 0.6:
        factors.append({"label": f"Deviation score ({deviation:.2f})", "value": 15, "color": "orange"})
    elif deviation >= 0.3:
        factors.append({"label": f"Deviation score ({deviation:.2f})", "value": 8, "color": "yellow"})

    stage_scores = {
        "Actions on Objectives": 30, "Command and Control": 25,
        "Persistence": 20, "Privilege Escalation": 20,
        "Defense Evasion": 15, "Execution": 10,
    }
    if stage in stage_scores:
        v = stage_scores[stage]
        factors.append({"label": f"Kill chain: {stage}", "value": v,
                        "color": "red" if v >= 20 else "orange" if v >= 15 else "yellow"})

    if has_persistence:  factors.append({"label": "Persistence mechanism", "value": 15, "color": "red"})
    if has_injection:    factors.append({"label": "Process injection",      "value": 25, "color": "red"})
    if has_net:          factors.append({"label": "Network activity",       "value": 10, "color": "orange"})
    if has_correlation:  factors.append({"label": "Multi-stage correlation","value": 20, "color": "red"})

    suggestions = []
    if not has_persistence: suggestions.append("Persistence indicator would add +15")
    if not has_injection:   suggestions.append("Process injection evidence would add +25")
    if deviation < 0.6:     suggestions.append("Higher behavioral deviation would add +15")
    if not has_correlation: suggestions.append("Multi-stage correlation would add +20")

    return {
        "score":       score,
        "stage":       stage,
        "stage_cap":   int(burst.get("stage_cap") or 100),
        "deviation":   round(deviation, 3),
        "chain_depth": chain_depth,
        "factors":     factors,
        "factor_sum":  sum(f["value"] for f in factors),
        "suggestions": suggestions,
        "reasons":     reasons,
        "anomalies":   [],
        "sub_scores":  {},
        "alertable":   score >= 40,
        "source":      "v1_legacy",
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5. AUDIT TRAIL
# ─────────────────────────────────────────────────────────────────────────────

def create_audit_entry(
    analyst_id: str,
    action: str,
    target_type: str,
    target_id: str,
    detail: str = "",
    ip_address: str = "",
) -> Dict[str, Any]:
    return {
        "audit_id":    f"AUD-{uuid.uuid4().hex[:8]}",
        "analyst_id":  analyst_id,
        "action":      action,
        "target_type": target_type,
        "target_id":   target_id,
        "detail":      detail,
        "ip_address":  ip_address,
        "ts":          datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
    }
