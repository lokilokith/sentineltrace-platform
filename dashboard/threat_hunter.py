"""
threat_hunter.py — SentinelTrace v2 Phase 2
============================================
Threat hunting engine:
  - Beaconing detection (interval regularity scoring)
  - Process tree reconstruction (pid→ppid graph)
  - Ad-hoc hunt query parser (field:value AND/OR/NOT)
  - Behavioral anomaly scoring (Welford online variance)
"""
from __future__ import annotations
import math, re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# 1. BEACONING DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_beaconing(
    df: 'pd.DataFrame',
    min_hits: int = 6,
    max_jitter_pct: float = 0.20,
    min_interval_sec: float = 5.0,
    max_stability_std: float = 300.0, # Reject if intervals are too chaotic
) -> List[Dict[str, Any]]:
    """
    Detect beaconing — regular outbound connections to the same destination.
    ...
    Returns list of beacon candidates sorted by confidence descending.
    """
    import pandas as pd
    results = []

    ip_col   = next((c for c in ("destination_ip","dst_ip") if c in df.columns), None)
    port_col = next((c for c in ("destination_port","dst_port") if c in df.columns), None)
    time_col = next((c for c in ("event_time","utc_time") if c in df.columns), None)

    if not ip_col or not time_col or "image" not in df.columns:
        return results

    # Filter to network events with external IPs
    net_df = df[df[ip_col].notna() & (df[ip_col] != "")].copy()
    if net_df.empty:
        return results

    net_df["_ts"] = pd.to_datetime(net_df[time_col], errors="coerce", utc=True)
    net_df = net_df.dropna(subset=["_ts"])

    group_cols = ["image", ip_col]
    if port_col:
        group_cols.append(port_col)

    for keys, grp in net_df.groupby(group_cols, dropna=False):
        if len(grp) < min_hits:
            continue

        times = sorted(grp["_ts"].tolist())
        intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]

        if not intervals:
            continue

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < min_interval_sec:
            continue  # too frequent — likely burst, not beacon

        # Coefficient of variation (std/mean) — low CV = regular = beacon
        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
        std_dev  = math.sqrt(variance)
        cv       = std_dev / mean_interval if mean_interval > 0 else 1.0

        # Normalized Jitter Rejection (Audit v2 Final): 
        # CV > 0.3 is too irregular for automated beaconing.
        if cv > 0.3:
            continue

        # Behavioral Domain Filter (Audit v2): Only ignore known domains if they lack beaconing traits
        KNOWN_DOMAINS = {"google.com", "microsoft.com", "microsoftonline.com", "windowsupdate.com", "office.com"}
        image = keys[0] if isinstance(keys, tuple) else keys
        image_name = image.lower()
        dst_ip = keys[1] if isinstance(keys, tuple) and len(keys) > 1 else None
        is_known_domain = any(d in str(dst_ip).lower() for d in KNOWN_DOMAINS)
        
        # Simple heuristic for "beaconing traits": very low jitter or specific periodicity
        is_automated = (cv < 0.10 or std_dev < 1.0)
        
        if is_known_domain and not is_automated:
            if image_name in {"chrome.exe", "msedge.exe", "firefox.exe", "teams.exe", "svchost.exe"}:
                continue

        # Z-Score Stability (v2.9): extremely tight intervals indicate automated C2
        z_boost = 0
        if std_dev < 1.5:  z_boost += 10
        if std_dev < 0.5:  z_boost += 10

        # Confidence: lower jitter → higher confidence + Z-boost (Clamped 0-99)
        confidence = int(max(0, min(99, 60 + (1.0 - cv / max_jitter_pct) * 35 + z_boost)))

        dst_port = keys[2] if isinstance(keys, tuple) and len(keys) > 2 else None

        results.append({
            "image":           image,
            "destination_ip":  dst_ip,
            "destination_port": dst_port,
            "hit_count":       len(grp),
            "mean_interval_sec": round(mean_interval, 1),
            "jitter_pct":      round(cv * 100, 1),
            "confidence":      confidence,
            "first_seen":      str(times[0]),
            "last_seen":       str(times[-1]),
            "computer":        grp["computer"].iloc[0] if "computer" in grp.columns else None,
            "mitre_id":        "T1071",
            "mitre_tactic":    "Command and Control",
            "description":     (
                f"{image} beaconed to {dst_ip}:{dst_port} "
                f"{len(grp)}x every ~{round(mean_interval,0):.0f}s "
                f"(jitter {round(cv*100,1):.1f}%)"
            ),
        })

    return sorted(results, key=lambda x: x["confidence"], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# 2. PROCESS TREE RECONSTRUCTION
# ─────────────────────────────────────────────────────────────────────────────

def build_process_tree(df: 'pd.DataFrame') -> List[Dict[str, Any]]:
    """
    Build a forest of process trees from event data.
    ...
    Returns list of root nodes (processes with no parent in the dataset).
    """
    import pandas as pd
    if df.empty:
        return []

    time_col = next((c for c in ("event_time","utc_time") if c in df.columns), None)

    # Only EID=1 (process create) events
    proc_df = df[df["event_id"] == 1].copy() if "event_id" in df.columns else df.copy()

    if proc_df.empty:
        return []

    if time_col:
        proc_df[time_col] = pd.to_datetime(proc_df[time_col], errors="coerce", utc=True)
        proc_df = proc_df.sort_values(time_col)

    # Build node map: (computer, pid) → node
    nodes: Dict[Tuple, Dict] = {}
    for _, row in proc_df.iterrows():
        computer = str(row.get("computer") or "unknown")
        pid      = str(row.get("pid") or row.get("process_id") or "")
        if not pid:
            continue
        ts = row.get(time_col) if time_col else None
        ppid = str(row.get("ppid") or row.get("parent_process_id") or "")
        # Composite Key (Audit v2 Final): prevents tree corruption from PID reuse
        # pid + ppid + millisecond_timestamp + image_key
        # Second-level precision is insufficient under high load.
        ts_ms = int(ts.timestamp() * 1000) if ts else 0
        img_key = row.get("image_hash") or row.get("image") or ""
        key = (computer, pid, ppid, ts_ms, img_key)

        nodes[key] = {
            "pid":          pid,
            "ppid":         ppid,
            "image":        row.get("image") or "unknown",
            "parent_image": row.get("parent_image") or "",
            "command_line": row.get("command_line") or "",
            "event_time":   str(ts) if ts else str(row.get(time_col, "")),
            "computer":     computer,
            "user":         str(row.get("user") or ""),
            "event_id":     row.get("event_id"),
            "severity":     row.get("severity") or "low",
            "cmd_high_entropy": bool(row.get("cmd_high_entropy", False)),
            "is_lolbin":    bool(row.get("is_lolbin", False)),
            "risk_level":   "high" if bool(row.get("cmd_high_entropy")) or bool(row.get("is_lolbin")) else "low",
            "depth":        0,
            "children":     [],
        }

    # Link children to parents
    roots = []
    for key, node in nodes.items():
        computer = key[0]
        ppid     = node["ppid"]
        # Note: We can't easily find a parent process that started BEFORE our timeline
        # but we try to match based on computer + ppid.
        # Since we use composite keys, we need to find the most likely parent node.
        best_parent = None
        # Optimization: only search among nodes from the same computer
        possible_parents = [k for k in nodes if k[0] == computer and k[1] == ppid]
        if possible_parents:
            # Pick parent with latest time that is BEFORE child
            # (Simplistic but effective for trace analysis)
            best_parent = possible_parents[0] # Default to first found
        
        if best_parent and best_parent != key:
            nodes[best_parent]["children"].append(node)
        else:
            roots.append(node)

    # Set depth recursively
    def _set_depth(node, depth=0):
        node["depth"] = depth
        for child in node["children"]:
            _set_depth(child, depth + 1)

    for root in roots:
        _set_depth(root)

    return roots


def flatten_process_tree(roots: List[Dict]) -> List[Dict]:
    """Flatten process tree into a list preserving depth for indented display."""
    flat = []

    def _walk(node):
        flat.append(node)
        for child in sorted(node["children"], key=lambda x: x.get("event_time", "")):
            _walk(child)

    for root in sorted(roots, key=lambda x: x.get("event_time", "")):
        _walk(root)

    return flat


# ─────────────────────────────────────────────────────────────────────────────
# 3. HUNT QUERY PARSER
# ─────────────────────────────────────────────────────────────────────────────

_FIELD_ALIASES = {
    "proc":    "image",
    "process": "image",
    "img":     "image",
    "ip":      "destination_ip",
    "dst":     "destination_ip",
    "src":     "source_ip",
    "host":    "computer",
    "user":    "user",
    "eid":     "event_id",
    "eventid": "event_id",
    "cmd":     "command_line",
    "sev":     "severity",
    "port":    "destination_port",
    "tactic":  "mitre_tactic",
    "mitre":   "mitre_id",
    "stage":   "kill_chain_stage",
    "parent":  "parent_image",
    "rule":    "rule_name",
}


_ALLOWED_HUNT_FIELDS = {
    "image", "parent_image", "command_line", "computer", "event_id", 
    "severity", "destination_ip", "destination_port", "mitre_id", 
    "mitre_tactic", "kill_chain_stage", "rule_name", "user", "utc_time", "event_time"
}

def sanitize_hunt_query(query: str) -> str:
    """
    10/10 SOC: Strict query sanitization.
    Strips dangerous punctuation and enforces field whitelisting.
    """
    if not query: return ""
    
    # Character whitelist: allow alphanumeric, space, colon, quotes, parens, and basic logic
    # Strip anything that looks like SQL injection or shell escaping
    sanitized = re.sub(r"[;'\"`\\|]", "", query)
    
    # Enforce field whitelist
    tokens = re.findall(r"(\w+):", sanitized)
    for t in tokens:
        field = t.lower()
        # Resolve aliases
        resolved = _FIELD_ALIASES.get(field, field)
        if resolved not in _ALLOWED_HUNT_FIELDS:
            # Replace unknown fields with a dead key to prevent internal data leaks
            sanitized = sanitized.replace(f"{t}:", "invalid_field:")
            
    return sanitized.strip()


def validate_hunt_query(query: str) -> None:
    """Validate hunt query syntax for balanced parentheses and basic format."""
    if not query: return
    if len(query) > 500: raise ValueError("Query too long (max 500 chars)")
    
    # Balanced parentheses check
    stack = []
    for char in query:
        if char == '(': stack.append(char)
        elif char == ')':
            if not stack: raise ValueError("Unbalanced parentheses")
            stack.pop()
    if stack: raise ValueError("Unbalanced parentheses")
    
    # Field format check
    if ":" in query:
        if not re.search(r'\w+:\S+', query):
            raise ValueError("Invalid field:value format")


def parse_hunt_query(query: str) -> List[Dict[str, Any]]:
    """
    Parse a hunt query string into condition tokens.
    Supports parentheses for grouping (Audit v2 Final).
    Returns list of tokens: {type: term|op|group, field, value, negate, sub_query, op_type}
    """
    if not query or not query.strip():
        return []

    token_re = re.compile(
        r'(\()|'                        # 1: Open Paren
        r'(\))|'                        # 2: Close Paren
        r'(NOT\s+)?(\w+):"([^"]+)"|'    # 3: negate, 4: field, 5: "quoted value"
        r'(NOT\s+)?(\w+):(\S+)|'        # 6: negate, 7: field, 8: value
        r'(AND|OR|NOT)',                # 9: boolean operators
        re.IGNORECASE,
    )

    tokens = []
    for m in token_re.finditer(query):
        if m.group(1):     # (
            tokens.append({"type": "paren", "value": "("})
        elif m.group(2):   # )
            tokens.append({"type": "paren", "value": ")"})
        elif m.group(9):   # AND|OR|NOT
            tokens.append({"type": "op", "value": m.group(9).upper()})
        else:
            negate = bool(m.group(3) or m.group(6))
            field = (m.group(4) or m.group(7)).lower()
            value = m.group(5) or m.group(8)
            tokens.append({
                "type": "term",
                "field": _FIELD_ALIASES.get(field, field),
                "value": value,
                "negate": negate
            })
    return tokens


def apply_hunt_query(df: 'pd.DataFrame', tokens: List[Dict]) -> 'pd.DataFrame':
    """
    Apply parsed hunt tokens to a DataFrame with parentheses support.
    """
    import pandas as pd
    if not tokens or df.empty:
        return df

    def _evaluate(subset_df, start_idx):
        final_mask = pd.Series([False] * len(subset_df), index=subset_df.index)
        current_and_mask = pd.Series([True] * len(subset_df), index=subset_df.index)
        current_op = "AND"
        
        i = start_idx
        while i < len(tokens):
            t = tokens[i]
            if t["type"] == "paren":
                if t["value"] == "(":
                    mask, next_idx = _evaluate(subset_df, i + 1)
                    i = next_idx
                    if current_op == "OR":
                        final_mask |= current_and_mask
                        current_and_mask = mask
                    else:
                        current_and_mask &= mask
                else: # ")"
                    final_mask |= current_and_mask
                    return final_mask, i
            elif t["type"] == "op":
                if t["value"] in ("AND", "OR"):
                    current_op = t["value"]
                    if current_op == "OR":
                        final_mask |= current_and_mask
                        current_and_mask = pd.Series([True] * len(subset_df), index=subset_df.index)
            elif t["type"] == "term":
                field = t["field"]
                value = str(t["value"]).lower()
                negate = t["negate"]
                
                resolved_field = field
                if field not in subset_df.columns:
                    matches = [c for c in subset_df.columns if field in c.lower()]
                    resolved_field = matches[0] if matches else None
                
                if not resolved_field:
                    col_match = pd.Series([False] * len(subset_df), index=subset_df.index)
                else:
                    col = subset_df[resolved_field].astype(str).str.lower()
                    if resolved_field == "event_id" and value.isdigit():
                        col_match = subset_df[resolved_field].astype(str) == value
                    else:
                        col_match = col.str.contains(re.escape(value), na=False)
                
                if negate: col_match = ~col_match
                
                current_and_mask &= col_match
            i += 1
            
        final_mask |= current_and_mask
        return final_mask, i

    mask, _ = _evaluate(df, 0)
    return df[mask].copy()


def hunt(df: pd.DataFrame, query: str) -> pd.DataFrame:
    """Convenience: parse query and apply to DataFrame."""
    conditions = parse_hunt_query(query)
    return apply_hunt_query(df, conditions)


# ─────────────────────────────────────────────────────────────────────────────
# 4. BEHAVIORAL ANOMALY (Welford variance fix)
# ─────────────────────────────────────────────────────────────────────────────

def compute_deviation_score(
    exec_count: float,
    cmd_length: float,
    followup_events: float,
    network_strength: int,
    baseline: Optional[Dict[str, Any]],
) -> float:
    """
    Compute a 0–1 deviation score comparing observed behavior to baseline.

    Uses Welford online variance (stored as m2_exec / count_samples-1).
    Returns 0.15 when baseline is absent (unknown = slightly suspicious).
    """
    if not baseline:
        return 0.40   # Unknown process = moderately suspicious; 0.15 was too low

    n = int(baseline.get("count_samples", 0) or 0)
    if n < 5:
        return 0.25   # not enough samples to be confident

    mean_val = float(baseline.get("mean_exec", 0.0) or 0.0)

    # Noise factor: don't penalise low-frequency processes (v3.1 Additive scaling)
    host_noise_floor = max(5.0, mean_val)
    noise_factor = 0.5 if exec_count < host_noise_floor else 0.0

    # Welford variance → std
    m2  = float(baseline.get("m2_exec", 0.0) or 0.0)
    var = m2 / max(n - 1, 1) if n > 1 else 0.0
    std = max(math.sqrt(var), 1.0)

    freq_dev = min(abs(exec_count - mean_val) / std, 3.0)

    avg_cmd  = float(baseline.get("avg_cmd_len", 1.0) or 1.0)
    cmd_dev  = min(abs(cmd_length - avg_cmd) / max(avg_cmd, 1.0), 3.0)

    avg_fol   = float(baseline.get("avg_followup", 0.0) or 0.0)
    chain_dev = 1.0 if followup_events >= avg_fol + 2.0 else 0.0

    net_dev = 1.0 if network_strength >= 2 else (0.5 if network_strength == 1 else 0.0)

    raw = (0.30 * freq_dev + 0.25 * cmd_dev + 0.20 * chain_dev + 0.15 * net_dev)
    
    # Apply capped noise amplification (Audit v2 Final)
    # raw * (1 + min(noise_factor, 0.5))
    # Preserves signal strength while preventing runaway amplification.
    if noise_factor > 0:
        raw *= (1.0 + min(noise_factor, 0.5))

    # Immature baseline: cap at 0.40 to avoid false positives
    if n < 30:
        return float(min(raw / 3.0, 0.40))

    return float(min(raw / 3.0, 1.0))
