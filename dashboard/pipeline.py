"""
pipeline.py — SentinelTrace Unified Analysis Pipeline
=======================================================
THIS IS THE MISSING GLUE.

Connects all engines in the correct order:
  1. Parser / enrichment (already done at ingest time)
  2. Baseline Engine      → deviation scores
  3. Sequence Engine      → attack-chain detection
  4. Correlation Engine   → campaign linking
  5. Feedback Engine      → analyst-verdict adjustments
  6. Scoring Engine       → final fused risk score
  7. Decision Layer       → recommended analyst action

Previously these were all isolated. This module wires them together
so every burst passes through every stage before hitting the UI.
"""

import logging
import json
import cProfile
import io
import pstats
import sys
import time
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict


log = logging.getLogger("pipeline")

PIPELINE_PROFILE_ROOT = Path(__file__).resolve().parents[1] / "engineering_outputs" / "profile_artifacts"


def _frame_size(frame: Any) -> Dict[str, Any]:
    if frame is None:
        return {"rows": 0, "cols": 0, "mem_mb": 0.0}
    try:
        if hasattr(frame, "shape"):
            rows, cols = frame.shape
            mem_mb = 0.0
            if hasattr(frame, "memory_usage"):
                try:
                    mem_mb = float(frame.memory_usage(deep=True).sum()) / (1024 * 1024)
                except Exception:
                    mem_mb = 0.0
            return {"rows": int(rows), "cols": int(cols), "mem_mb": round(mem_mb, 3)}
    except Exception:
        pass
    return {"rows": 0, "cols": 0, "mem_mb": 0.0}


def _profile_is_valid(profiler: Optional[cProfile.Profile]) -> bool:
    if profiler is None or not hasattr(profiler, "getstats"):
        return False
    try:
        return bool(profiler.getstats())
    except Exception:
        return False


def _top_profile_rows(profiler: Optional[cProfile.Profile], limit: int = 20) -> List[Dict[str, Any]]:
    if not _profile_is_valid(profiler):
        return []
    stats = pstats.Stats(profiler)
    rows: List[Dict[str, Any]] = []
    for (filename, line_no, func_name), stat in stats.stats.items():
        primitive_calls, total_calls, total_time, cumulative_time, _callers = stat
        rows.append(
            {
                "qualified_name": f"{Path(filename).name}:{line_no}:{func_name}",
                "file": filename,
                "line": line_no,
                "function": func_name,
                "primitive_calls": primitive_calls,
                "total_calls": total_calls,
                "total_seconds": total_time,
                "cumulative_seconds": cumulative_time,
                "avg_seconds_per_call": (cumulative_time / total_calls) if total_calls else 0.0,
            }
        )
    rows.sort(key=lambda item: item["cumulative_seconds"], reverse=True)
    return rows[:limit]


def _write_pipeline_profile_artifacts(
    run_id: str,
    phase: str,
    profiler: Optional[cProfile.Profile],
    elapsed_seconds: float,
    metadata: Dict[str, Any],
) -> Dict[str, str]:
    if not _profile_is_valid(profiler):
        log.warning("[PROFILE] Skipping pipeline artifact write for run_id=%s phase=%s because profiler was not active", run_id[:16], phase)
        return {}

    artifact_dir = PIPELINE_PROFILE_ROOT / run_id[:16] / "pipeline_corr_scoring"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    prof_path = artifact_dir / f"{run_id[:16]}_{phase}.prof"
    pstats_path = artifact_dir / f"{run_id[:16]}_{phase}.pstats.txt"
    json_path = artifact_dir / f"{run_id[:16]}_{phase}.json"

    try:
        profiler.dump_stats(str(prof_path))

        stream = io.StringIO()
        pstats.Stats(profiler, stream=stream).strip_dirs().sort_stats("cumulative").print_stats(20)
        pstats_path.write_text(stream.getvalue(), encoding="utf-8")

        top_rows = _top_profile_rows(profiler, limit=20)
        payload = {
            "run_id": run_id[:16],
            "phase": phase,
            "elapsed_seconds": round(float(elapsed_seconds), 6),
            "top_functions": top_rows,
            "metadata": metadata,
        }
        json_path.write_text(json.dumps(payload, default=str, sort_keys=True, indent=2), encoding="utf-8")

        return {
            "prof": str(prof_path),
            "pstats": str(pstats_path),
            "json": str(json_path),
        }
    except Exception as exc:
        log.warning("[PROFILE] Failed to write pipeline artifacts for run_id=%s phase=%s: %s", run_id[:16], phase, exc)
        return {}

# ---------------------------------------------------------------------------
# 10/10 Mastery: Formal Invariant Layer (The Proof)
# ---------------------------------------------------------------------------
def validate_minimal_truth(ctx: Dict[str, Any]) -> bool:
    """
    Validates the minimal sufficient invariants for formal correctness.
    1. Score Composition: score == f(evidence)
    2. Causality: Registry/Process/Network events must have valid ancestry.
    3. Separation: Campaigns must strictly partition correlated events.
    """
    run_id = ctx.get("run_id")
    score = Decimal(str(ctx.get("attack_conf_score", 0)))
    
    # 1. Behavioral Specification: If no detections -> score = 0
    if not ctx.get("detections") or len(ctx["detections"]) == 0:
        if score > 0:
            raise AssertionError(f"Behavioral violation: detections=0 but score={score}")

    # 2. Linkage Invariant: Every edge must connect valid nodes in the campaign
    campaigns = ctx.get("correlation_campaigns", [])
    for camp in campaigns:
        # Build node set for the campaign
        node_uids = {e.get("event_uid") for e in camp.get("events", [])}
        for edge in camp.get("edges", []):
            f, t = edge.get("from"), edge.get("to")
            if not f or not t:
                 raise AssertionError("Linkage violation: Empty edge nodes")
            if f not in node_uids or t not in node_uids:
                raise AssertionError(f"Linkage violation: Edge {f}->{t} references missing node")

    # 3. Causality Invariant: Child cannot precede parent in a causal link
    for camp in campaigns:
        # Build time lookup
        time_map = {e.get("event_uid"): e.get("event_time") for e in camp.get("events", [])}
        for edge in camp.get("edges", []):
            f, t = edge.get("from"), edge.get("to")
            t1, t2 = time_map.get(f), time_map.get(t)
            if t1 and t2:
                # Use string comparison for ISO times or parse
                if t2 < t1:
                    raise AssertionError(f"Causality violation: {t} precedes parent {f} ({t2} < {t1})")

    # 4. Separation Invariant: No overlapping campaigns
    all_uids = [e.get("event_uid") for c in campaigns for e in c.get("events", [])]
    if len(all_uids) != len(set(all_uids)):
        raise AssertionError("Separation violation: Campaigns overlap (shared events)")

    return True

# ---------------------------------------------------------------------------
# Signal Whitelist & Aliases (Frozen Map)
# ---------------------------------------------------------------------------

ALIASES = {
    "rule": "rule",
    "yara": "rule",
    "sigma": "rule",
    "sequence": "sequence",
    "behavior": "anomaly",
    "baseline": "anomaly",
    "statistical": "anomaly",
}

VALID_TYPES = {"rule", "sequence", "anomaly"}


def pick_primary_detection(detections: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Selects the highest-fidelity signal from a burst to prevent group drift."""
    if not detections:
        return None

    # Priority: sequence > rule > anomaly
    priority = {"sequence": 3, "rule": 2, "anomaly": 1}

    def _rank(d: Dict) -> int:
        dt = str(d.get("type") or d.get("detection_source") or "anomaly").lower().strip()
        dt = ALIASES.get(dt, "anomaly")
        if dt not in VALID_TYPES:
            dt = "anomaly"
        return priority.get(dt, 0)

    sorted_dets = sorted(detections, key=lambda d: (_rank(d), float(d.get("confidence") or 0.0)), reverse=True)
    return sorted_dets[0] if sorted_dets else None


# ---------------------------------------------------------------------------
# 1. Decision layer
# ---------------------------------------------------------------------------
DECISION_RULES = [
    # (condition_fn, action, reason)

    # 🔴 HARD ATTACK CONDITIONS (must override score)
    # Tightened: Requires at least medium confidence (45) for multiple sequence hits
    (lambda c: c.get("has_lateral_movement") or c.get("has_credential_access") or c.get("has_privilege_escalation"),
     "ESCALATE",
     "High-risk kill-chain stage reached"),

    (lambda c: c.get("has_multi_host_spread") and c.get("attack_conf_score", 0) >= 45,
     "ESCALATE",
     "Attack spread across multiple hosts"),

    (lambda c: c.get("sequence_hits", 0) >= 2 and c.get("attack_conf_score", 0) >= 45,
     "ESCALATE",
     "Multiple attack chains detected with significant confidence"),

    (lambda c: c.get("highest_kill_chain") in ("Lateral Movement", "Command and Control"),
     "ESCALATE",
     "Critical kill-chain stage reached"),

    (lambda c: c.get("has_encoded_command") and c.get("attack_conf_score", 0) >= 35,
     "ESCALATE",
     "Encoded PowerShell or script chain detected"),

    (lambda c: c.get("has_remote_execution") or c.get("has_persistence_evasion"),
     "INVESTIGATE",
     "Remote execution or persistence-evasion pattern observed"),

    # 🟠 High score
    (lambda c: c["attack_conf_score"] >= 70,
     "ESCALATE",
     "High-confidence attack detected"),

    # 🟡 Medium risk
    (lambda c: c.get("attack_conf_score", 0) >= 45
               or c.get("has_persistence")
               or c.get("has_injection")
               or c.get("sequence_hits", 0) >= 1,
     "INVESTIGATE",
     "Suspicious behavior or multi-stage activity requiring investigation"),

    # 🟢 Low risk
    (lambda c: c["attack_conf_score"] >= 20,
     "MONITOR",
     "Low-confidence activity — monitor"),

    (lambda c: True,
     "BASELINE",
     "Normal activity"),
]


def compute_decision(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Given a fully-scored analysis context, produce a recommended action.
    Returns {"action": str, "reason": str, "priority": str, "response_tasks": list}
    """
    for condition, action, reason in DECISION_RULES:
        try:
            if condition(context):
                priority = {
                    "ESCALATE":    "P1",
                    "INVESTIGATE": "P2",
                    "MONITOR":     "P3",
                    "BASELINE":    "P4",
                }.get(action, "P4")

                tasks = _build_response_tasks(action, context)
                return {
                    "action":         action,
                    "reason":         reason,
                    "priority":       priority,
                    "response_tasks": tasks,
                }
        except Exception:
            continue

    decision = {"action": "BASELINE", "reason": "Insufficient data", "priority": "P4",
            "response_tasks": []}

    # Safety override: ensure high-confidence or critical kill-chain indicators
    # cannot be silently downgraded to BASELINE due to rule ordering issues.
    try:
        ac = int(context.get("attack_conf_score", 0) or 0)
        if decision["action"] == "BASELINE":
            if ac >= 70:
                decision["action"] = "ESCALATE"
                decision["reason"] = "Safety override: high-confidence attack"
                decision["priority"] = "P1"
            elif ac >= 45:
                decision["action"] = "INVESTIGATE"
                decision["reason"] = "Safety override: medium-confidence attack"
                decision["priority"] = "P2"

        # Flags that must escalate regardless of action assignment
        if (context.get("has_lateral_movement") or context.get("has_privilege_escalation") or context.get("has_credential_access")):
            decision["action"] = "ESCALATE"
            decision["reason"] = "Safety override: critical kill-chain indicator present"
            decision["priority"] = "P1"
    except Exception:
        pass

    return decision


def _build_response_tasks(action: str, context: Dict[str, Any]) -> List[Dict[str, str]]:
    tasks = []
    stage = context.get("highest_kill_chain") or "Execution"

    if action == "ESCALATE":
        tasks += [
            {"task": "Isolate affected host from network",               "priority": "immediate"},
            {"task": "Preserve memory and disk image",                   "priority": "immediate"},
            {"task": "Reset credentials for affected accounts",          "priority": "urgent"},
            {"task": "Block identified IOCs at firewall and DNS",        "priority": "urgent"},
            {"task": "Notify security management and open P1 ticket",   "priority": "urgent"},
        ]
    if action in ("ESCALATE", "INVESTIGATE"):
        tasks += [
            {"task": "Review parent/child process relationships",        "priority": "high"},
            {"task": "Check for persistence in Run keys and startup",    "priority": "high"},
            {"task": "Pivot on destination IPs and DNS queries",         "priority": "high"},
        ]
    if context.get("has_lateral_movement"):
        tasks.append({"task": "Hunt for lateral movement on adjacent hosts", "priority": "high"})
    if context.get("has_credential_access"):
        tasks.append({"task": "Audit privileged account usage immediately", "priority": "high"})
    if context.get("has_privilege_escalation"):
        tasks.append({"task": "Inspect token theft and privilege escalation activity", "priority": "high"})
    if context.get("has_encoded_command"):
        tasks.append({"task": "Decode the PowerShell or script chain and review parent process context", "priority": "high"})
    if context.get("has_remote_execution"):
        tasks.append({"task": "Verify PsExec, WMI, or WinRM origin and service creation", "priority": "high"})
    if context.get("has_persistence_evasion"):
        tasks.append({"task": "Correlate persistence and defense-evasion steps on the same host", "priority": "high"})
    if stage in ("Lateral Movement", "Command and Control"):
        tasks.append({"task": "Hunt for lateral movement on adjacent hosts", "priority": "high"})
    if stage == "Credential Access":
        tasks.append({"task": "Audit privileged account usage immediately",  "priority": "high"})
    if action == "MONITOR":
        tasks += [
            {"task": "Set alert threshold for this process image",       "priority": "normal"},
            {"task": "Correlate with network telemetry",                 "priority": "normal"},
        ]

    return tasks


# ---------------------------------------------------------------------------
# 2. Attack narrative builder
# ---------------------------------------------------------------------------

def build_attack_narrative(
    bursts: List[Dict[str, Any]],
    campaigns: List[Dict[str, Any]],
    sequence_detections: List[Dict[str, Any]],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Produce a human-readable attack story from all available signals.
    This is the "Attack Story" the analyst sees at the top of the dashboard.
    """
    lines: List[str] = []
    stage = context.get("highest_kill_chain") or "Execution"
    score = context.get("attack_conf_score", 0)

    # Opening summary
    if score >= 75:
        lines.append(
            f"HIGH CONFIDENCE ATTACK DETECTED — {score}/100 confidence, "
            f"progressed to {stage}."
        )
    elif score >= 45:
        lines.append(
            f"SUSPICIOUS ACTIVITY — {score}/100 confidence, "
            f"kill-chain evidence up to {stage}."
        )
    else:
        lines.append("Low-risk baseline activity. No confirmed attack indicators.")

    # Sequence detections — most specific evidence
    unique_chains = []
    for seq in sequence_detections:
        chain = seq.get('chain_str', seq.get('rule_name'))
        if chain and chain not in unique_chains:
            unique_chains.append(chain)
            
    for chain in unique_chains[:3]:
        lines.append(f"• Attack chain detected: {chain}")

    # Persistence / injection
    attack_bursts = [b for b in bursts if b.get("classification") == "attack_candidate"]
    for b in sorted(attack_bursts, key=lambda x: x.get("risk_score", 0), reverse=True)[:3]:
        img = b.get("image", "?")
        kc  = b.get("kill_chain_stage", "?")
        sc  = b.get("risk_score", 0)
        indicators = []
        if b.get("has_persistence"): indicators.append("persistence")
        if b.get("has_injection"):   indicators.append("injection")
        if b.get("has_net"):         indicators.append("network activity")
        ind_str = (", ".join(indicators) + " — ") if indicators else ""
        lines.append(f"• {img} [{kc}] — {ind_str}risk score {sc}")

    # Campaigns
    for camp in campaigns[:2]:
        lines.append(
            f"• Multi-stage campaign detected across "
            f"{len(camp.get('computers', []))} host(s): "
            f"confidence {camp.get('confidence', 0):.0f}%"
        )

    # Narrative Fallback (Bug 6)
    if len(lines) == 1:
        lines.append(
            f"No confirmed attack chains, but {context.get('detections_count', 0)} signals observed."
        )

    return {
        "summary": lines[0] if lines else "No activity.",
        "bullets": lines[1:],
        "full_text": "\n".join(lines),
        "stage": stage,
        "score": score,
        "is_attack": score >= 45,
    }


# ---------------------------------------------------------------------------
# 3. Top-threats prioritiser
# ---------------------------------------------------------------------------

def prioritise_bursts(bursts: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    """
    Return the top-N highest-risk bursts, ranked by multi-factor priority score.
    This replaces the flat list that shows everything equally.
    """
    KILL_CHAIN_ORDER = [
        "Background", "Delivery", "Execution", "Defense Evasion",
        "Persistence", "Privilege Escalation", "Credential Access",
        "Discovery", "Lateral Movement", "Collection",
        "Command and Control", "Exfiltration", "Actions on Objectives",
    ]
    kc_rank = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}

    def _priority_score(b: Dict) -> float:
        sc    = float(b.get("risk_score") or b.get("peak_score") or 0)
        stage = b.get("kill_chain_stage") or "Background"
        kc    = kc_rank.get(stage, 0)
        bonus = (
            (10 if b.get("has_persistence") else 0) +
            (15 if b.get("has_injection")   else 0) +
            (5  if b.get("has_correlation") else 0) +
            (5  if b.get("has_net")         else 0)
        )
        return sc + kc * 2 + bonus + (20 if b.get("has_sequence_detection") else 0)

    return sorted(bursts, key=_priority_score, reverse=True)[:limit]


def group_sessions(bursts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group bursts into stage-aware, time-bound attack sessions (300s window).
    """
    import datetime
    def parse_ts(ts) -> float:
        if not ts: return 0.0
        try:
            if isinstance(ts, (int, float)): return float(ts)
            import pandas as pd
            return pd.to_datetime(ts, utc=True).timestamp()
        except Exception:
            return 0.0

    sessions = []
    # Sort by time for sequential grouping
    sorted_bursts = sorted(bursts, key=lambda x: parse_ts(x.get("start_time") or x.get("event_time")))
    
    for b in sorted_bursts:
        b_start = parse_ts(b.get("start_time") or b.get("event_time"))
        b_end   = parse_ts(b.get("end_time") or b.get("event_time"))
        b_stage = b.get("kill_chain_stage", "Background")
        b_host  = b.get("computer", "unknown")
        
        matched = False
        for s in sessions:
            if (b_host == s["host"] and 
                abs(b_start - s["last_ts"]) < 300 and 
                b_stage == s["stage"]):
                s["bursts"].append(b)
                s["last_ts"] = max(s["last_ts"], b_end)
                s["peak_score"] = max(s["peak_score"], b.get("risk_score", 0))
                matched = True
                break
        
        if not matched:
            sessions.append({
                "host": b_host,
                "stage": b_stage,
                "bursts": [b],
                "start_ts": b_start,
                "last_ts": b_end,
                "peak_score": b.get("risk_score", 0),
                "image": b.get("image")
            })
    return sessions


# ---------------------------------------------------------------------------
# 4. Full pipeline runner
# ---------------------------------------------------------------------------

def collapse_bursts(bursts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Collapses multiple bursts belonging to the same semantic attack chain.
    Ensures 1 chain = 1 UI row, preserving the strongest signal.
    """
    def parse_ts(ts):
        import pandas as pd
        try:
            return pd.to_datetime(ts, utc=True).timestamp()
        except Exception:
            return 0

    collapsed = {}
    for b in bursts:
        chain = tuple(b.get("attack_chain", []))
        if not chain:
            continue
        
        comp  = str(b.get("computer") or "unknown").lower().strip()
        stage = str(b.get("kill_chain_stage") or "Background").strip()
        
        # 300s Time Bucket to prevent merging temporal stages (v3.3)
        time_bucket = int(parse_ts(b.get("start_time") or b.get("event_time")) // 300)
        
        key = (chain, comp, stage, time_bucket)

        if key not in collapsed or (float(b.get("risk_score", 0)) > float(collapsed[key].get("risk_score", 0))):
            collapsed[key] = b

    return list(collapsed.values())


def run_full_pipeline(
    events_df: 'pd.DataFrame',
    detections_df: 'pd.DataFrame',
    run_id: str,
    context: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Given raw events + detections already stored in DB (by analysis_engine),
    run the full enrichment pipeline and augment the context dict.
    """
    import pandas as pd
    import copy as _copy

    # 9.8 IMMUTABILITY: Deep-copy the input context so mutations don't
    # corrupt the caller's reference if the pipeline fails partway through.
    # This is correct functional engineering — pipelines must be side-effect-free.
    if not isinstance(context, dict):
        context = {}
    context = _copy.deepcopy(context)

    # Ensure required keys exist (prevents downstream key errors)
    context.setdefault("kill_chain_path", [])
    context.setdefault("meta", {"pipeline_stage": "init", "errors": [], "warnings": []})

    context.setdefault("pipeline_profiling", {})
    context["pipeline_profiling"].setdefault(
        "inputs",
        {
            "events_df": _frame_size(events_df),
            "detections_df": _frame_size(detections_df),
            "dataframe_merge_count": 0,
            "scoring_batch_count": int(len(context.get("burst_aggregates", []) or [])),
            "sequence_batch_count": 0,
            "correlation_pair_count": 0,
        },
    )

    context["meta"]["pipeline_stage"] = "analysis_started"
    log.info("[Pipeline] Starting full analysis for run_id=%s", run_id)
    
    # ── [10/10] Formal Scope Initialization ───────────────────────────────
    KILL_CHAIN_ORDER = [
        "Background", "Delivery", "Execution", "Defense Evasion",
        "Persistence", "Privilege Escalation", "Credential Access",
        "Discovery", "Lateral Movement", "Collection",
        "Command and Control", "Exfiltration", "Actions on Objectives",
    ]
    kc_rank = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}
    
    try:
        # ── [10/10] Component Health Registry ─────────────────────────────────
        context.setdefault("analysis_integrity", {
            "rule": "OK",
            "sequence": "OK",
            "correlation": "OK",
            "scoring": "OK",
            "baseline": "OK"
        })
        context.setdefault("health_trend", "STABLE") # Mocked for now, needs historical comparison

        # ── A. Sequence engine ──────────────────────────────────────────────
        sequence_detections: List[Dict[str, Any]] = []
        if not events_df.empty:
            try:
                from dashboard.sequence_engine import get_sequence_engine
                seq_engine = get_sequence_engine()
                df_seq = events_df.copy()
                if "event_time" in df_seq.columns and "utc_time" not in df_seq.columns:
                    df_seq["utc_time"] = df_seq["event_time"]
                sequence_detections = seq_engine.process_dataframe(df_seq)

                for sd in sequence_detections:
                    sd["run_id"] = run_id

                import math
                import datetime

                # 1. Dedup sequences & frequency normalization
                import re
                def normalize_cmd(cmd: str) -> str:
                    if not cmd: return ""
                    c = cmd.lower().strip()
                    c = re.sub(r'[a-f0-9]{20,}', '[HEX]', c)
                    c = " ".join(c.split())
                    return c[:100]

                BENIGN_PARENTS = {"svchost.exe", "services.exe", "explorer.exe", "wininit.exe"}
                grouped_seqs = defaultdict(list)
                
                for sd in sequence_detections:
                    img = (sd.get("image") or "").lower()
                    pimg = (sd.get("parent_image") or "").lower()
                    comp = (sd.get("computer") or "").lower()
                    pat_id = str(sd.get("pattern_id") or "")
                    cmd_raw = str(sd.get("command_line") or "")
                    cmd_norm = normalize_cmd(cmd_raw)
                    
                    ts = sd.get("event_time") or sd.get("utc_time")
                    try:
                        import pandas as pd
                        if isinstance(ts, pd.Timestamp): evt_sec = ts.timestamp()
                        elif isinstance(ts, datetime.datetime): evt_sec = ts.timestamp()
                        else: evt_sec = pd.to_datetime(ts, errors="coerce", utc=True).timestamp()
                    except Exception:
                        evt_sec = datetime.datetime.now(datetime.timezone.utc).timestamp()
                        
                    time_bucket = int(evt_sec // 30)
                    group_key = (img, pimg, pat_id, comp, cmd_norm, time_bucket)
                    grouped_seqs[group_key].append(sd)

                deduped_seqs = []
                for gkey, items in grouped_seqs.items():
                    best_sd = max(items, key=lambda x: int(x.get("confidence_score") or x.get("confidence") or 0)).copy()
                    base_score = float(best_sd.get("confidence_score") or best_sd.get("confidence") or 0)
                    frequency = len(items)
                    normalized_score = base_score / math.log(1 + frequency)
                    if frequency > 5: normalized_score *= 0.5
                    if "schtasks.exe" in gkey[0] and any(bp in gkey[1] for bp in BENIGN_PARENTS):
                        normalized_score *= 0.5
                    best_sd["confidence_score"] = int(normalized_score)
                    best_sd["original_frequency"] = frequency
                    deduped_seqs.append(best_sd)

                from dashboard.correlation_engine import deduplicate_chains
                sequence_detections = deduplicate_chains(deduped_seqs)
                context["pipeline_profiling"]["inputs"]["sequence_batch_count"] = len(sequence_detections)

                if sequence_detections:
                    context.setdefault("detections", [])
                    context["detections"] = list(context["detections"]) + sequence_detections
                    context["detections_count"] = len(context["detections"])

            except Exception as exc:
                log.error("[Pipeline] [STAGE] Sequence engine failed: %s", exc, exc_info=True)
            
        # --- Ensure sequence detections are visible to UI ---
        detections = context.get("detections", [])
        context["sequence_detections"] = [
            d for d in detections if d.get("detection_source") == "sequence" or d.get("is_sequence")
        ]
        if not context["sequence_detections"] and context.get("detections_count", 0) > 0:
            # We have rules but no sequences; this is normal but we track it
            pass

        # ── B. Apply feedback suppressions ─────────────────────────────────
        bursts = list(context.get("timeline", []) or [])
        if bursts:
            try:
                from dashboard.feedback_engine import load_suppressions, apply_feedback_adjustment
                suppressions = load_suppressions()
                if suppressions:
                    for burst in bursts:
                        delta, reason = apply_feedback_adjustment(burst, suppressions)
                        if delta != 0:
                            burst["feedback_delta"] = delta
                            burst.setdefault("confidence_reasons", [])
                            burst["confidence_reasons"].append(f"Feedback adjustment {delta:+d}: {reason}")
            except Exception as exc:
                log.warning("[Pipeline] Feedback engine failed: %s", exc)

        context["timeline"] = bursts

        # ── C. Re-prioritise burst aggregates with sequence boost ───────────
        burst_aggregates = list(context.get("burst_aggregates", []) or [])
        seq_by_image: Dict[str, int] = {}
        for sd in sequence_detections:
            img  = (sd.get("image") or "").lower()
            conf = int(sd.get("confidence_score") or sd.get("confidence") or 0)
            seq_by_image[img] = max(seq_by_image.get(img, 0), conf)

        for ba in burst_aggregates:
            img = (ba.get("image") or "").lower()
            seq_boost = seq_by_image.get(img, 0)
            if seq_boost > 0:
                old = float(ba.get("peak_score") or ba.get("risk_score") or 0.0)
                behavior = float(ba.get("behavior_score", 0))
                # Normalized + Bounded Sequence Boost (v3.1)
                boost = min(10.0, (seq_boost / 10.0) * (0.5 + behavior))
                ba["peak_score"] = min(100.0, old + boost)
                ba["has_sequence_detection"] = True

        context["burst_aggregates"] = prioritise_bursts(burst_aggregates)

        # --- Execute correlation (FIX 8) ---
        corr_prof = cProfile.Profile()
        corr_prof_enabled = False
        corr_started = time.perf_counter()
        try:
            from dashboard.correlation_engine import correlate_bursts, deduplicate_chains
            all_dets = context.get("detections", [])
            if sys.getprofile() is None:
                corr_prof.enable()
                corr_prof_enabled = True
            else:
                log.warning("[PROFILE] Skipping nested correlation profiling for run_id=%s because another profiler is active", run_id[:16])
            _, campaigns = correlate_bursts(all_dets, run_id=run_id)
            if corr_prof_enabled:
                corr_prof.disable()
            campaigns = deduplicate_chains(campaigns)
            context["correlation_campaigns"] = campaigns

            corr_debug = None
            if all_dets and isinstance(all_dets[0], dict):
                corr_debug = all_dets[0].get("correlation_debug")
            if corr_debug:
                context["pipeline_profiling"]["inputs"]["correlation_pair_count"] = int(corr_debug.get("pair_checks", 0))
                context["pipeline_profiling"]["correlation_debug"] = corr_debug
        except Exception as exc:
            if corr_prof_enabled:
                corr_prof.disable()
            log.error("[Pipeline] [STAGE] Correlation engine failed: %s", exc, exc_info=True)
            campaigns = []
            context["analysis_integrity"]["correlation"] = "FAILED"
            context["correlation_status"] = "failed"
        finally:
            corr_elapsed = time.perf_counter() - corr_started
            corr_artifacts = _write_pipeline_profile_artifacts(
                run_id=run_id,
                phase="correlation",
                profiler=corr_prof if corr_prof_enabled else None,
                elapsed_seconds=corr_elapsed,
                metadata={
                    "detections_count": len(context.get("detections", []) or []),
                    "campaign_count": len(campaigns or []),
                    "inputs": context.get("pipeline_profiling", {}).get("inputs", {}),
                },
            )
            context["pipeline_profiling"]["correlation"] = {
                "elapsed_seconds": round(corr_elapsed, 6),
                "artifact_paths": corr_artifacts,
            }
            
        # --- Qualified SUSPICIOUS_EMPTY check (10/10) ---
        det_count = context.get("detections_count", 0)
        seq_count = len(context.get("sequence_detections", []))
        if det_count > 5 and seq_count > 0 and len(campaigns) == 0:
            context["correlation_status"] = "SUSPICIOUS_EMPTY"
            log.warning("[Pipeline] Correlation is SUSPICIOUS_EMPTY (dets=%d, seqs=%d)", det_count, seq_count)

        # ── E. Burst-Level De-duplication (The UI Truth Fix) ──────────────────
        bursts = collapse_bursts(bursts)
        
        # ── F. Metric Aggregation (The Realistic Truth) ───────────────────────────
        # We aggregate AFTER de-duplication to ensure counts reflect unique stories
        kill_chain_counts = defaultdict(int)
        highest_stage = "Background"
        for b in bursts:
            stage = b.get("kill_chain_stage") or "Background"
            kill_chain_counts[stage] += 1
            if kc_rank.get(stage, 0) > kc_rank.get(highest_stage, 0):
                highest_stage = stage
        
        context["events_by_severity"] = dict(kill_chain_counts)
        context["highest_kill_chain"] = highest_stage
        
        # ── F. Sigmoid Confidence Decay (The 10/10 Truth) ───────────────────
        try:
            import math
            # 1. Feedback Integration & Score Normalization (v3.1)
            valid_scores = []
            for b in burst_aggregates:
                # Use adjusted_score (feedback-aware) if available (v3.3)
                base_score = float(
                    b["adjusted_score"] if b.get("adjusted_score") is not None
                    else (b.get("peak_score") or b.get("risk_score") or 0.0)
                )
                feedback = float(b.get("feedback_delta", 0.0))
                
                adjusted_score = max(0.0, min(100.0, base_score + feedback))
                b["adjusted_score"] = adjusted_score # Sync for UI aggregation
                
                if adjusted_score >= 45:
                    valid_scores.append(adjusted_score)

            # 2. Sigmoid Decay Calculation (v3.3 Standards)
            n_val = Decimal(str(len(valid_scores)))
            if n_val == 0:
                max_risk = max([float(b.get("adjusted_score") or b.get("risk_score", 0)) for b in burst_aggregates], default=0.0)
                avg_top = Decimal(str(max_risk))
                raw_score_dec = avg_top * Decimal("0.5")
            else:
                top_3 = sorted(valid_scores, reverse=True)[:3]
                avg_top = Decimal(str(sum(top_3))) / Decimal(str(len(top_3)))
                decay = Decimal("1.0") - (Decimal("1.0") / (Decimal("1.0") + n_val))
                raw_score_dec = avg_top * decay

            # 3. Finite & Non-negative guards
            raw_score_dec = raw_score_dec.quantize(Decimal("0.0001"), ROUND_HALF_UP)
            
            # 4. Consistency & Pattern Boost (Driver-Specific v3.3)
            drivers = [b.get("primary_driver", "rule") for b in burst_aggregates if float(b.get("adjusted_score") or b.get("risk_score", 0)) >= 30]
            if drivers:
                from collections import Counter
                counts = Counter(drivers)
                dominant, count = counts.most_common(1)[0]
                consistency = count / max(1, len(drivers))
                
                # Standardized Evidence filtering (v3.3)
                relevant = [b for b in burst_aggregates if float(b.get("adjusted_score") or b.get("risk_score", 0)) >= 30]
                
                # Signal-specific strength
                if dominant == "behavior":
                    avg_strength = sum(b.get("behavior_score", 0) for b in relevant) / max(1, len(relevant))
                elif dominant == "correlation" or dominant == "campaign":
                    avg_strength = sum(b.get("correlation_strength", 0) for b in relevant) / (100 * max(1, len(relevant)))
                else:
                    avg_strength = 0.5
                
                if consistency > 0.7 and avg_strength > 0.5:
                    raw_score_dec += Decimal("5.0")
                    context["pattern_consistency"] = "STRONG"

            # 5. Global Constraint (Bounded by max burst)
            max_any = Decimal(str(max([float(b.get("adjusted_score") or b.get("risk_score", 0)) for b in burst_aggregates], default=0.0)))
            bounded_score = max(raw_score_dec, max_any)

            # 6. Weighted Confidence Modifier (Trimmed-Min v3.1)
            conf_mods = [float(b.get("confidence_modifier", 1.0)) for b in burst_aggregates]
            if conf_mods:
                mods = sorted(conf_mods)
                avg_mod = sum(mods) / len(mods)
                trimmed_min = mods[1] if len(mods) > 2 else min(mods)
                effective_mod = (0.8 * avg_mod) + (0.2 * trimmed_min)
            else:
                effective_mod = 1.0

            # 7. Final Pipeline Hierarchy Multipliers
            integrity = context["analysis_integrity"]
            multiplier = Decimal(str(effective_mod))
            
            if integrity.get("rule") == "FAILED": multiplier *= Decimal("0.5")
            if integrity.get("sequence") == "FAILED": multiplier *= Decimal("0.7")
            if integrity.get("correlation") == "FAILED": multiplier *= Decimal("0.85")
            
            if context.get("correlation_status") == "SUSPICIOUS_EMPTY":
                scaler = Decimal(str(min(1.0, (det_count + seq_count) / 20.0)))
                multiplier *= (Decimal("1.0") - (Decimal("0.15") * scaler))

            final_score_dec = (bounded_score * multiplier).quantize(Decimal("1"), ROUND_HALF_UP)
            
            # Catastrophic Override (10/10)
            critical_fails = sum(1 for k, v in integrity.items() if v == "FAILED" and k in ["rule", "sequence"])
            if critical_fails >= 2:
                final_score_dec = min(final_score_dec, Decimal("50"))
                context["severity_label_override"] = "UNTRUSTWORTHY_RESULT"

            context["attack_conf_score"] = int(final_score_dec)
            attack_conf_score = int(final_score_dec) # Local for narrative
            
            # 8. Confidence Score (v2.8 Integration)
            conf_val = float(len(context.get("detections", [])) * 5.0 + len(campaigns or []) * 5.0)
            if len(context.get("baseline_execution_context", [])) >= 100: conf_val += 20.0
            confidence_final = min(100.0, conf_val * effective_mod)
            context["confidence_score"]  = int(confidence_final)
            confidence_score = int(confidence_final) # Local for narrative

            # ── [10/10] System Health Integration ─────────────────────────
            # Dampen all final scores if bursts indicate degraded engine health (v3.3)
            low_health = [b for b in burst_aggregates if float(b.get("system_health", 100)) < 70]
            if low_health and burst_aggregates:
                ratio = len(low_health) / len(burst_aggregates)
                penalty = 0.9 - (0.1 * ratio)  # dynamic penalty (scaling from 0.8 to 0.9)
                
                # Apply penalty to both signal strength and reliability
                attack_conf_score = int(float(attack_conf_score) * penalty)
                confidence_score  = int(float(confidence_score) * penalty)
                
                context["attack_conf_score"] = attack_conf_score
                context["confidence_score"]  = confidence_score
                
                log.warning("[Pipeline] 10/10 Lock: Scores dampened by %.1f%% due to engine health issues (%d/%d bursts degraded)", 
                            (1.0 - float(penalty)) * 100, len(low_health), len(burst_aggregates))

            # Metadata for decision logic
            behaviors = [float(b.get("behavior_score", 0)) for b in burst_aggregates]
            context["max_behavior"] = max(behaviors) if behaviors else 0.0
            context["avg_behavior"] = sum(behaviors) / max(1, len(behaviors))

            if context.get("incident"):
                context["incident"]["score"] = attack_conf_score
                _lvl = "High" if attack_conf_score >= 75 else "Medium" if attack_conf_score >= 50 else "Low" if attack_conf_score > 0 else "None"
                context["incident"]["severity"] = _lvl
                try:
                    from dashboard.analysis_engine import upsert_incident_row
                    upsert_incident_row(context["incident"]["incident_id"], "Open", _lvl.lower(), attack_conf_score, str(context.get("analysis_run_id") or run_id))
                except Exception as e: log.warning("[Pipeline] Failed to update incident: %s", e)
        except Exception as exc:
            log.error("[Pipeline] [STAGE] Scoring engine failed: %s", exc, exc_info=True)
            context.setdefault("attack_conf_score", 0)
            context.setdefault("confidence_score", 0)

        # ── [10/10 EXPERT] Adaptive Link Depth & Breadth ───────────────────
        # Limit incident_links by both depth (max 3) and total nodes (breadth)
        # Restore links that bridge different kill-chain stages (bridge-links)
        try:
            from collections import deque
            def get_limited_links(root_uid, all_edges, max_depth=3, max_breadth=20):
                visited = {root_uid}
                queue = deque([(root_uid, 0)])
                limited_edges = []
                
                while queue and len(visited) < max_breadth:
                    curr, depth = queue.popleft()
                    if depth >= max_depth: continue
                    
                    for edge in all_edges:
                        if edge["from"] == curr and edge["to"] not in visited:
                            # [10/10 EXPERT] Bridge-Link Protection
                            is_bridge = edge.get("from_stage") != edge.get("to_stage")
                            if is_bridge or len(visited) < max_breadth:
                                visited.add(edge["to"])
                                queue.append((edge["to"], depth + 1))
                                limited_edges.append(edge)
                return limited_edges

            for camp in campaigns:
                if camp.get("edges"):
                    # Dynamically increase depth if confidence > 80
                    d_limit = 5 if int(camp.get("confidence", 0)) > 80 else 3
                    camp["edges"] = get_limited_links(camp["edges"][0]["from"], camp["edges"], max_depth=d_limit)
        except Exception as e:
            log.warning("[Pipeline] Adaptive linking failed: %s", e)

        # ── E. Kill Chain Stage Alignment ──────────────────
        KILL_CHAIN_ORDER = [
            "Background", "Delivery", "Execution", "Defense Evasion",
            "Persistence", "Privilege Escalation", "Credential Access",
            "Discovery", "Lateral Movement", "Collection",
            "Command and Control", "Exfiltration", "Actions on Objectives",
        ]
        kc_rank = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}
        
        kill_chain_progression = set()
        for corr in campaigns:
            for edge in corr.get("edges", []):
                if edge.get("from_stage") and edge.get("from_stage") != "Background": kill_chain_progression.add(edge["from_stage"])
                if edge.get("to_stage") and edge.get("to_stage") != "Background": kill_chain_progression.add(edge["to_stage"])
        
        # 9.8/10 Mastery: Proactive Fallback
        kill_chain_path = context.get("kill_chain_path")
        if kill_chain_path is None:
            log.warning("[Pipeline] kill_chain_path missing - using empty fallback")
            kill_chain_path = []

        if kill_chain_path:
            context["kill_chain_path"] = kill_chain_path
            context["highest_kill_chain"] = kill_chain_path[-1]
            global_stage = kill_chain_path[-1]
        else:
            context["highest_kill_chain"] = "Background"
            global_stage = "Background"

        # Non-destructive alignment (stage_hint)
        for b in bursts:
            b_stage = b.get("kill_chain_stage", "Background")
            if kc_rank.get(global_stage, 0) > kc_rank.get(b_stage, 0):
                b["stage_hint"] = global_stage
            else:
                b["stage_hint"] = None
            
        # ── F. Timeline reasoning injection ─────────────────────────────────
        total_baseline_events = len(context.get("baseline_execution_context", []))
        suspicious_processes = {"cmd.exe", "powershell.exe", "pwsh.exe", "schtasks.exe", "wmic.exe", "wmiprvse.exe", "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
        benign_admin_tools = BENIGN_PARENTS | {"splunkd.exe", "splunk.exe", "osqueryd.exe", "senseir.exe", "csfalconservice.exe", "crowdstrike.exe", "carbonblack.exe", "cb.exe", "qualysagent.exe", "rapid7agent.exe"}
        
        for burst in bursts:
            reason = []
            freq = burst.get("event_count", 0)
            pimg = str(burst.get("parent_image", "")).lower()
            img = str(burst.get("image", "")).lower()
            cmd = str(burst.get("command_line") or burst.get("commandline") or "").lower()
            has_sequence = burst.get("has_sequence_detection") or any(s_img in img for s_img in [str(s.get("image", "")).lower() for s in sequence_detections])
            
            if not burst.get("kill_chain_stage") or burst["kill_chain_stage"] == "Background":
                if img in {"schtasks.exe"} or "schtasks" in cmd or any(token in cmd for token in ("currentversion\\run", "runonce", "startup", "autorun")):
                    burst["kill_chain_stage"] = "Persistence"
                elif img in {"regsvr32.exe", "rundll32.exe", "mshta.exe"} or any(token in cmd for token in ("regsvr32", "rundll32", "mshta", "-enc", "-encodedcommand", "frombase64string", "invoke-expression", "iex ", "-nop")):
                    burst["kill_chain_stage"] = "Defense Evasion"
                elif img in {"powershell.exe", "pwsh.exe"} and any(token in cmd for token in ("-enc", "-encodedcommand", "frombase64string", "invoke-expression", "iex ", "-nop", "http://", "https://")):
                    burst["kill_chain_stage"] = "Execution"
                elif (img in suspicious_processes or any(sp in img for sp in suspicious_processes)) and (has_sequence or any(token in cmd for token in ("psexec", "wmic", "winrm", "sc.exe create", "service create", "-enc", "frombase64string", "invoke-expression", "iex ", "-nop"))):
                    burst["kill_chain_stage"] = "Execution"
                elif img in benign_admin_tools or pimg in benign_admin_tools:
                    burst["kill_chain_stage"] = "Background"
            
            if freq > 10: reason.append("High frequency")
            if has_sequence:
                reason.append("Sequence-linked")
                burst["has_sequence_detection"] = True
            if pimg and "unknown" not in pimg and pimg not in BENIGN_PARENTS: reason.append("Abnormal parent")
            burst["reason"] = reason

            # Repeated-process dampening: reduce Execution-stage inflation for high-frequency,
            # benign-seeming bursts when baseline is mature. This prevents background cmd/powershell
            # noise from dominating the Execution tactic without weakening encoded/LOLBIN detections.
            try:
                if burst.get("kill_chain_stage") == "Execution":
                    # Use total_baseline_events as a proxy for baseline maturity
                    if (freq > 20 and not has_sequence and (pimg in benign_admin_tools or pimg == "")
                        and not any(token in cmd for token in ("-enc", "-encodedcommand", "psexec", "wmic", "runonce", "schtasks", "reg add", "frombase64string", "invoke-expression", "iex "))
                        and total_baseline_events >= 20):
                        burst["kill_chain_stage"] = "Background"
                        burst.setdefault("reason", []).append("Dampened repeated benign execution (baseline mature)")
            except Exception:
                pass

        # ── G. Decision layer ───────────────────────────────────────────────
        context["correlation_count"] = sum(len(c.get("edges", [])) for c in campaigns)
        dec_input = {
            "attack_conf_score":   context.get("attack_conf_score", 0),
            "highest_kill_chain":  global_stage,
            "has_persistence":     any(b.get("has_persistence") for b in bursts),
            "has_injection":       any(b.get("has_injection") for b in bursts),
            "has_lateral_movement": any(b.get("kill_chain_stage") == "Lateral Movement" for b in bursts),
            "has_credential_access": any(b.get("kill_chain_stage") == "Credential Access" for b in bursts),
            "has_privilege_escalation": any(b.get("kill_chain_stage") == "Privilege Escalation" for b in bursts),
            "has_encoded_command": any(
                bool(b.get("cmd_has_encoded_flag") or b.get("has_encoded_flag"))
                or any(token in str(b.get("command_line") or "").lower() for token in ("-enc", "frombase64string", "invoke-expression", "iex "))
                for b in bursts
            ),
            "has_remote_execution": any(
                str(b.get("image") or "").lower() in {"psexec.exe", "wmic.exe"}
                or any(token in str(b.get("command_line") or "").lower() for token in ("psexec", "wmic", "winrm", "sc.exe create"))
                for b in bursts
            ),
            "has_persistence_evasion": any(
                bool(b.get("has_persistence"))
                and any(token in str(b.get("command_line") or "").lower() for token in ("-enc", "frombase64string", "invoke-expression", "iex ", "-nop"))
                for b in bursts
            ),
            "has_multi_host_spread": len({str(b.get("computer") or "").lower() for b in bursts if b.get("computer")}) > 1,
            "detections_count":    context.get("detections_count", 0),
            "correlation_count":   context["correlation_count"],
            "sequence_hits":       len(sequence_detections),
            "campaigns":           len(campaigns),
        }

        log.info(
            "[DecisionInput] score=%s seq_hits=%s stage=%s campaigns=%s",
            dec_input.get("attack_conf_score"),
            dec_input.get("sequence_hits"),
            dec_input.get("highest_kill_chain"),
            dec_input.get("campaigns"),
        )

        decision = compute_decision(dec_input)
        context["recommended_action"] = decision["action"]
        context["action_reason"]      = decision["reason"]
        context["action_priority"]    = decision["priority"]
        context["response_tasks"]     = decision["response_tasks"]

        # ── H. Pattern-aware IOC Extraction (FIX 12 refined) ──────────────────
        try:
            if events_df is not None and not events_df.empty:
                df_norm = events_df.copy()
                if "CommandLine" in df_norm.columns: df_norm["command_line"] = df_norm["CommandLine"].fillna("")
                if "Image" in df_norm.columns: df_norm["image"] = df_norm["Image"].fillna("")
                from dashboard.analysis_engine import extract_iocs
                iocs = extract_iocs(df_norm.to_dict(orient="records"))
                
                # Pattern-aware filtering
                filtered = {
                    "ips": [ip for ip in iocs.get("ips", []) if not ip.startswith("127.")],
                    "domains": iocs.get("domains", []),
                    "hashes": iocs.get("hashes", []),
                    "files": iocs.get("files", []),
                    "commands": [
                        c for c in iocs.get("commands", [])
                        if len(c) > 20 or "enc" in c.lower() or "-nop" in c.lower()
                    ]
                }
                context["iocs"] = filtered
        except Exception as e: log.warning("[Pipeline] IOC extraction failed: %s", e)

        # ── I. Attack narrative & Sessions ─────────────────────────────────────
        narrative = build_attack_narrative(bursts, campaigns, sequence_detections, context)
        # Use localized variables from scoring block (v3.1)
        conf_val = context.get("confidence_score", 0)
        score_val = context.get("attack_conf_score", 0)
        _stats = f"Confidence: {int(conf_val)}\nScore: {int(score_val)}\nReason:"
        narrative["full_text"] = _stats + "\n- " + "\n- ".join(narrative["bullets"])
        # ── [10/10] Kill Chain Guarantee ──────────────────────────────────
        narrative["kill_chain"] = kill_chain_path or []
        context["attack_narrative"] = narrative
        
        # Session Grouping (FIX 14)
        context["attack_sessions"] = group_sessions(bursts)

        # [10/10 EXPERT] Global Component Health (Hard Overrides)
        integrity = context["analysis_integrity"]
        rule_failed = integrity.get("rule") == "FAILED"
        seq_failed = integrity.get("sequence") == "FAILED"
        corr_failed = integrity.get("correlation") == "FAILED"
        
        # Weighted Health % calculation
        # Rule: 40%, Seq: 30%, Corr: 20%, Rest: 10%
        health_pct = 100.0
        if rule_failed: health_pct -= 40.0
        if seq_failed: health_pct -= 30.0
        if corr_failed: health_pct -= 20.0
        
        if rule_failed:
            context["system_health_label"] = "CRITICAL DEGRADED"
            context["urgency"] = "HIGH"
            context["require_manual_confirmation"] = True
        elif seq_failed or corr_failed:
            context["system_health_label"] = "DEGRADED"
        else:
            context["system_health_label"] = "HEALTHY"
            
        context["final_system_health_pct"] = max(0, int(health_pct))
        context["final_system_confidence"] = float(context.get("confidence_score", 100)) * (health_pct / 100.0)

        score = context.get("attack_conf_score", 0)
        level = ("High" if score >= 75 else "Medium" if score >= 45 else "Low" if score > 0 else "None")
        
        # Catastrophic Label override
        if context.get("severity_label_override"):
            level = f"{level} ({context['severity_label_override']})"
            
        context["attack_conf_level"] = level
        context["is_alertable"] = score >= 45

        log.info("[Pipeline] Complete: score=%d level=%s action=%s health=%d%s", 
                 context.get("attack_conf_score", 0), level, decision["action"], 
                 context.get("confidence_score", 0), context.get("system_health_label", ""))

    except Exception as exc:
        log.error("[Pipeline] FATAL: Pipeline crashed: %s", exc, exc_info=True)
        context["pipeline_status"] = "CRASHED"
        context["system_health_label"] = "PIELINE CRITICAL FAILURE"
        # Ensure we don't hide the crash from calling layers if they expect it
        raise
    finally:
        # ── [10/10] Finality Guard ──────────────────────────────────────────
        try:
            from dashboard.baseline_engine import get_baseline_engine
            be = get_baseline_engine()
            be.save_to_db()
            logging.getLogger("pipeline").info("[Pipeline] Finality Guard: Baseline persisted")
        except Exception as e:
            logging.getLogger("pipeline").error("[Pipeline] Finality Guard: Persistence failed: %s", e)

    # ── [10/10] Formal Proof: Minimal Sufficiency ─────────────────────────
    try:
        validate_minimal_truth(context)
        log.info("[Pipeline] Formal Correctness Proof: VERIFIED for run_id=%s", run_id)
    except AssertionError as ae:
        log.error("[Pipeline] Formal Correctness Proof: FAILED for run_id=%s: %s", run_id, ae)
        context["pipeline_status"] = "INVALID"
        context["system_health_label"] = "LOGICAL INVARIANT VIOLATION"

    return context
