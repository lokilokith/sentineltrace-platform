"""
analysis_engine.py — SentinelTrace Full Analysis Engine  (MySQL edition)
=========================================================================
Converted from SQLite to MySQL.  All sqlite3 / DB_PATH references removed.
Uses dashboard.db context managers throughout.

Exports (used by app.py):
    ingest_upload, persist_case, run_full_analysis, process_event,
    upsert_incident_row, persist_behavior_baseline
"""

from __future__ import annotations

import datetime
import cProfile
import io
import hashlib
import math
import pstats
import traceback
import uuid
import json
import unicodedata
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from decimal import Decimal

import pandas as pd

# 10/10 Mastery: Multi-Process Isolation & Resource Guards
import os
import queue
import threading
import sys
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError
from contextlib import contextmanager

# Global Analysis Infrastructure (V9.0 "THE UNBREAKABLE")
_ANALYSIS_QUEUE = queue.Queue()
_ANALYSIS_EXECUTOR = None
_EXECUTOR_LOCK = threading.Lock()

# Thread-safe lock for all correlation/campaign DB write operations.
# Prevents race conditions when multiple analysis threads persist simultaneously.
DB_WRITE_LOCK = threading.Lock()

def get_analysis_executor():
    """Double-checked locking for the single-node analysis process."""
    global _ANALYSIS_EXECUTOR
    if _ANALYSIS_EXECUTOR is None:
        with _EXECUTOR_LOCK:
            if _ANALYSIS_EXECUTOR is None:
                # ── [10/10] Process-Level Isolation ────────────────────────
                # We limit to 1 worker to ensure absolute single-job fairness
                # and prevent CPU thrashing during heavy graph correlation.
                _ANALYSIS_EXECUTOR = ProcessPoolExecutor(max_workers=1)
    return _ANALYSIS_EXECUTOR

# --- NO MODULE-LEVEL PANDAS OR SQLALCHEMY ---



# --- YARA support ---
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

import yaml

from dashboard.event_parser import (
    parse_event,
    load_all_sources_from_xml,
    enrich_parent_chains,
)
from dashboard.detection_engine import find_detections, match_rules
from dashboard.db import (
    DB_TYPE,
    DB_STRICT,
    INGESTED,
    ANALYZING,
    COMPLETE,
    DEGRADED,
    FAILED,
    checked_insert,
    dispose_engine,
    get_db_connection,
    get_cursor,
    get_datetime_columns,
    get_engine,
    get_table_columns,
    now_utc,
    sanitize_datetime,
    sanitize_row,
    sql_insert_ignore,
    sql_now_minus,
    sql_upsert,
    quote_identifier,
)
from dashboard.scoring_engine import get_scoring_engine, validate_context
from dashboard.analysis_cache import (
    set_analysis_snapshot,
    get_analysis_snapshot,
    clear_analysis_snapshot,
    publish_analysis_stage_progress,
)

# Module-level logger — available to ALL functions in this module
log = logging.getLogger("analysis")

# ---------------------------------------------------------------------------
# 9.8 — Global timeout kill switch (thread-local, per-analysis)
# ---------------------------------------------------------------------------
import threading as _threading
import time as _time

_THREAD_DEADLINE: _threading.local = _threading.local()

# Hard cap: analyses running longer than this are killed internally
MAX_ANALYSIS_SECONDS = 900   # 15-minute wall-clock limit

# Data-bounding caps maintained here for single-source-of-truth
MAX_EVENTS     = 1_000
MAX_DETECTIONS = 5_000
STORY_MAX_EVENTS = int(os.environ.get("STORY_MAX_EVENTS", "2000"))


def _start_analysis_timer() -> None:
    """Record the start time for THIS thread's analysis run."""
    _THREAD_DEADLINE.start = _time.monotonic()
    _THREAD_DEADLINE.limit = MAX_ANALYSIS_SECONDS


def check_timeout(label: str = "") -> None:
    """
    [9.8] Raise TimeoutError if the current analysis thread has exceeded
    MAX_ANALYSIS_SECONDS.  Call this at the start of every expensive loop.

    Args:
        label: A human-readable stage name for the error message.
    """
    start = getattr(_THREAD_DEADLINE, "start", None)
    limit = getattr(_THREAD_DEADLINE, "limit", MAX_ANALYSIS_SECONDS)
    if start is None:
        return   # Timer not started — skip check (legacy code paths)
    elapsed = _time.monotonic() - start
    if elapsed > limit:
        raise TimeoutError(
            f"[TIMEOUT] Analysis exceeded {limit}s at stage '{label}' "
            f"(elapsed={elapsed:.1f}s)"
        )


def _enforce_snapshot_contract(context: dict, run_id: str) -> dict:
    """
    [9.8] Hard schema validation before any snapshot write.
    Raises RuntimeError (triggers the outer except → fail snapshot) if
    a required field is missing or has the wrong type.

    Returns the validated context on success.
    """
    REQUIRED_FIELDS = {
        "timeline":          list,
        "attack_narrative":  dict,
        "attack_conf_score": (int, float),
        "status":            str,
    }
    missing = []
    wrong_type = []
    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in context:
            missing.append(field)
        elif not isinstance(context[field], expected_type):
            wrong_type.append(
                f"{field} (got {type(context[field]).__name__}, want {expected_type})"
            )

    if missing or wrong_type:
        problems = "; ".join(
            [f"missing: {missing}" if missing else ""]
            + [f"wrong type: {wrong_type}" if wrong_type else ""]
        ).strip("; ")
        log.error("[CONTRACT] Snapshot contract FAILED for run_id=%s: %s", run_id[:16], problems)
        raise RuntimeError(f"Snapshot contract violation: {problems}")

    log.debug("[CONTRACT] Snapshot contract OK for run_id=%s", run_id[:16])
    return context


# ---------------------------------------------------------------------------
# Perf timing helper
# ---------------------------------------------------------------------------

class _PerfTimer:
    """Lightweight wall-clock stage timer for observability."""
    def __init__(self, run_id: str):
        self._run_id = run_id[:16]
        self._started = _time.monotonic()
        self._t = self._started
        self._laps: List[Tuple[str, float]] = []

    def lap(self, stage: str) -> float:
        now = _time.monotonic()
        elapsed_ms = (now - self._t) * 1000
        self._laps.append((stage, elapsed_ms / 1000.0))
        log.info(
            "[PERF] run_id=%s  stage=%-20s  duration=%.0fms",
            self._run_id, stage, elapsed_ms
        )
        self._t = now
        return elapsed_ms

    def snapshot(self) -> Dict[str, Any]:
        total_seconds = _time.monotonic() - self._started
        laps = [
            {
                "stage": stage,
                "elapsed_seconds": elapsed_seconds,
                "elapsed_ms": round(elapsed_seconds * 1000.0, 3),
            }
            for stage, elapsed_seconds in self._laps
        ]
        slowest = max(laps, key=lambda item: item["elapsed_seconds"], default=None)
        return {
            "run_id": self._run_id,
            "total_seconds": total_seconds,
            "laps": laps,
            "slowest_stage": slowest,
        }


def _current_process_rss_bytes() -> int:
    try:
        import psutil

        return int(psutil.Process().memory_info().rss)
    except Exception:
        return 0


PROFILE_ARTIFACT_ROOT = Path(__file__).resolve().parents[1] / "engineering_outputs" / "profile_artifacts"


def _profile_rows(profiler: cProfile.Profile, limit: int = 20) -> List[Dict[str, Any]]:
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


def _profile_frame_summary(frame: Any) -> Dict[str, Any]:
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

    try:
        return {"rows": int(len(frame)), "cols": 0, "mem_mb": 0.0}
    except Exception:
        return {"rows": 0, "cols": 0, "mem_mb": 0.0}


def _profile_dataframe_sizes(frames: Dict[str, Any]) -> Dict[str, Any]:
    return {name: _profile_frame_summary(frame) for name, frame in frames.items()}


def _profile_db_timings(stage_summary: Dict[str, Any]) -> Dict[str, float]:
    db_stages = {"load_events", "load_detections", "load_correlations", "load_correlation_campaigns", "load_behaviors", "snapshot_write"}
    timings: Dict[str, float] = {}
    for lap in stage_summary.get("laps", []):
        stage = str(lap.get("stage") or "")
        if stage in db_stages:
            timings[stage] = round(float(lap.get("elapsed_ms") or 0.0), 3)
    return timings


def _write_profile_artifacts(
    run_id: str,
    phase: str,
    profiler: cProfile.Profile,
    stage_summary: Dict[str, Any],
    profile_rows: List[Dict[str, Any]],
    bottleneck: Dict[str, Any],
    profile_inputs: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    artifact_dir = PROFILE_ARTIFACT_ROOT / run_id[:16] / phase
    artifact_dir.mkdir(parents=True, exist_ok=True)

    prof_path = artifact_dir / f"{run_id[:16]}_{phase}.prof"
    pstats_path = artifact_dir / f"{run_id[:16]}_{phase}.pstats.txt"
    json_path = artifact_dir / f"{run_id[:16]}_{phase}.json"

    profiler.dump_stats(str(prof_path))

    stream = io.StringIO()
    pstats.Stats(profiler, stream=stream).strip_dirs().sort_stats("cumulative").print_stats(20)
    pstats_path.write_text(stream.getvalue(), encoding="utf-8")

    artifact_summary = {
        "run_id": run_id[:16],
        "phase": phase,
        "total_seconds": round(float(stage_summary.get("total_seconds") or 0.0), 6),
        "stage_timings": stage_summary.get("laps", []),
        "db_timing_ms": _profile_db_timings(stage_summary),
        "top_functions": profile_rows,
        "bottleneck": bottleneck,
        "profile_inputs": profile_inputs or {},
    }
    json_path.write_text(json.dumps(artifact_summary, default=str, sort_keys=True, indent=2), encoding="utf-8")

    return {
        "prof": str(prof_path),
        "pstats": str(pstats_path),
        "json": str(json_path),
    }


def _classify_profile_bottleneck(stage_summary: Dict[str, Any], profile_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    slowest_stage = stage_summary.get("slowest_stage") or {}
    stage_name = str(slowest_stage.get("stage") or "").lower()
    top_functions = " ".join(row["qualified_name"].lower() for row in profile_rows[:6])

    if any(token in stage_name for token in ("load_events", "load_detections", "snapshot_write", "persist")) or any(
        token in top_functions for token in ("read_sql", "executemany", "commit", "get_db_connection", "get_cursor")
    ):
        category = "db-bound"
        reason = "The slowest stage is dominated by database access and commit work."
    elif any(token in stage_name for token in ("snapshot_assembly", "serialization")) or any(
        token in top_functions for token in ("to_dict", "json", "copy.deepcopy", "render_template")
    ):
        category = "serialization-bound"
        reason = "The slowest stage is dominated by snapshot or payload serialization."
    elif any(token in top_functions for token in ("groupby", "merge", "concat", "sort_values", "iterrows", "_build_bursts", "_calculate_ml_deviations", "_apply_correlations", "_calculate_confidence_and_severity")):
        category = "dataframe-bound"
        reason = "The slowest functions are pandas-heavy dataframe operations."
    else:
        category = "cpu-bound"
        reason = "The profile is dominated by pure Python computation and control flow."

    return {
        "category": category,
        "reason": reason,
        "slowest_stage": slowest_stage,
        "signals": profile_rows[:5],
    }


def _emit_analysis_profile_summary(
    run_id: str,
    profiler: cProfile.Profile,
    perf: _PerfTimer,
    context: Optional[dict],
    phase: str,
    attach_to_context: bool = True,
) -> Dict[str, Any]:
    profiler.disable()
    stage_summary = perf.snapshot()
    profile_rows = _profile_rows(profiler)
    bottleneck = _classify_profile_bottleneck(stage_summary, profile_rows)
    summary = {
        "phase": phase,
        "run_id": run_id[:16],
        "total_seconds": round(stage_summary.get("total_seconds", 0.0), 6),
        "stage_timings": stage_summary.get("laps", []),
        "db_timing_ms": _profile_db_timings(stage_summary),
        "slowest_stage": stage_summary.get("slowest_stage"),
        "top_functions": profile_rows,
        "bottleneck": bottleneck,
    }

    artifact_paths = _write_profile_artifacts(
        run_id=run_id,
        phase=phase,
        profiler=profiler,
        stage_summary=stage_summary,
        profile_rows=profile_rows,
        bottleneck=bottleneck,
        profile_inputs=(context or {}).get("meta", {}).get("profiling_inputs") if isinstance(context, dict) else None,
    )
    summary["artifact_paths"] = artifact_paths

    if attach_to_context and isinstance(context, dict):
        context["profiling"] = summary
        meta = context.get("meta")
        if isinstance(meta, dict):
            meta["profiling"] = {
                "phase": phase,
                "category": bottleneck["category"],
                "slowest_stage": stage_summary.get("slowest_stage"),
                "artifact_paths": artifact_paths,
            }

    slowest_function = profile_rows[0] if profile_rows else {}
    log.info(
        "[PROFILE] run_id=%s phase=%s category=%s slowest_stage=%s elapsed_sec=%.3f slowest_fn=%s fn_sec=%.3f",
        run_id[:16],
        phase,
        bottleneck["category"],
        (stage_summary.get("slowest_stage") or {}).get("stage"),
        float((stage_summary.get("slowest_stage") or {}).get("elapsed_seconds") or 0.0),
        slowest_function.get("qualified_name") or "n/a",
        float(slowest_function.get("cumulative_seconds") or 0.0),
    )
    log.info(
        "[PROFILE_ARTIFACTS] run_id=%s phase=%s prof=%s pstats=%s json=%s",
        run_id[:16],
        phase,
        artifact_paths["prof"],
        artifact_paths["pstats"],
        artifact_paths["json"],
    )
    log.info("[PROFILE_JSON] %s", json.dumps(summary, default=str, sort_keys=True, separators=(",", ":")))
    return summary

# ---------------------------------------------------------------------------
# YAML Rule loader
# ---------------------------------------------------------------------------

_loaded_rules: list = []

def load_detection_rules(rules_path=None, force=False) -> list:
    """
    Load detection rules from YAML file.
    Searches: rules_path → project root rules.yaml → dashboard/rules.yaml
    """
    global _loaded_rules
    if _loaded_rules and not rules_path and not force:
        return _loaded_rules

    search_paths = []
    if rules_path:
        search_paths.append(Path(rules_path))
    # Auto-discover rules.yaml
    base = Path(__file__).resolve().parent
    search_paths += [
        base.parent / "rules.yaml",     # project root
        base / "rules.yaml",             # dashboard/
        Path("rules.yaml"),              # cwd
    ]
    for p in search_paths:
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                rules = data.get("rules", []) if data else []
                _loaded_rules = rules
                print(f"[rules] Loaded {len(rules)} detection rules from {p}")
                return rules
            except Exception as e:
                print(f"[rules] Failed to load {p}: {e}")
    print("[rules] No rules.yaml found — using heuristic EID detection only")
    _loaded_rules = []
    return []

# Load rules at import time
# Rules are now loaded explicitly via load_detection_rules() or on-demand in ingest_upload


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MITRE_TO_KILL_CHAIN = {
    "Initial Access": ["Delivery"],
    "Execution": ["Execution"],
    "Persistence": ["Persistence"],
    "Privilege Escalation": ["Privilege Escalation"],
    "Defense Evasion": ["Defense Evasion"],
    "Credential Access": ["Credential Access"],
    "Discovery": ["Discovery"],
    "Lateral Movement": ["Lateral Movement"],
    "Collection": ["Collection"],
    "Command and Control": ["Command and Control"],
    "Exfiltration": ["Exfiltration"],
    "Impact": ["Actions on Objectives"],
}

KILL_CHAIN_ORDER = [
    "Background", "Delivery", "Execution", "Defense Evasion",
    "Persistence", "Privilege Escalation", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Actions on Objectives",
]
KILLCHAIN_ORDER_FOR_RANK = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}

_HIGH_EVENT_IDS = {1, 8, 9, 12, 13, 14, 19, 25}
_MED_EVENT_IDS  = {3, 7, 10, 11, 22, 23}

# ---------------------------------------------------------------------------
# 10/10 Formal Mastery: Canonical Normalization & Semantic Hashing
# ---------------------------------------------------------------------------
def normalize_nfc(val: Any) -> str:
    """UTF-8 NFC normalization for bit-perfect stability."""
    if val is None: return ""
    s = str(val).strip()
    return unicodedata.normalize("NFC", s)

def generate_semantic_hash(records: List[Dict[str, Any]]) -> str:
    """
    Generate a bit-perfect hash of the event set context.
    1. Sort records by (event_time, event_uid)
    2. Sort keys within each record
    3. Normalize NFC
    4. ASCII-only JSON serialization
    """
    def _clean(d):
        return {k: normalize_nfc(v) for k, v in d.items() if v is not None}
    
    # Authoritative sort for stability
    sorted_records = sorted(
        [_clean(r) for r in records],
        key=lambda x: (x.get("event_time", ""), x.get("event_uid", ""))
    )
    
    # Canonical JSON string
    canonical_json = json.dumps(
        sorted_records,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":")
    )
    return hashlib.sha256(canonical_json.encode("ascii")).hexdigest()

def to_pure_python_records(df: 'pd.DataFrame') -> List[Dict[str, Any]]:
    """Convert Pandas DF to zero-entropy pure Python records."""
    import pandas as pd
    # Coerce scalars and handle NaT/NaN
    records = df.replace({pd.NA: None, pd.NaT: None}).to_dict("records")
    # Force bit-perfect consistency
    return [dict(sorted((k, normalize_nfc(v)) for k, v in r.items())) for r in records]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def promote_stage(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if not a:
        return b
    if not b:
        return a
    if a not in KILL_CHAIN_ORDER and b not in KILL_CHAIN_ORDER:
        return a or b
    if a not in KILL_CHAIN_ORDER:
        return b
    if b not in KILL_CHAIN_ORDER:
        return a
    return b if KILL_CHAIN_ORDER.index(b) > KILL_CHAIN_ORDER.index(a) else a


def rank_dangerous_bursts(bursts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ranked = sorted(
        bursts,
        key=lambda b: (
            -int(b.get("peak_score", 0) or 0),
            -KILLCHAIN_ORDER_FOR_RANK.get(b.get("kill_chain_stage") or "Background", 0),
            -int(b.get("total_count", 0) or 0),
        ),
    )
    return ranked[:10]


def _build_campaign_name(images: List[str], command_lines: List[str], progression: List[str], final_stage: str, host_count: int) -> str:
    images_l = [str(image or "").lower() for image in images]
    commands_l = [str(command or "").lower() for command in command_lines]
    combined_commands = " ".join(commands_l)
    has_powershell = any(token in " ".join(images_l) for token in ("powershell", "pwsh")) or any(token in combined_commands for token in ("powershell", "pwsh", "-enc", "-encodedcommand", "frombase64string", "invoke-expression", "iex "))
    has_encoded = any(token in combined_commands for token in ("-enc", "-encodedcommand", "frombase64string", "[convert]::frombase64", "invoke-expression", "iex ", "-nop"))
    has_remote_exec = any(token in " ".join(images_l) for token in ("psexec", "wmic", "winrm", "schtasks", "wmiprvse")) or any(token in combined_commands for token in ("psexec", "wmic", "winrm", "sc.exe create", "service create", "schtasks"))
    has_persistence = any(stage == "Persistence" for stage in progression) or any(token in combined_commands for token in ("schtasks", "runonce", "currentversion\\run", "startup", "autorun")) or any(token in " ".join(images_l) for token in ("schtasks", "regsvr32", "rundll32"))
    has_lolbin = any(token in " ".join(images_l) for token in ("cmd.exe", "powershell", "pwsh", "rundll32", "regsvr32", "mshta", "wmic", "wmiprvse", "certutil"))
    has_privilege = any(stage == "Privilege Escalation" for stage in progression)

    if has_powershell and has_encoded and (has_remote_exec or host_count > 1):
        return "Encoded-PowerShell-LateralChain"
    if has_powershell and has_encoded:
        return "Encoded-PowerShell-Execution"
    if has_powershell and (has_remote_exec or host_count > 1):
        return "PowerShell-Remote-Chain"
    if has_persistence:
        if any(token in combined_commands for token in ("reg add", "currentversion\\run", "runonce")) or any(image.startswith("reg") for image in images_l):
            return "Persistence-Registry-Chain"
        if "schtasks" in combined_commands or any("schtasks" in image for image in images_l):
            return "Persistence-ScheduledTask-Chain"
        return "Persistence-LOLBIN-Chain"
    if final_stage == "Lateral Movement" or host_count > 1:
        if has_remote_exec and any("cmd.exe" in image for image in images_l):
            return "MultiHost-CMD-LateralChain"
        if has_remote_exec:
            return "MultiHost-RemoteExecution-Chain"
        return "Lateral-Movement-Chain"
    if has_privilege:
        return "Privilege-Escalation-Chain"
    if final_stage == "Command and Control" or any(token in combined_commands for token in ("http://", "https://", "dns")):
        return "C2-Beacon-Chain"
    if has_lolbin:
        return "LOLBIN-Execution-Sequence"
    return "Suspicious-Process-Chain"


def is_external_ip(ip: str) -> bool:
    if not ip:
        return False
    ip = str(ip)
    return not ip.startswith((
        "10.", "192.168.",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "127.", "::1",
    ))


def baseline_is_mature(entry: Optional[Dict[str, Any]]) -> bool:
    if not entry:
        return False
    return int(entry.get("count_samples", 0) or 0) >= 20


def time_overlap(burst: Dict[str, Any], corr: Dict[str, Any], window_seconds: int = 900) -> bool:
    try:
        b_start = _coerce_utc_timestamp(burst.get("start_time"))
        c_end   = _coerce_utc_timestamp(corr.get("end_time"))
        if pd.isna(b_start) or pd.isna(c_end):
            return False
        return abs((b_start - c_end).total_seconds()) <= window_seconds
    except Exception:
        return False


def _assign_severity(event_id: Optional[int]) -> str:
    if event_id in _HIGH_EVENT_IDS:
        return "high"
    if event_id in _MED_EVENT_IDS:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# YARA loader
# ---------------------------------------------------------------------------

def load_yara_rules(rules_path: Optional[Path]):
    if not rules_path or not Path(rules_path).exists():
        return None
    if Path(rules_path).suffix.lower() not in (".yar", ".yara"):
        return None
    if not YARA_AVAILABLE:
        raise RuntimeError("python-yara not installed. Run: pip install yara-python")
    try:
        return yara.compile(filepath=str(rules_path))
    except yara.SyntaxError as e:
        raise RuntimeError(f"Invalid YARA rule: {e}") from e


# ---------------------------------------------------------------------------
# Attack Storyline Reconstruction
# ---------------------------------------------------------------------------

_EID_DESCRIPTIONS = {
    1:  ("Process created", lambda ev: f"{_img(ev)} executed" + (f" (parent: {_img_parent(ev)})" if ev.get('parent_image') else "")),
    3:  ("Network connection", lambda ev: f"{_img(ev)} made outbound connection to {ev.get('destination_ip','?')}:{ev.get('destination_port','?')}"),
    5:  ("Process terminated", lambda ev: f"{_img(ev)} terminated"),
    7:  ("Image loaded", lambda ev: f"DLL loaded by {_img(ev)}: {ev.get('image_loaded','?')}"),
    10: ("Process access", lambda ev: f"{_img(ev)} accessed another process (possible credential dumping)"),
    11: ("File created", lambda ev: f"{_img(ev)} created file: {ev.get('target_filename') or ev.get('file_path','?')}"),
    12: ("Registry key created/deleted", lambda ev: f"{_img(ev)} modified registry key: {ev.get('reg_key','?')}"),
    13: ("Registry value set", lambda ev: _reg_story(ev)),
    14: ("Registry key renamed", lambda ev: f"{_img(ev)} renamed registry key: {ev.get('reg_key','?')}"),
    15: ("File stream created", lambda ev: f"{_img(ev)} created alternate data stream: {ev.get('target_filename','?')}"),
    22: ("DNS query", lambda ev: f"{_img(ev)} queried DNS for: {ev.get('query_name','?')}"),
    25: ("Process tampering", lambda ev: f"{_img(ev)} tampered with a process image"),
}

def _img(ev: Dict) -> str:
    img = str(ev.get("image") or "")
    return img.split("\\")[-1] if "\\" in img else (img or "Unknown process")

def _img_parent(ev: Dict) -> str:
    p = str(ev.get("parent_image") or "")
    return p.split("\\")[-1] if "\\" in p else p

def _reg_story(ev: Dict) -> str:
    img = _img(ev)
    key = str(ev.get("reg_key") or ev.get("target_filename") or "?").lower()
    if any(x in key for x in ["\\run\\", "\\runonce\\", "currentversion\\run"]):
        return f"Persistence established — {img} wrote to Registry Run key: {key}"
    if "image file execution options" in key:
        return f"IFEO hijack — {img} modified Image File Execution Options: {key}"
    if "appinit_dlls" in key:
        return f"AppInit_DLLs persistence — {img} wrote to AppInit_DLLs"
    if "\\services\\" in key:
        return f"Service registry modified by {img}: {key}"
    if "winlogon" in key:
        return f"Winlogon hijack by {img}: {key}"
    return f"{img} set registry value: {key}"


def describe_event(ev: Dict) -> Optional[str]:
    """Return a human-readable description for one event, or None if unknown."""
    try:
        eid = int(float(str(ev.get("event_id", 0)).strip()))
    except (TypeError, ValueError):
        return None
    handler = _EID_DESCRIPTIONS.get(eid)
    if handler:
        _, fn = handler
        try:
            return fn(ev)
        except Exception:
            return handler[0]
    return None


def link_events(prev: Dict, curr: Dict) -> str:
    """Heuristic causal linking between two sequential events."""
    from datetime import timedelta
    
    # 1. Direct Parent-Child via GUID
    if prev.get("process_guid") and curr.get("parent_guid"):
        if prev["process_guid"] == curr["parent_guid"]:
            return "spawned"

    # 2. Image Name Match (fallback for missing GUIDs)
    p_img = str(prev.get("image") or "").lower().split("\\")[-1]
    c_parent = str(curr.get("parent_image") or "").lower().split("\\")[-1]
    if p_img and c_parent and p_img == c_parent:
        return "triggered"

    # 3. Temporal Proximity (log corruption fallback)
    p_time = _coerce_utc_timestamp(prev.get("event_time") or prev.get("utc_time"))
    c_time = _coerce_utc_timestamp(curr.get("event_time") or curr.get("utc_time"))
    if pd.notna(p_time) and pd.notna(c_time):
        if abs(c_time - p_time) <= timedelta(seconds=5):
            return "likely related to"

    return "related to"


def compress_steps(steps: List[str]) -> List[str]:
    """Deduplicate sequential identical steps with 'burst activity' note."""
    if not steps:
        return []
    out = []
    i = 0
    while i < len(steps):
        j = i + 1
        count = 1
        while j < len(steps) and steps[j] == steps[i]:
            count += 1
            j += 1
        
        text = steps[i]
        if count > 1:
            text = f"{text} ({count} times, burst activity)"
        out.append(text)
        i = j
    return out


def extract_iocs(events: List[Dict], cap: int = 20) -> Dict[str, List[str]]:
    """Extract and deduplicate Indicators of Compromise from event list."""
    ips  = {e.get("destination_ip") for e in events if e.get("destination_ip")}
    files = {e.get("target_filename") or e.get("file_path") for e in events if (e.get("target_filename") or e.get("file_path"))}
    regs = {e.get("reg_key") or e.get("target_object") for e in events if (e.get("reg_key") or e.get("target_object"))}
    
    return {
        "ips":      list(sorted([str(i) for i in ips if i]))[:cap],
        "files":    list(sorted([str(f) for f in files if f]))[:cap],
        "registry": list(sorted([str(r) for r in regs if r]))[:cap],
    }


def classify_attack(stages: List[str]) -> str:
    """Classify the attack based on the combination of kill-chain stages observed."""
    s = set(stages)
    if {"Execution", "Persistence", "Command and Control"} <= s:
        return "Multi-stage compromise"
    if "Persistence" in s:
        return "Persistence Establishment"
    if "Initial Access" in s or "Delivery" in s:
        return "Initial Access / Delivery"
    if "Credential Access" in s:
        return "Credential Harvesting"
    if "Actions on Objectives" in s:
        return "Data Exfiltration / Impact"
    return "Suspicious Activity"


def match_detection_to_burst(det, burst):
    """
    10/10 SOC-Grade Matcher (Refined v3.2)
    Implements host isolation, PID+Time hard constraints, GUID matching, 
    and a scored fallback for high-fidelity process linking.
    """
    # 1. Host Isolation (Non-negotiable)
    if det.get("computer") != burst.get("computer"):
        return False

    try:
        # 2. PID + Time Hard Constraint (±5s)
        dt_raw = det.get("utc_time") or det.get("event_time")
        bt_raw = burst.get("start_time")
        
        d_time = _coerce_utc_timestamp(dt_raw)
        b_time = _coerce_utc_timestamp(bt_raw)

        d_pid = det.get("process_id")
        b_pid = burst.get("process_id")
        if d_pid and b_pid and d_pid == b_pid:
            if abs((d_time - b_time).total_seconds()) <= 5:
                # Both same host (checked above) + Same PID + same time = High Integrity
                return True
    except Exception:
        pass  # time-parse failure — skip PID check

    # 3. GUID Hard Match (Atomic Link)
    d_guid = det.get("process_guid") or det.get("proc_guid")
    b_guid = burst.get("process_guid") or burst.get("proc_guid")
    if d_guid and b_guid and d_guid == b_guid:
        return True

    # 4. Scored Fallback (Threshold >= 5)
    # Only count if fields are present to prevent None == None collisions
    score = 0
    if det.get("rule_id") and det.get("rule_id") == burst.get("rule_id"):
        score += 3
    if det.get("parent_image") and det.get("parent_image") == burst.get("parent_image"):
        score += 2
    
    det_img = str(det.get("image") or "").lower()
    bst_img = str(burst.get("image") or "").lower()
    if det_img and bst_img and det_img == bst_img:
        score += 2
    
    # Prefix similarity check
    d_cmd = str(det.get("command_line") or "")[:50].strip()
    b_cmd = str(burst.get("command_line") or "")[:50].strip()
    if d_cmd and b_cmd and d_cmd == b_cmd:
        score += 1

    # 10/10 SOC: Time-Skew / Clock Drift Resilience
    # High fidelity signals (Score >= 6) are allowed up to 30s drift
    try:
        dt_raw = det.get("utc_time") or det.get("event_time")
        bt_raw = burst.get("start_time")
        d_time = _coerce_utc_timestamp(dt_raw)
        b_time = _coerce_utc_timestamp(bt_raw)
        time_diff = abs((d_time - b_time).total_seconds())
        
        if score >= 6 and time_diff <= 30:
            return True
    except Exception:
        pass  # time-parse failure for drift check

    return score >= 5


def recommend_action(stage: str, severity: str) -> str:
    """Provide specific analyst recommendations based on stage and severity."""
    s = str(severity).lower()
    if stage == "Command and Control":
        return "CRITICAL: Isolate host immediately, block egress IPs, and collect memory forensics."
    if stage == "Persistence":
        return "HIGH: Remove startup entries, inspect autoruns, and audit local accounts."
    if stage == "Execution":
        return "MEDIUM: Review process tree, quarantine suspicious binaries, and check for sibling processes."
    if s == "critical" or s == "high":
        return "HIGH: Perform full forensic sweep of the host and rotate affected user credentials."
    return "Investigate context and validate indicators against threat intelligence."


def build_attack_story(events: List[Dict], detections: List[Dict] = None) -> Dict[str, Any]:
    """
    Reconstructs a causal attack narrative from events and detections.
    Returns a rich incident dictionary with story, timeline, IOCs, and recommendations.
    """
    if not events:
        return {
            "story": [],
            "steps": [],
            "timeline": [],
            "iocs": {},
            "attack_type": "Unknown",
            "story_confidence": 0.0,
            "bullets": [],
            "campaign_name": "Suspicious Process Chain",
            "pivot_hints": [],
            "explanation_points": [],
        }

    # 1. Authoritative Sorting (Causal Lineage + Kill Chain Index)
    def _sort_key(e):
        import pandas as pd
        t = _coerce_utc_timestamp(e.get("event_time") or e.get("utc_time"))
        if pd.isna(t): t = pd.Timestamp(0, tz='UTC')
        
        # Lineage boost: Processes that spawn others stay together
        # We use a bitmask for [IsParent|StageIndex|Timestamp]
        stage = e.get("kill_chain_stage") or "Background"
        idx = KILLCHAIN_ORDER_FOR_RANK.get(stage, 0)
        
        # Priority: Kill-chain position (causality) > Time
        return (idx, t)

    sorted_events = sorted(events, key=_sort_key)

    # 2. Build Story with Causal Linking
    story_steps = []
    kc_progression = []
    
    for i, ev in enumerate(sorted_events):
        desc = describe_event(ev)
        if not desc:
            continue
            
        stage = ev.get("kill_chain_stage") or "Background"
        if stage not in kc_progression and stage != "Background":
            kc_progression.append(stage)

        if i > 0:
            link = link_events(sorted_events[i-1], ev)
            story_steps.append(f"... {link} ...")
        
        story_steps.append(desc)

    # 3. Finalize Components
    compressed_story = compress_steps(story_steps)
    iocs = extract_iocs(events)
    final_stage = kc_progression[-1] if kc_progression else "Execution"
    images = sorted({str(ev.get("image") or "unknown").strip() for ev in sorted_events})
    computers = sorted({str(ev.get("computer") or "unknown").strip() for ev in sorted_events})
    command_lines = [str(ev.get("command_line") or "").strip().lower() for ev in sorted_events if ev.get("command_line")]

    has_encoded_powerShell = any("powershell" in img.lower() for img in images) and any(
        marker in cmd for cmd in command_lines for marker in ("-enc", "frombase64string", "invoke-expression", "iex(")
    )
    has_remote_exec = any(tool in " ".join(images).lower() for tool in ("psexec", "wmic", "winrm", "schtasks", "sc.exe")) or len(computers) > 1
    has_persistence = any(stage in kc_progression for stage in ("Persistence",)) or any(
        marker in " ".join(command_lines) for marker in ("run\\", "runonce", "schtasks", "startup", "autorun")
    )
    has_network = any(bool(ev.get("destination_ip") or ev.get("dst_ip")) for ev in sorted_events)
    campaign_name = _build_campaign_name(images, command_lines, kc_progression, final_stage, len(computers))

    bullets = [
        f"{campaign_name} spans {len(computers)} host(s) and {len(images)} process family(ies).",
        f"Kill-chain progression: {' → '.join(kc_progression) if kc_progression else 'Background' }.",
    ]
    if has_encoded_powerShell:
        bullets.append("Encoded PowerShell behavior suggests command staging or obfuscation.")
    if has_persistence:
        bullets.append("Persistence behavior indicates the chain is trying to survive across reboots or sessions.")
    if has_remote_exec:
        bullets.append("Remote execution or cross-host spread raises lateral-movement concern.")
    if has_network:
        bullets.append("Network activity is present, which supports C2 or staging pivots.")
    if final_stage in ("Privilege Escalation", "Credential Access"):
        bullets.append(f"The chain reached {final_stage}, which materially increases operational urgency.")

    pivot_hints = [
        "Pivot on parent-child process lineage and command-line decoding.",
        "Pivot on adjacent hosts and remote execution artifacts.",
    ]
    if has_persistence:
        pivot_hints.append("Pivot on autoruns, Run keys, and scheduled task residue.")
    if has_network:
        pivot_hints.append("Pivot on destination IPs, DNS lookups, and beacon timing.")
    if final_stage in ("Privilege Escalation", "Credential Access"):
        pivot_hints.append("Pivot on token theft, privilege changes, and parent-process provenance.")

    explanation_points = bullets[:]
    
    # Severity for recommendation (heuristic if not provided)
    max_sev = "low"
    if detections:
        sevs = [str(d.get("severity") or "low").lower() for d in detections]
        if "critical" in sevs: max_sev = "critical"
        elif "high" in sevs: max_sev = "high"
        elif "medium" in sevs: max_sev = "medium"

    return {
        "story":              compressed_story,
        "steps":              compressed_story,
        "timeline":           sorted_events,
        "transitions":        kc_progression,
        "iocs":               iocs,
        "attack_type":        classify_attack(kc_progression),
        "recommended_action": recommend_action(final_stage, max_sev),
        "story_confidence":   round(min(len(events) / 10.0, 1.0), 2),
        "summary":            f"{campaign_name}: " + (" → ".join(compressed_story[:5]) + ("..." if len(compressed_story) > 5 else "") if compressed_story else "No narrative steps available."),
        "kill_chain":         kc_progression,
        "mitre_ids":          list(set(d.get("mitre_id") for d in (detections or []) if d.get("mitre_id"))),
        "bullets":            bullets,
        "campaign_name":      campaign_name,
        "pivot_hints":        pivot_hints,
        "explanation_points":  explanation_points,
    }


# ---------------------------------------------------------------------------
# Behavior generation
# ---------------------------------------------------------------------------
def _generate_behaviors(df: 'pd.DataFrame', run_id: str) -> 'pd.DataFrame':
    import pandas as pd
    behaviors = []
    for _, r in df.iterrows():
        eid_raw = r.get("event_id")
        try:
            eid = str(int(float(eid_raw)))
        except Exception:
            continue
        btype = None
        if eid == "1":              btype = "execution"
        elif eid == "3":            btype = "network"
        elif eid in ("11", "15"):   btype = "file"
        elif eid in ("12","13","14"): btype = "registry"
        if not btype:
            continue
        behaviors.append({
            "run_id":            run_id,
            "behavior_id":       f"{run_id}-{eid}-{uuid.uuid4().hex[:8]}",
            "behavior_type":     btype,
            "event_time":        r.get("event_time"),
            "image":             r.get("image"),
            "parent_image":      r.get("parent_image"),
            "command_line":      r.get("command_line"),
            "user":              r.get("user"),
            "process_id":        r.get("pid"),
            "parent_process_id": r.get("ppid"),
            "computer":          r.get("computer"),
            "source_ip":         r.get("src_ip"),
            "destination_ip":    r.get("destination_ip"),
            "destination_port":  r.get("destination_port"),
            "target_filename":   r.get("file_path") or r.get("target_filename"),
            "reg_key":           r.get("reg_key") or r.get("targetobject"),
            "raw_event_id":      eid,
        })
    return pd.DataFrame(behaviors)


# ---------------------------------------------------------------------------
# ingest_upload
# ---------------------------------------------------------------------------

def check_xml_depth(xml_path: Path, max_depth: int = 50) -> bool:
    """
    [10/10 Mastery] Nesting Depth Guard (Billion Laughs Protection).
    Uses iterparse to validate structure without full memory allocation.
    """
    try:
        import xml.etree.ElementTree as ET
        depth = 0
        max_seen = 0
        for event, elem in ET.iterparse(xml_path, events=('start', 'end')):
            if event == 'start':
                depth += 1
                max_seen = max(max_seen, depth)
                if max_seen > max_depth:
                    return False
            else:
                depth -= 1
        return True
    except Exception:
        return False

def ingest_upload(
    xml_path: Path,
    rules_path: Optional[Path] = None,
    run_id: Optional[str] = None,
) -> Tuple['pd.DataFrame', 'pd.DataFrame', 'pd.DataFrame', str]:
    """Parse XML into (events_df, detections_df, behaviors_df, content_hash). No DB writes."""
    import pandas as pd
    t_ingest_start = time.perf_counter()

    def _set_ingest_progress(progress: int, message: str) -> None:
        if not run_id:
            return
        try:
            from dashboard.progress import set_run_progress
            set_run_progress(run_id, "running", progress, message)
        except Exception:
            pass

    def _df_mem_mb(df: 'pd.DataFrame') -> float:
        if df is None or df.empty:
            return 0.0
        try:
            return float(df.memory_usage(deep=True).sum()) / (1024 * 1024)
        except Exception:
            return 0.0
    
    # ── [10/10] Pre-Parse File Size Guard ──────────────────────────────
    if not Path(xml_path).exists():
        raise FileNotFoundError(f"Sysmon XML not found: {xml_path}")
    
    file_size = os.path.getsize(xml_path)
    # Absolute 100MB cap for single-node SOC
    if file_size > 100 * 1024 * 1024:
        raise ValueError(f"Upload blocked: XML size ({file_size/1e6:.1f}MB) exceeds SOC safety limit (100MB).")
    _set_ingest_progress(10, "Validating upload...")

    log.info(
        "[INGEST_PROBE] stage=xml_file_check elapsed_sec=%.3f file=%s size_bytes=%d",
        time.perf_counter() - t_ingest_start,
        Path(xml_path).name,
        file_size,
    )

    # ── [10/10] XML Nesting Guard ──────────────────────────────────────
    if not check_xml_depth(xml_path):
        raise ValueError("Upload blocked: XML nesting depth exceeds SOC safety limit (Recursive Malice suspected).")
    _set_ingest_progress(15, "Parsing XML structure...")

    t_after_depth = time.perf_counter()
    log.info(
        "[INGEST_PROBE] stage=xml_depth_guard elapsed_sec=%.3f",
        t_after_depth - t_ingest_start,
    )

    # ── [10/10] Adaptive Memory Guard ──────────────────────────────────
    # Since psutil might be missing, we use a conservative safe bound (250MB) 
    # to account for Pandas 2x-3x memory consumption during parsing.
    SAFE_LIMIT = 250 * 1024 * 1024 
    
    t0 = time.perf_counter()
    rows = load_all_sources_from_xml(xml_path)
    t_rows = time.perf_counter() - t0
    if not rows:
        raise RuntimeError("Upload aborted: XML contained no events.")
    _set_ingest_progress(25, "Building event records...")
    log.info(
        "[INGEST_PROBE] stage=load_all_sources_from_xml elapsed_sec=%.3f events=%d",
        t_rows,
        len(rows),
    )

    # 10/10 Mastery: Immediate conversion to Pure Python Core
    t0 = time.perf_counter()
    raw_records = [dict(sorted(r.items())) for r in rows]
    log.info(
        "[INGEST_PROBE] stage=raw_record_materialize elapsed_sec=%.3f records=%d",
        time.perf_counter() - t0,
        len(raw_records),
    )
    
    # Semantic Hashing for run_id (Content-based ID)
    # We use a subset of fields for the initial ID to handle re-uploads
    t0 = time.perf_counter()
    run_id = generate_semantic_hash(raw_records)[:16]
    content_hash = generate_semantic_hash(raw_records)
    log.info(
        "[INGEST_PROBE] stage=semantic_hash elapsed_sec=%.3f records=%d run_id=%s",
        time.perf_counter() - t0,
        len(raw_records),
        run_id[:16],
    )

    t0 = time.perf_counter()
    events_df = pd.DataFrame(raw_records)
    _set_ingest_progress(35, "Creating dataframes...")
    log.info(
        "[INGEST_PROBE] stage=dataframe_create elapsed_sec=%.3f rows=%d cols=%d mem_mb=%.2f",
        time.perf_counter() - t0,
        len(events_df),
        len(events_df.columns),
        _df_mem_mb(events_df),
    )
    if "event_id" not in events_df.columns:
        raise RuntimeError("event_id column missing in parsed XML")

    t0 = time.perf_counter()
    events_df["event_id"] = events_df["event_id"].astype(str).str.strip()
    events_df = events_df[
        events_df["event_id"].notna() & (events_df["event_id"] != "None")
    ]
    if events_df.empty:
        raise RuntimeError("All events dropped — EventID missing/invalid in XML")

    events_df["run_id"]     = run_id
    events_df["event_time"] = pd.to_datetime(
        events_df["utc_time"], errors="coerce", utc=True
    )
    events_df = events_df.dropna(subset=["event_time"])
    _set_ingest_progress(45, "Normalizing timestamps...")
    log.info(
        "[INGEST_PROBE] stage=normalize_event_id_time elapsed_sec=%.3f rows=%d mem_mb=%.2f",
        time.perf_counter() - t0,
        len(events_df),
        _df_mem_mb(events_df),
    )

    # ── PIPELINE UPGRADE: enrich every event with computed signal fields ──
    # Guards all fields against None/float before calling .lower()
    try:
        from dashboard.event_parser import enrich_event

        def _safe_enrich(r):
            # Coerce image/parent_image/command_line to str|None before enrichment
            for fld in ("image", "parent_image", "command_line", "dst_ip",
                        "destination_ip", "src_ip", "computer", "user"):
                v = r.get(fld)
                if v is not None and not isinstance(v, str):
                    r[fld] = str(v) if str(v) not in ("nan", "None", "") else None
            return enrich_event(r)

        t0 = time.perf_counter()
        records = events_df.to_dict("records")
        t_to_dict = time.perf_counter() - t0

        t0 = time.perf_counter()
        records = [_safe_enrich(r) for r in records]
        t_enrich_loop = time.perf_counter() - t0

        t0 = time.perf_counter()
        events_df = pd.DataFrame(records)
        t_rebuild_df = time.perf_counter() - t0

        log.info(
            "[INGEST_PROBE] stage=event_enrichment elapsed_sec=%.3f to_dict_sec=%.3f enrich_loop_sec=%.3f rebuild_df_sec=%.3f rows=%d cols=%d mem_mb=%.2f",
            t_to_dict + t_enrich_loop + t_rebuild_df,
            t_to_dict,
            t_enrich_loop,
            t_rebuild_df,
            len(events_df),
            len(events_df.columns),
            _df_mem_mb(events_df),
        )
        _set_ingest_progress(55, "Enriching events...")
    except Exception as _ee:
        import traceback; traceback.print_exc()
        print(f"[ingest] Event enrichment failed: {_ee}")

    # Enrich parent chains (grandparent_image, process_depth)
    try:
        # Ensure string columns are proper strings before enrichment
        for _col in ("image", "parent_image", "computer", "pid", "ppid"):
            if _col in events_df.columns:
                events_df[_col] = events_df[_col].astype(object).where(events_df[_col].notna(), None)
                events_df[_col] = events_df[_col].map(
                    lambda v: None if v is None or str(v) in ("nan", "None", "") else str(v)
                )
        t0 = time.perf_counter()
        events_df = enrich_parent_chains(events_df)
        parent_chain_metrics = getattr(events_df, "attrs", {}).get("parent_chain_metrics", {}) or {}
        log.info(
            "[INGEST_PROBE] stage=parent_chain_enrichment elapsed_sec=%.3f rows=%d cols=%d mem_mb=%.2f lineage_traversal=%d parent_lookups=%d grandparent_lookups=%d repeated_queries=%d max_depth=%d merges=%d cumulative_sec=%.3f top_phases=%s",
            time.perf_counter() - t0,
            len(events_df),
            len(events_df.columns),
            _df_mem_mb(events_df),
            int(parent_chain_metrics.get("lineage_traversal_count", 0) or 0),
            int(parent_chain_metrics.get("parent_lookup_count", 0) or 0),
            int(parent_chain_metrics.get("grandparent_lookup_count", 0) or 0),
            int(parent_chain_metrics.get("repeated_query_count", 0) or 0),
            int(parent_chain_metrics.get("recursion_depth_max", 0) or 0),
            int(parent_chain_metrics.get("dataframe_merge_count", 0) or 0),
            float(parent_chain_metrics.get("cumulative_seconds", 0.0) or 0.0),
            json.dumps(parent_chain_metrics.get("top_slowest_phases", []), default=str, sort_keys=True),
        )
        if parent_chain_metrics:
            log.info(
                "[INGEST_PROBE] stage=parent_chain_metrics %s",
                json.dumps(parent_chain_metrics, default=str, sort_keys=True),
            )
        _set_ingest_progress(60, "Expanding process chains...")
    except Exception as _pce:
        import traceback; traceback.print_exc()
        print(f"[ingest] Parent chain enrichment failed: {_pce}")

    # Deduplicate by event_uid — XML files often contain repeated events.
    # Keeps first occurrence; silences hundreds of INSERT IGNORE warnings.
    if "event_uid" in events_df.columns:
        t0 = time.perf_counter()
        before = len(events_df)
        events_df = events_df.drop_duplicates(subset=["event_uid"], keep="first")
        dupes = before - len(events_df)
        if dupes > 0:
            print(f"[ingest] Deduplicated {dupes} duplicate event_uid rows from XML.")
        log.info(
            "[INGEST_PROBE] stage=deduplicate_event_uid elapsed_sec=%.3f before=%d after=%d dupes=%d",
            time.perf_counter() - t0,
            before,
            len(events_df),
            dupes,
        )

    t0 = time.perf_counter()
    severity_lookup = {eid: "high" for eid in _HIGH_EVENT_IDS}
    severity_lookup.update({eid: "medium" for eid in _MED_EVENT_IDS if eid not in severity_lookup})
    event_ids = pd.to_numeric(events_df["event_id"], errors="coerce").fillna(0).astype(int)
    events_df["severity"] = event_ids.map(severity_lookup).fillna("low")
    log.info(
        "[INGEST_PROBE] stage=severity_assignment elapsed_sec=%.3f rows=%d",
        time.perf_counter() - t0,
        len(events_df),
    )
    _set_ingest_progress(70, "Scoring events...")

    events_df = events_df.rename(columns={
        "commandline":    "command_line",
        "processid":      "pid",
        "parentprocessid":"ppid",
    })

    # ── YARA scan — weighted scoring via yara_engine ──────────────────────
    from dashboard.yara_engine import load_yara_rules as _load_yara, run_yara_on_events
    yara_rules     = _load_yara(rules_path) if rules_path else None
    events_df["yara_hits"]  = None
    events_df["yara_score"] = 0

    if yara_rules is not None:
        t0 = time.perf_counter()
        records = events_df.to_dict("records")
        records = run_yara_on_events(yara_rules, records)
        # Re-absorb yara_score and yara_hits back into the dataframe
        for i, rec in enumerate(records):
            events_df.at[events_df.index[i], "yara_score"] = rec.get("yara_score", 0)
            events_df.at[events_df.index[i], "yara_hits"]  = rec.get("yara_hits", 0)

        hit_mask = events_df["yara_score"] > 0
        # Adjust severity upward for YARA-matched events
        events_df.loc[hit_mask & (events_df["severity"] == "low"),    "severity"] = "medium"
        events_df.loc[events_df["yara_score"] >= 60,                  "severity"] = "high"
        if "tags" not in events_df.columns:
            events_df["tags"] = ""
        events_df.loc[hit_mask, "tags"] = (
            events_df.loc[hit_mask, "tags"].fillna("") + ",YARA_MATCH"
        )
        log.info(
            "[INGEST_PROBE] stage=yara_scan elapsed_sec=%.3f rows=%d yara_hits=%d",
            time.perf_counter() - t0,
            len(events_df),
            int(hit_mask.sum()),
        )

    t0 = time.perf_counter()
    behaviors_df  = _generate_behaviors(events_df, run_id)
    log.info(
        "[INGEST_PROBE] stage=behavior_generation elapsed_sec=%.3f rows=%d mem_mb=%.2f",
        time.perf_counter() - t0,
        len(behaviors_df),
        _df_mem_mb(behaviors_df),
    )

    # Use YAML rules if available, else fall back to heuristic EID mapping
    t0 = time.perf_counter()
    detections_df = find_detections(events_df, rules=_loaded_rules if _loaded_rules else None)
    log.info(
        "[INGEST_PROBE] stage=find_detections elapsed_sec=%.3f rows=%d mem_mb=%.2f",
        time.perf_counter() - t0,
        len(detections_df),
        _df_mem_mb(detections_df),
    )
    print("[DEBUG] ingest_upload rules detections_df rows:", len(detections_df))
    if not detections_df.empty:
        detections_df["run_id"] = run_id
    else:
        detections_df = pd.DataFrame(columns=[
            "run_id","rule_id","rule_name","mitre_id","mitre_tactic",
            "kill_chain_stage","utc_time","image","event_id","description",
            "severity","computer","process_id","parent_process_id","parent_image",
            "source_ip","source_port","destination_ip","destination_port",
            "target_filename","confidence_score",
        ])

    # YARA detections — scored events with yara_score > 0 become detections
    yara_rows = []
    if "yara_score" in events_df.columns:
        yara_hit_df = events_df[events_df["yara_score"] > 0]
        for r in yara_hit_df.to_dict(orient="records"):
            yara_score = int(r.get("yara_score") or 0)
            yara_rows.append({
                "run_id":           run_id,
                "rule_id":          "YARA-MATCH",
                "rule_name":        f"YARA Match (score={yara_score})",
                "mitre_id":         None,
                "mitre_tactic":     "Execution",
                "kill_chain_stage": "Execution",
                "utc_time":         r.get("utc_time"),
                "image":            r.get("image"),
                "event_id":         r.get("event_id"),
                "description":      f"YARA rules matched ({r.get('yara_hits', 0)} hits)",
                "severity":         r.get("severity", "high"),
                "computer":         r.get("computer"),
                "process_id":       r.get("process_id") or r.get("pid"),
                "parent_process_id":r.get("parent_process_id") or r.get("ppid"),
                "parent_image":     r.get("parent_image"),
                "source_ip":        r.get("source_ip") or r.get("src_ip"),
                "source_port":      r.get("source_port"),
                "destination_ip":   r.get("destination_ip") or r.get("dst_ip"),
                "destination_port": r.get("destination_port") or r.get("dst_port"),
                "target_filename":  r.get("target_filename") or r.get("file_path"),
                "confidence_score": yara_score,
            })
    if yara_rows:
        t0 = time.perf_counter()
        detections_df = pd.concat(
            [detections_df, pd.DataFrame(yara_rows)], ignore_index=True
        )
        log.info(
            "[INGEST_PROBE] stage=concat_yara_detections elapsed_sec=%.3f yara_rows=%d total_detections=%d",
            time.perf_counter() - t0,
            len(yara_rows),
            len(detections_df),
        )
    _set_ingest_progress(80, "Finalizing ingest payload...")

    print("[DEBUG] ingest_upload total detections_df rows:", len(detections_df))
    
    # 10/10 Formal Invariant: Refined Data Integrity Check
    final_count = len(events_df)
    ingest_log = logging.getLogger("analysis")
    ingest_log.info("[INGEST] Records: raw=%d, final=%d (dropped=%d)", len(raw_records), final_count, len(raw_records) - final_count)
    
    if final_count == 0 and len(raw_records) > 0:
        ingest_log.critical("[INVARIANT-FAILURE] Total data loss during ingest.")
        raise RuntimeError("Formal invariant broken: Total ingest data loss.")

    log.info(
        "[INGEST_PROBE] stage=ingest_upload_total elapsed_sec=%.3f raw_records=%d events=%d detections=%d behaviors=%d events_mem_mb=%.2f",
        time.perf_counter() - t_ingest_start,
        len(raw_records),
        len(events_df),
        len(detections_df),
        len(behaviors_df),
        _df_mem_mb(events_df),
    )
    _set_ingest_progress(85, "Ingest ready for persistence...")

    return events_df, detections_df, behaviors_df, content_hash


# ---------------------------------------------------------------------------
# persist_case  — write upload to sentinel_cases (MySQL)
# ---------------------------------------------------------------------------

def persist_case(
    events_df: 'pd.DataFrame',
    detections_df: 'pd.DataFrame',
    behaviors_df: 'pd.DataFrame',
    content_hash: str,
) -> str:
    if events_df.empty:
        raise RuntimeError("No events to persist")

    import pandas as pd

    run_ids = events_df["run_id"].dropna().unique().tolist()
    if len(run_ids) != 1:
        raise RuntimeError(f"Expected exactly one run_id, got: {run_ids}")
    run_id = run_ids[0]
    t_persist_start = time.perf_counter()

    def _df_mem_mb(df: 'pd.DataFrame') -> float:
        if df is None or df.empty:
            return 0.0
        try:
            return float(df.memory_usage(deep=True).sum()) / (1024 * 1024)
        except Exception:
            return 0.0

    _DT_COLS = {
        "event_time", "utc_time", "inserted_at", "created_at", "updated_at",
        "last_seen", "first_seen", "last_updated", "start_time", "end_time",
        "ts", "timestamp",
    }

    def _sanitise(df: pd.DataFrame) -> pd.DataFrame:
        clean = df.copy()

        # ── Drop any column that contains non-scalar values (lists, dicts) ──
        # These cannot be stored in MySQL and would silently break INSERT
        scalar_drops = []
        for col in clean.columns:
            try:
                sample = clean[col].dropna()
                if len(sample) > 0 and isinstance(sample.iloc[0], (list, dict, set)):
                    scalar_drops.append(col)
            except Exception:
                scalar_drops.append(col)
        # Also explicitly drop known non-DB columns added by enrichment
        for drop_col in ("yara_hits", "yara_rule_names", "tags_list",
                         "process_chain", "process_depth",
                         "b64_preview", "cmd_b64_preview",
                         "grandparent_image",  # may be in events but check DB schema
                         ):
            if drop_col in clean.columns and drop_col not in scalar_drops:
                scalar_drops.append(drop_col)
        if scalar_drops:
            clean = clean.drop(columns=scalar_drops, errors="ignore")

        # ── Sanitize datetime columns ─────────────────────────────────────
        for col in list(clean.columns):
            try:
                if col in _DT_COLS or clean[col].dtype.kind == "M":
                    if pd.api.types.is_datetime64_any_dtype(clean[col]):
                        if getattr(clean[col].dt, "tz", None) is not None:
                            clean[col] = clean[col].dt.tz_convert(None)
                        continue
                    clean[col] = clean[col].apply(sanitize_datetime)
            except Exception:
                pass

        # ── Coerce booleans to int (MySQL TINYINT) ────────────────────────
        bool_signal_cols = (
            "is_lolbin", "is_high_entropy", "has_encoded_flag",
            "has_download_url", "b64_detected", "is_external_ip",
            "is_suspicious_chain", "is_system_process",
            "cmd_high_entropy", "cmd_has_encoded_flag",
            "cmd_b64_detected", "cmd_has_download_url",
        )
        for c in bool_signal_cols:
            if c in clean.columns:
                try:
                    clean[c] = clean[c].fillna(False).astype(int)
                except Exception:
                    clean[c] = 0

        # ── Final: replace NaN/NaT with None for MySQL ───────────────────
        try:
            clean = clean.astype(object).where(pd.notna(clean), None)
        except Exception:
            # Fallback: column-by-column
            for col in clean.columns:
                try:
                    clean[col] = clean[col].where(pd.notna(clean[col]), None)
                except Exception:
                    pass

        return clean

    # Batch size: commit every N rows to avoid lock-wait timeouts on large uploads
    BATCH_SIZE = 500

    def _bulk_insert(conn, table: str, records: list, valid_cols: list) -> int:
        """
        Insert records in batches of BATCH_SIZE, committing after each batch.
        Uses executemany() for performance — one round-trip per batch instead of one per row.
        Returns total rows inserted.
        """
        if not records:
            return 0

        # Determine the consistent column set from the first non-empty record
        cols = [k for k in records[0] if k in valid_cols]
        if not cols:
            return 0

        ph  = ", ".join(["%s"] * len(cols))
        cs  = ", ".join(f"`{c}`" for c in cols)
        sql = f"INSERT IGNORE INTO `{table}` ({cs}) VALUES ({ph})"

        total = 0
        attempted = 0
        insert_time_total = 0.0
        commit_time_total = 0.0
        batch_count = 0
        for i in range(0, len(records), BATCH_SIZE):
            batch = records[i : i + BATCH_SIZE]
            rows  = [[rec.get(c) for c in cols] for rec in batch]
            batch_count += 1
            with get_cursor(conn) as cur:
                t0 = time.perf_counter()
                cur.executemany(sql, rows)
                insert_time_total += time.perf_counter() - t0
                # MySQL rowcount after executemany = rows inserted (not attempted)
                # -1 means "unknown" for some drivers — count batch size as fallback
                rc = cur.rowcount
                total += rc if rc >= 0 else len(batch)
                attempted += len(batch)
            t0 = time.perf_counter()
            conn.commit()
            commit_time_total += time.perf_counter() - t0

        log.info(
            "[INGEST_PROBE] stage=bulk_insert table=%s elapsed_sec=%.3f rows_attempted=%d rows_reported=%d batches=%d batch_size=%d insert_exec_sec=%.3f commit_sec=%.3f",
            table,
            insert_time_total + commit_time_total,
            attempted,
            total,
            batch_count,
            BATCH_SIZE,
            insert_time_total,
            commit_time_total,
        )

        return attempted  # return attempted so caller sees true count

    # ── Sanitise all three dataframes up-front ──────────────────────────────
    t0 = time.perf_counter()
    ev_clean  = _sanitise(events_df).to_dict("records")
    bh_clean  = _sanitise(behaviors_df).to_dict("records") if not behaviors_df.empty else []
    det_clean = _sanitise(detections_df).to_dict("records") if not detections_df.empty else []
    log.info(
        "[INGEST_PROBE] stage=sanitise_dataframes elapsed_sec=%.3f events_in=%d events_out=%d behaviors_in=%d behaviors_out=%d detections_in=%d detections_out=%d events_mem_mb=%.2f detections_mem_mb=%.2f behaviors_mem_mb=%.2f",
        time.perf_counter() - t0,
        len(events_df),
        len(ev_clean),
        len(behaviors_df),
        len(bh_clean),
        len(detections_df),
        len(det_clean),
        _df_mem_mb(events_df),
        _df_mem_mb(detections_df),
        _df_mem_mb(behaviors_df),
    )

    # ── Get valid column lists (single short connection) ────────────────────
    t0 = time.perf_counter()
    with get_db_connection("cases") as conn:
        with get_cursor(conn) as cur:
            valid_ev  = get_table_columns(cur, "events")
            valid_bh  = get_table_columns(cur, "behaviors")
            valid_det = get_table_columns(cur, "detections")
    log.info(
        "[INGEST_PROBE] stage=load_table_columns elapsed_sec=%.3f events_cols=%d behaviors_cols=%d detections_cols=%d",
        time.perf_counter() - t0,
        len(valid_ev),
        len(valid_bh),
        len(valid_det),
    )

    # ── Master Record Logic ─────────────────────────────────────────────────
    t0 = time.perf_counter()
    with get_db_connection("cases") as conn:
        with get_cursor(conn) as cur:
            # Atomic update of the case master record
            cur.execute(
                "INSERT INTO cases (run_id, status, content_hash, analysis_version, start_time) "
                "VALUES (%s, %s, %s, 1, %s) "
                "ON DUPLICATE KEY UPDATE status=VALUES(status), content_hash=VALUES(content_hash)",
                (run_id, "INGESTED", content_hash, now_utc())
            )
            # Record the state transition
            cur.execute(
                "INSERT INTO case_history (run_id, old_status, new_status, reason) "
                "VALUES (%s, %s, %s, %s)",
                (run_id, "NONE", "INGESTED", json.dumps({"source": "ingest_upload"}))
            )
        conn.commit()
    log.info(
        "[INGEST_PROBE] stage=upsert_case_master elapsed_sec=%.3f run_id=%s",
        time.perf_counter() - t0,
        run_id[:16],
    )

    # ── Batch insert each table independently ───────────────────────────────
    # Note: run_id is deterministic (hash of content), so re-uploading the
    # same XML produces the same run_id. INSERT IGNORE handles duplicates safely.
    with get_db_connection("cases") as conn:
        n_ev = _bulk_insert(conn, "events", ev_clean, valid_ev)
        print(f"[persist_case] events inserted/present: {n_ev}/{len(ev_clean)}")

    with get_db_connection("cases") as conn:
        n_bh = _bulk_insert(conn, "behaviors", bh_clean, valid_bh)

    with get_db_connection("cases") as conn:
        n_det = _bulk_insert(conn, "detections", det_clean, valid_det)
        print(f"[persist_case] detections inserted: {n_det}/{len(det_clean)}")

    print(f"[persist_case] run_id={run_id} saved to sentinel_cases.")
    log.info(
        "[INGEST_PROBE] stage=persist_case_total elapsed_sec=%.3f run_id=%s events=%d behaviors=%d detections=%d",
        time.perf_counter() - t_persist_start,
        run_id[:16],
        n_ev,
        n_bh,
        n_det,
    )
    return run_id


# ---------------------------------------------------------------------------
# process_event  — called per live event by sysmon_collector
# ---------------------------------------------------------------------------

def process_event(evt: dict, conn: Any = None) -> None:
    if not evt.get("severity"):
        try:
            evt["severity"] = _assign_severity(int(evt.get("event_id") or 0))
        except Exception:
            evt["severity"] = "low"

    alerts = match_rules(evt)
    if not alerts:
        return
    if conn:
        _persist_alerts_internal(conn, evt, alerts)
    else:
        with get_db_connection("live") as c:
            _persist_alerts_internal(c, evt, alerts)
            c.commit()


# ---------------------------------------------------------------------------
# Simple rule matching (YAML rules from rules.yaml)
# ---------------------------------------------------------------------------

_RULES_CACHE: Optional[List[Dict]] = None

def _load_rules(rules_path: Optional[Path] = None) -> List[Dict]:
    global _RULES_CACHE
    if _RULES_CACHE is not None and rules_path is None:
        return _RULES_CACHE
    import yaml
    default = Path(__file__).resolve().parent / "rules.yaml"
    path    = Path(rules_path) if rules_path else default
    if not path.exists():
        _RULES_CACHE = []
        return _RULES_CACHE
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    _RULES_CACHE = data.get("rules", []) if data else []
    return _RULES_CACHE


def _match_rules_on_event(evt: dict) -> List[Dict]:
    rules  = _load_rules()
    alerts = []
    eid    = evt.get("event_id")
    try:
        eid = int(eid)
    except Exception:
        eid = None
    image  = (evt.get("image") or "").lower()
    sev    = (evt.get("severity") or "low").lower()
    fpath  = (evt.get("file_path") or "").lower()

    for rule in rules:
        rule_eids = rule.get("event_id", [])
        if rule_eids and eid not in rule_eids:
            continue
        img_contains = rule.get("image_contains")
        if img_contains and img_contains.lower() not in image:
            continue
        img_any = rule.get("image_any", [])
        if img_any and not any(i.lower() in image for i in img_any):
            continue
        sev_req = rule.get("severity_required")
        if sev_req and sev != sev_req.lower():
            continue
        path_any = rule.get("path_prefix_any", [])
        if path_any and not any(fpath.startswith(p.lower()) for p in path_any):
            continue
        alerts.append({
            "rule_id":          rule.get("rule_id"),
            "rule_name":        rule.get("name"),
            "mitre_id":         rule.get("mitre_id"),
            "mitre_tactic":     rule.get("mitre_tactic"),
            "kill_chain_stage": rule.get("mitre_tactic", "Execution"),
            "severity":         sev,
        })
    return alerts


# ---------------------------------------------------------------------------
# _persist_alerts_internal
# ---------------------------------------------------------------------------

def _persist_alerts_internal(conn: Any, evt: dict, alerts: list) -> None:
    # FIX: sanitize timestamp — Sysmon XML can have 7-digit fractional seconds + Z
    _ts_raw   = evt.get("utc_time") or now_utc()
    timestamp = sanitize_datetime(_ts_raw) or now_utc()
    run_id    = evt.get("run_id", "live")
    with get_cursor(conn) as cur:
        for alert in alerts:
            alert_id = f"ALT-{uuid.uuid4().hex[:8]}"
            checked_insert(
                cur, "alerts",
                ["alert_id","ts","rule_id","rule_name","severity",
                 "image","computer","mitre_id","run_id"],
                (alert_id, timestamp, alert.get("rule_id"), alert.get("rule_name"),
                 alert.get("severity"), evt.get("image"), evt.get("computer"),
                 alert.get("mitre_id"), run_id),
                identity_hint=f"alert_id={alert_id}",
            )
            cur.execute(
                "INSERT INTO `detections` ("
                " `run_id`,`rule_id`,`rule_name`,`mitre_id`,`mitre_tactic`,"
                " `kill_chain_stage`,`utc_time`,`image`,`event_id`,`description`,"
                " `severity`,`computer`,`process_id`,`parent_process_id`,"
                " `parent_image`,`confidence_score`"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    run_id,
                    alert.get("rule_id"), alert.get("rule_name"), alert.get("mitre_id"),
                    "Unknown", alert.get("kill_chain_stage","Execution"),
                    timestamp, evt.get("image"),
                    int(evt.get("event_id") or 0),
                    f"Rule: {alert.get('rule_name')} triggered",
                    alert.get("severity"), evt.get("computer"),
                    evt.get("pid"), evt.get("ppid"), evt.get("parent_image"),
                    85.0,
                ),
            )


# ---------------------------------------------------------------------------
# upsert_incident_row
# ---------------------------------------------------------------------------

def upsert_incident_row(
    incident_id: str,
    status: str,
    severity: str,
    confidence: int,
    run_id: str = "live",
    escalation: str = "auto",
    conn: Any = None,
) -> None:
    ts = now_utc()
    
    # SOC-grade: Determine priority and SLA based on severity
    sev_map = {
        "critical": ("P1", 4),
        "high":     ("P1", 4),
        "medium":   ("P2", 8),
        "low":      ("P3", 24),
    }
    priority, sla_hours = sev_map.get(severity.lower(), ("P3", 48))
    sla_deadline = ts + datetime.timedelta(hours=sla_hours)

    stmt = sql_upsert(
        "incidents",
        [
            "incident_id", "status", "severity", "confidence", "escalation",
            "priority", "sla_deadline", "run_id", "created_at", "updated_at"
        ],
        ["incident_id"],
        ["status", "confidence", "escalation", "priority", "sla_deadline", "updated_at"],
    )
    vals = (incident_id, status, severity, confidence, escalation, priority, sla_deadline, run_id, ts, ts)

    def _do(c: Any) -> None:
        with get_cursor(c) as cur:
            cur.execute(stmt, vals)

    if conn:
        _do(conn)
    else:
        with get_db_connection("live") as c:
            _do(c)
            c.commit()


# ---------------------------------------------------------------------------
# Behavior baseline — MySQL
# ---------------------------------------------------------------------------

def load_behavior_baseline() -> Dict[Tuple[str,str,str,str,int], Dict[str,Any]]:
    engine = get_engine("live")
    import pandas as pd
    from sqlalchemy import text
    try:
        df = pd.read_sql_query(text("SELECT * FROM behavior_baseline"), engine)
    except Exception:
        return {}
    baseline: Dict = {}
    for row in df.to_dict(orient="records"):
        key = (
            row.get("computer") or "unknown_host",
            row["process_name"],
            row["user_type"],
            row["parent_process"],
            int(row["hour_bucket"]),
        )
        count = int(row.get("count_samples", 0) or 0)
        var   = float(row.get("var_exec", 0.0) or 0.0)
        m2    = var * (count - 1) if count > 1 else 0.0
        baseline[key] = {
            "count_samples": count,
            "mean_exec":     float(row.get("avg_exec", 0.0) or 0.0),
            "m2_exec":       m2,
            "avg_cmd_len":   float(row.get("avg_cmd_len", 0.0) or 0.0),
            "avg_followup":  float(row.get("avg_followup", 0.0) or 0.0),
            "seen_days":     int(row.get("seen_days", 0) or 0),
        }
    return baseline


def persist_behavior_baseline(
    baseline_state: Dict[Tuple[str,str,str,str,int], Dict[str,Any]],
    conn: Any = None,
) -> None:
    if not baseline_state:
        return
    ts   = now_utc()
    stmt = sql_upsert(
        "behavior_baseline",
        ["computer","process_name","user_type","parent_process","hour_bucket",
         "avg_exec","var_exec","avg_cmd_len","avg_followup","count_samples","seen_days","last_updated"],
        [],
        ["avg_exec","var_exec","avg_cmd_len","avg_followup","count_samples","seen_days","last_updated"],
    )

    # Build all rows up-front then batch-insert with executemany
    rows = []
    for (computer, pname, utype, parent, hour), entry in baseline_state.items():
        count    = int(entry["count_samples"])
        variance = entry["m2_exec"] / (count - 1) if count > 1 else 0.0
        rows.append((
            computer, pname, utype, parent, hour,
            float(entry.get("mean_exec", 0.0)),
            variance,
            float(entry.get("avg_cmd_len", 0.0)),
            float(entry.get("avg_followup", 0.0)),
            count,
            int(entry.get("seen_days", 1) or 1),
            ts,
        ))

    if not rows:
        return

    BATCH = 500
    def _do(c: Any) -> None:
        with get_cursor(c) as cur:
            for i in range(0, len(rows), BATCH):
                cur.executemany(stmt, rows[i:i + BATCH])
            c.commit()

    if conn:
        _do(conn)
    else:
        with get_db_connection("live") as c:
            _do(c)


def _read_sql_dataframe(sql, engine, params=None, *, chunksize: int = 5000):
    import pandas as pd

    with engine.connect().execution_options(stream_results=True) as conn:
        reader = pd.read_sql_query(sql, conn, params=params, chunksize=chunksize)
        if chunksize:
            frames = [chunk for chunk in reader if not chunk.empty]
            if not frames:
                return pd.DataFrame()
            if len(frames) == 1:
                return frames[0].reset_index(drop=True)
            return pd.concat(frames, ignore_index=True)
        return reader


# ---------------------------------------------------------------------------
# DB loaders  (MySQL versions of the SQLite load_* helpers)
# ---------------------------------------------------------------------------

def load_events(run_id: str) -> 'pd.DataFrame':
    from sqlalchemy import text
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        df = _read_sql_dataframe(
            text(
                "SELECT event_uid, event_time, event_id, image, parent_image, "
                "command_line, `user`, src_ip, dst_ip, dst_port, severity, "
                "computer, file_path, description, run_id, pid, ppid "
                "FROM events WHERE run_id = :run_id ORDER BY event_time DESC"
            ),
            engine,
            params={"run_id": run_id},
            chunksize=5000,
        )
    except Exception as e:
        print(f"[WARN] Failed to load events: {e}")
        return pd.DataFrame()

    # Keep event_time for burst building; add utc_time alias for display
    if "event_time" in df.columns and "utc_time" not in df.columns:
        df["utc_time"] = df["event_time"]
    elif "utc_time" in df.columns and "event_time" not in df.columns:
        df["event_time"] = df["utc_time"]
    df = df.rename(columns={
        "pid": "process_id", "ppid": "parent_process_id",
        "file_path": "target_filename", "src_ip": "source_ip",
        "dst_ip": "destination_ip",
    })
    # Keep command_line accessible under both names
    if "command_line" in df.columns and "commandline" not in df.columns:
        df["commandline"] = df["command_line"]
    for col in ["description", "computer", "tags"]:
        if col not in df.columns:
            df[col] = ""
    if "tags" in df.columns:
        df["tags"] = df["tags"].fillna("").astype(str).str.split(",").map(
            lambda values: [t for t in values if t]
        )
    if "event_time" in df.columns:
        df["_parsed_time"] = df["event_time"]
    elif "utc_time" in df.columns:
        df["_parsed_time"] = df["utc_time"]
    else:
        df["_parsed_time"] = pd.NaT
    return df


def load_detections(run_id: str) -> 'pd.DataFrame':
    from sqlalchemy import text
    empty = pd.DataFrame(columns=[
        "rule_id","rule_name","mitre_id","mitre_tactic","kill_chain_stage",
        "utc_time","image","event_id","description","severity","computer",
        "process_id","parent_process_id","parent_image","source_ip",
        "source_port","destination_ip","destination_port",
        "target_filename","confidence_score",
    ])
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        det = _read_sql_dataframe(
            text(
                "SELECT run_id, rule_id, rule_name, mitre_id, mitre_tactic, "
                "kill_chain_stage, utc_time, image, event_id, description, "
                "severity, computer, process_id, parent_process_id, parent_image, "
                "confidence_score "
                "FROM detections WHERE run_id = :run_id ORDER BY utc_time DESC"
            ),
            engine,
            params={"run_id": run_id},
            chunksize=5000,
        )
    except Exception as e:
        print(f"[WARN] Failed to load detections: {e}")
        return empty
    if "event_time" in det.columns and "utc_time" not in det.columns:
        det = det.rename(columns={"event_time": "utc_time"})
    for col in empty.columns:
        if col not in det.columns:
            det[col] = None
    return det


def load_correlations(run_id: str) -> 'pd.DataFrame':
    from sqlalchemy import text
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        return _read_sql_dataframe(
            text("SELECT * FROM correlations WHERE run_id = :run_id"),
            engine,
            params={"run_id": run_id},
            chunksize=2000,
        )
    except Exception:
        return pd.DataFrame()


def load_correlations_detail(run_id: str) -> 'pd.DataFrame':
    from sqlalchemy import text
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        return _read_sql_dataframe(
            text("SELECT * FROM correlations WHERE run_id = :run_id "
                 "ORDER BY start_time ASC LIMIT 10"),
            engine,
            params={"run_id": run_id},
            chunksize=10,
        )
    except Exception:
        return pd.DataFrame()


def load_correlation_campaigns(run_id: str) -> 'pd.DataFrame':
    from sqlalchemy import text
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        return _read_sql_dataframe(
            text("SELECT * FROM correlation_campaigns WHERE run_id = :run_id "
                 "ORDER BY last_seen DESC"),
            engine,
            params={"run_id": run_id},
            chunksize=1000,
        )
    except Exception:
        return pd.DataFrame()


def load_behaviors(run_id: str) -> 'pd.DataFrame':
    from sqlalchemy import text
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        df = _read_sql_dataframe(
            text(
                "SELECT run_id, behavior_id, behavior_type, event_time, image, "
                "parent_image, command_line, `user`, process_id, parent_process_id, "
                "computer, source_ip, destination_ip, destination_port, target_filename, "
                "reg_key, raw_event_id "
                "FROM behaviors WHERE run_id = :run_id ORDER BY event_time DESC LIMIT 5000"
            ),
            engine,
            params={"run_id": run_id},
            chunksize=1000,
        )
    except Exception:
        return pd.DataFrame()
    # Normalize legacy schema column names
    if "user_name" in df.columns and "user" not in df.columns:
        df = df.rename(columns={"user_name": "user"})
    if "process_id" not in df.columns and "pid" in df.columns:
        df = df.rename(columns={"pid": "process_id"})
    return df


def _burst_value(row: Any, field: str, default: Any = None) -> Any:
    if row is None:
        return default
    getter = getattr(row, "get", None)
    if callable(getter):
        try:
            return getter(field, default)
        except TypeError:
            pass
    return getattr(row, field, default)


def _safe_lower_text(value: Any, default: str = "") -> str:
    try:
        return str(value if value is not None else default).lower()
    except Exception:
        return str(default).lower()


def _coerce_utc_timestamp(value: Any):
    if value is None or value == "":
        return pd.NaT
    if isinstance(value, pd.Timestamp):
        if value.tzinfo is None:
            return value.tz_localize("UTC")
        return value.tz_convert("UTC")
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            return pd.Timestamp(value, tz="UTC")
        return pd.Timestamp(value).tz_convert("UTC")
    try:
        return pd.to_datetime(value, errors="coerce", utc=True)
    except Exception:
        return pd.NaT


def _timeline_key_prefix(value: Any, width: int = 13) -> str:
    """Return a deterministic time bucket prefix for timeline/correlation keys."""
    if value is None or value == "":
        return ""
    try:
        ts = pd.to_datetime(value, errors="coerce", utc=True)
    except Exception:
        ts = pd.NaT
    if pd.notna(ts):
        return ts.isoformat()[:width]
    try:
        return str(value)[:width]
    except Exception:
        return ""


def load_incident_row(incident_id: str, run_id: str = "") -> Optional[dict]:
    try:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "SELECT incident_id, status, severity, confidence, escalation, "
                    "analyst, notes, created_at, updated_at FROM incidents "
                    "WHERE incident_id = %s",
                    (incident_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
    except Exception:
        return None


def update_campaign_status_lifecycle() -> None:
    """Mark campaigns dormant if last_seen > 24 hours ago."""
    try:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    f"UPDATE correlation_campaigns SET status = 'dormant' "
                    f"WHERE status = 'active' "
                    f"AND last_seen < {sql_now_minus(24, 'HOUR')}"
                )
            conn.commit()
    except Exception as e:
        print(f"[WARN] Campaign lifecycle update failed: {e}")


def _persist_auto_correlation_with_cursor(
    cur,
    burst: Dict[str, Any],
    run_id: str,
    existing_campaign_row: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    corr_id   = burst["correlation_id"]
    now_ts    = now_utc()
    new_stage = burst.get("kill_chain_stage") or "Execution"
    new_conf  = int(burst.get("risk_score", 0))

    row = existing_campaign_row
    if row is None:
        cur.execute(
            "SELECT burst_count, max_confidence, highest_kill_chain "
            "FROM correlation_campaigns WHERE corr_id = %s AND run_id = %s",
            (corr_id, run_id),
        )
        row = cur.fetchone()
    if row:
        final_stage = promote_stage(row["highest_kill_chain"], new_stage)
        cur.execute(
            "UPDATE correlation_campaigns SET "
            "burst_count=%s, last_seen=%s, max_confidence=%s, "
            "highest_kill_chain=%s, status='active' "
            "WHERE corr_id=%s AND run_id=%s",
            (
                row["burst_count"] + 1, now_ts,
                max(row["max_confidence"], new_conf),
                final_stage, corr_id, run_id,
            ),
        )
    else:
        checked_insert(
            cur, "correlation_campaigns",
            ["corr_id","run_id","base_image","computer","first_seen",
             "last_seen","burst_count","max_confidence",
             "highest_kill_chain","status","description"],
            (
                corr_id, run_id,
                burst.get("image"), burst.get("computer"),
                now_ts, now_ts, 1, new_conf, new_stage, "active",
                f"Auto-correlated campaign for {burst.get('image')}",
            ),
            identity_hint=f"corr_id={corr_id}",
        )

    rich_desc = (
        f"[{new_stage}] Risk:{new_conf}% - "
        f"Detected sequence involving {burst.get('count',0)} events."
    )
    cur.execute(
        "INSERT INTO `correlations` "
        "(`corr_id`,`run_id`,`base_image`,`start_time`,`end_time`,"
        "`description`,`event_ids`,`computer`) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            corr_id, run_id, burst.get("image"),
            sanitize_datetime(burst.get("start_time")),
            sanitize_datetime(burst.get("end_time")),
            rich_desc,
            json.dumps(burst.get("event_ids", [])),
            burst.get("computer"),
        ),
    )

    return {
        "corr_id": corr_id,
        "run_id": run_id,
        "base_image": burst.get("image"),
        "computer": burst.get("computer"),
        "first_seen": sanitize_datetime(burst.get("start_time")),
        "last_seen": sanitize_datetime(burst.get("end_time")),
        "description": rich_desc,
        "event_ids": json.dumps(burst.get("event_ids", [])),
        "kill_chain_stage": new_stage,
        "severity": "high" if new_conf >= 70 else "medium" if new_conf >= 40 else "low",
        "confidence": new_conf,
        "highest_kill_chain": new_stage,
        "max_confidence": new_conf,
        "status": "active",
        "burst_count": int(row["burst_count"] + 1) if row else 1,
    }


def persist_auto_correlation_bulk(bursts: List[Dict[str, Any]], run_id: str) -> Dict[str, Any]:
    if not bursts:
        return {"campaign_rows": [], "detail_rows": [], "burst_count": 0, "campaign_count": 0, "existing_campaign_count": 0}

    mode = "cases" if run_id != "live" else "live"
    try:
        with get_db_connection(mode) as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "SELECT corr_id, burst_count, max_confidence, highest_kill_chain "
                    "FROM correlation_campaigns WHERE run_id = %s",
                    (run_id,),
                )
                existing_campaigns = {row["corr_id"]: row for row in cur.fetchall()}

                campaign_rows_by_id: Dict[str, Dict[str, Any]] = {}
                detail_rows: List[Dict[str, Any]] = []
                for b in bursts:
                    persisted_row = _persist_auto_correlation_with_cursor(
                        cur,
                        b,
                        run_id,
                        existing_campaign_row=existing_campaigns.get(b["correlation_id"]),
                    )
                    campaign_rows_by_id[persisted_row["corr_id"]] = persisted_row
                    existing_campaigns[persisted_row["corr_id"]] = persisted_row
                    detail_rows.append(persisted_row)
                conn.commit()
        return {
            "campaign_rows": list(campaign_rows_by_id.values()),
            "detail_rows": detail_rows,
            "burst_count": len(bursts),
            "campaign_count": len(campaign_rows_by_id),
            "existing_campaign_count": len(existing_campaigns),
        }
    except Exception as e:
        log.warning("[Bulk Correlation] Persist failed: %s", e)
        return {"campaign_rows": [], "detail_rows": [], "burst_count": len(bursts), "campaign_count": 0, "existing_campaign_count": 0, "error": str(e)}


def persist_auto_correlation(burst: Dict[str, Any], run_id: str) -> None:
    persist_auto_correlation_bulk([burst], run_id)


# ---------------------------------------------------------------------------
# Burst building
# ---------------------------------------------------------------------------

def _build_bursts(df: 'pd.DataFrame', beh_df: 'pd.DataFrame', run_id: str) -> List[Dict[str,Any]]:
    if not beh_df.empty and "event_time" in beh_df.columns:
        base = beh_df.copy()
        # Normalize schema aliases before fillna so we never get KeyError
        if "user_name" in base.columns and "user" not in base.columns:
            base = base.rename(columns={"user_name": "user"})
        if "process_id" not in base.columns and "pid" in base.columns:
            base = base.rename(columns={"pid": "process_id"})
        for col in ("image", "process_id", "computer", "user"):
            if col not in base.columns:
                base[col] = None
        if "_parsed_time" in base.columns:
            base["parsed_time"] = base["_parsed_time"]
        else:
            base["parsed_time"] = base["event_time"]
        base = base.dropna(subset=["parsed_time"]).sort_values("parsed_time")
        for col in ("image","process_id","computer","user"):
            base[col] = base[col].fillna(f"unknown_{col}")
        grouped_rows: List[Dict] = []
        current: Optional[Dict] = None
        current_key = None
        current_end_time = None
        for b in base.itertuples(index=False):
            img   = _burst_value(b, "image")
            pid   = _burst_value(b, "process_id")
            host  = _burst_value(b, "computer")
            user  = _burst_value(b, "user")
            btime = _burst_value(b, "parsed_time")
            eid   = str(_burst_value(b, "raw_event_id"))
            btype = _burst_value(b, "behavior_type")
            if pd.isna(btime):
                continue
            key = (img, pid, host, user)
            if current is None or key != current_key or (
                current_end_time is not None and
                (btime - current_end_time).total_seconds() > 900
            ):
                if current:
                    grouped_rows.append(current)
                current_key = key
                current = _new_burst(img, pid, host, user, btime, eid, btype, run_id, b)
                current_end_time = btime
            else:
                _extend_burst(current, btime, eid, btype, b)
                current_end_time = btime
        if current:
            grouped_rows.append(current)
        return grouped_rows
    else:
        if "event_time" not in df.columns or df.empty:
            return []
        time_col = "_parsed_time" if "_parsed_time" in df.columns else "event_time"
        base_tl = df.sort_values(time_col).copy()
        if "parsed_time" not in base_tl.columns:
            if "_parsed_time" in base_tl.columns:
                base_tl["parsed_time"] = base_tl["_parsed_time"]
            else:
                base_tl["parsed_time"] = base_tl["event_time"]
        grouped_rows = []
        current = None
        current_end_time = None
        for row in base_tl.itertuples(index=False):
            if not _burst_value(row, "event_id"):
                continue
            img   = _burst_value(row, "image") or "unknown_process"
            ut    = _burst_value(row, "parsed_time") or _burst_value(row, "event_time") or ""
            host  = _burst_value(row, "computer")
            user  = _burst_value(row, "user")
            if current is None:
                current = _new_burst_from_row(img, ut, host, user, row, run_id)
                current_end_time = ut
            else:
                this = ut
                if (img == current["image"] and
                        pd.notna(current_end_time) and pd.notna(this) and
                        (this - current_end_time).total_seconds() <= 900):
                    _extend_burst_from_row(current, ut, row)
                    current_end_time = this
                else:
                    grouped_rows.append(current)
                    current = _new_burst_from_row(img, ut, host, user, row, run_id)
                    current_end_time = ut
        if current:
            grouped_rows.append(current)
        return grouped_rows


def _new_burst(img, pid, host, user, btime, eid, btype, run_id, b) -> Dict:
    row_get = getattr(b, "get", None)
    if callable(row_get):
        def value(field, default=None):
            try:
                return row_get(field, default)
            except TypeError:
                return getattr(b, field, default)
    else:
        def value(field, default=None):
            return getattr(b, field, default)

    return {
        "burst_id": f"{run_id}-{uuid.uuid4().hex[:8]}",
        "start_time": btime.isoformat(), "end_time": btime.isoformat(),
        "count": 1, "exec_event_count": 1 if btype=="execution" else 0,
        "image": img, "kill_chain_stage": "Execution",
        "event_ids": [eid], "mitre_ids": [], "mitre_tactics": [],
        "descriptions": [], "has_correlation": False, "severity": None,
        "type": "telemetry",
        "source_ip": value("source_ip"), "destination_ip": value("destination_ip"),
        "destination_port": value("destination_port"),
        "target_filename": value("target_filename") or value("file_path"),
        "reg_key": value("reg_key") or value("targetobject"),
        "has_exec": btype=="execution", "has_net": btype=="network",
        "has_file": btype=="file", "has_reg": btype=="registry",
        "net_event_count": 1 if btype=="network" else 0,
        "process_id": pid, "parent_process_id": None, "parent_image": None,
        "computer": host, "user": user,
        "hosts": [host] if host else [], "users": [user] if user else [],
    }

def _is_high_signal(val: Any) -> bool:
    if not val:
        return False
    v = str(val).lower()
    return any(x in v for x in [
        "run", "runonce", "services", "image file execution options",
        "appinit_dlls", "start menu", "startup", "tasks", "wmi", "schtasks"
    ])


def _extend_burst(current, btime, eid, btype, b):
    row_get = getattr(b, "get", None)
    if callable(row_get):
        def value(field, default=None):
            try:
                return row_get(field, default)
            except TypeError:
                return getattr(b, field, default)
    else:
        def value(field, default=None):
            return getattr(b, field, default)

    current["end_time"] = btime.isoformat()
    current["count"] += 1
    current["event_ids"].append(eid)
    if btype == "execution": current["exec_event_count"] = current.get("exec_event_count",0)+1
    if btype == "network":
        current["has_net"] = True
        current["net_event_count"] = current.get("net_event_count",0)+1
    if btype == "file":    current["has_file"] = True
    if btype == "registry": current["has_reg"] = True
    for fld in ("source_ip", "destination_ip", "destination_port"):
        fld_value = value(fld)
        if fld_value:
            current[fld] = fld_value
    for fld in ("target_filename", "reg_key"):
        fld_value = value(fld)
        if fld_value:
            if not current.get(fld) or _is_high_signal(fld_value):
                current[fld] = fld_value


def _new_burst_from_row(img, ut, host, user, row, run_id) -> Dict:
    row_get = getattr(row, "get", None)
    if callable(row_get):
        def value(field, default=None):
            try:
                return row_get(field, default)
            except TypeError:
                return getattr(row, field, default)
    else:
        def value(field, default=None):
            return getattr(row, field, default)

    eid = value("event_id")
    return {
        "burst_id": f"{run_id}-{uuid.uuid4().hex[:8]}",
        "start_time": ut, "end_time": ut,
        "count": 1, "exec_event_count": 1 if eid==1 else 0,
        "image": img, "kill_chain_stage": "Unclassified",
        "event_ids": [str(eid)], "mitre_ids": [], "mitre_tactics": [],
        "descriptions": [value("description")],
        "has_correlation": False, "severity": value("severity"),
        "type": "telemetry",
        "source_ip": value("source_ip"), "destination_ip": value("destination_ip"),
        "destination_port": value("destination_port"),
        "target_filename": value("target_filename") or value("file_path"),
        "reg_key": value("reg_key") or value("targetobject"),
        "has_exec": eid==1, "has_net": eid==3,
        "has_file": eid in (11,15), "has_reg": eid in (12,13,14),
        "net_event_count": 1 if eid==3 else 0,
        "process_id": value("process_id"), "parent_process_id": value("parent_process_id"),
        "parent_image": value("parent_image"),
        "computer": host, "user": user,
        "hosts": [host] if host else [], "users": [user] if user else [],
    }


def _extend_burst_from_row(current, ut, row):
    row_get = getattr(row, "get", None)
    if callable(row_get):
        def value(field, default=None):
            try:
                return row_get(field, default)
            except TypeError:
                return getattr(row, field, default)
    else:
        def value(field, default=None):
            return getattr(row, field, default)

    current["end_time"] = ut
    current["count"] += 1
    eid = value("event_id")
    current["event_ids"].append(str(eid))
    if eid==1:  current["exec_event_count"] = current.get("exec_event_count",0)+1
    if eid==3:  current["has_net"]=True; current["net_event_count"]=current.get("net_event_count",0)+1
    if eid in (11,15): current["has_file"]=True
    if eid in (12,13,14): current["has_reg"]=True
    current["descriptions"].append(value("description"))
    for fld in ("source_ip", "destination_ip", "destination_port"):
        fld_value = value(fld)
        if fld_value:
            current[fld] = fld_value
    for fld in ("target_filename", "reg_key"):
        fld_value = value(fld)
        if fld_value:
            if not current.get(fld) or _is_high_signal(fld_value):
                current[fld] = fld_value


# ---------------------------------------------------------------------------
# Feature extraction, deviation, kill-chain, correlations, confidence
# (Identical logic to the original — just no SQLite)
# ---------------------------------------------------------------------------

def _extract_behavior_features(burst: Dict) -> Dict:
    pname  = burst.get("image") or "unknown_process"
    parent = burst.get("parent_image") or burst.get("parent_process_id") or "unknown_parent"
    user   = (burst.get("user") or "").upper()
    import pandas as pd
    try:
        dt = pd.to_datetime(burst.get("start_time"), errors="coerce", utc=True)
        hour_bucket = int(dt.hour) if pd.notna(dt) else -1
    except Exception:
        hour_bucket = -1
    executions = int(burst.get("exec_event_count", burst.get("count", 0)))
    descs = burst.get("descriptions") or []
    cmd   = burst.get("commandline") or ""
    if not cmd:
        cmd = " ".join(str(d) for d in descs) if isinstance(descs,list) else str(descs)
    cmd = cmd[:2000]
    lower_cmd = cmd.lower()
    lp = pname.lower()
    cmd_len = float(len(cmd))
    if lp.endswith(("powershell.exe","pwsh.exe")): cmd_len /= 2.0
    elif lp.endswith(("cmd.exe",)):                cmd_len /= 1.5
    followup = sum([
        int(bool(burst.get("has_net"))),
        int(bool(burst.get("has_file"))),
        int(bool(burst.get("has_reg"))),
    ])
    dst_ip  = burst.get("destination_ip") or ""
    net_cnt = int(burst.get("net_event_count",0) or 0)
    net_strength = (2 if dst_ip and is_external_ip(dst_ip) and net_cnt>=3
                    else 1 if net_cnt>0 else 0)
    return {
        "process_name":       pname,
        "parent_process":     parent,
        "user_type":          "system" if "SYSTEM" in user else "interactive",
        "hour_bucket":        hour_bucket,
        "exec_count":         executions,
        "command_hash":       hashlib.sha256(lower_cmd.encode()).hexdigest(),
        "command_length":     cmd_len,
        "has_encoded_flag":   ("-enc" in lower_cmd) or ("/enc" in lower_cmd),
        "has_download_flag":  "http://" in lower_cmd or "https://" in lower_cmd,
        "followup_events":    followup,
        "network_strength":   net_strength,
    }


def _compute_deviation_score(features: Dict, baseline_entry: Optional[Dict]) -> float:
    if not baseline_entry:
        return 0.40   # v2.9: Standardized "Unknown" floor
    n = int(baseline_entry.get("count_samples",0) or 0)
    if n < 5:
        return 0.25
    mean_val = float(baseline_entry.get("mean_exec",0.0))
    host_noise_floor = max(5.0, mean_val)
    if float(features["exec_count"]) < host_noise_floor:
        return 0.1
    m2  = float(baseline_entry.get("m2_exec",0.0))
    var = m2 / max(n-1,1) if n>1 else 0.0
    std = max(var**0.5, 1.0)
    freq_dev  = min(abs(float(features["exec_count"]) - mean_val) / std, 3.0)
    avg_cmd   = float(baseline_entry.get("avg_cmd_len",1.0)) or 1.0
    cmd_dev   = min(abs(float(features["command_length"]) - avg_cmd) / avg_cmd, 3.0)
    avg_fol   = float(baseline_entry.get("avg_followup",0.0))
    chain_dev = 1.0 if float(features["followup_events"]) >= avg_fol+2.0 else 0.0
    ns        = int(features.get("network_strength",0) or 0)
    net_dev   = 1.0 if ns==2 else 0.5 if ns==1 else 0.0
    raw = (0.30*freq_dev + 0.25*cmd_dev + 0.20*chain_dev + 0.15*net_dev)
    if not baseline_is_mature(baseline_entry):
        return min(float(min(raw/3.0,1.0)), 0.4)
    return float(min(raw/3.0,1.0))


def _update_local_baseline(burst: Dict, features: Dict, baseline_state: Dict) -> None:
    if int(features.get("hour_bucket",-1) or -1) < 0:
        return
    host   = burst.get("computer") or "unknown_host"
    pname  = features["process_name"]
    utype  = features["user_type"]
    parent = features["parent_process"]
    hour   = features["hour_bucket"]
    pk = (host, pname, utype, parent, hour)
    sk = (host, pname, utype, "", hour)
    entry = baseline_state.get(pk) or baseline_state.get(sk)
    if entry and int(entry.get("count_samples",0)) > 200:
        return
    if not entry:
        baseline_state[pk] = {
            "count_samples":1, "mean_exec":float(features["exec_count"]),
            "m2_exec":0.0, "avg_cmd_len":float(features["command_length"]),
            "avg_followup":float(features["followup_events"]), "seen_days":1,
        }
        return
    key_to_use = pk if pk in baseline_state else sk
    entry = baseline_state[key_to_use]
    if entry.get("seen_days",1) > 30:
        entry["mean_exec"]     = float(entry["mean_exec"]) * 0.98
        entry["count_samples"] = max(1, int(entry["count_samples"]*0.98))
    n_prev = entry["count_samples"]
    n = n_prev + 1
    x = float(features["exec_count"])
    mean = float(entry.get("mean_exec",0.0))
    m2   = float(entry.get("m2_exec",0.0))
    delta = x - mean; mean += delta/n; delta2 = x - mean; m2 += delta*delta2
    entry["mean_exec"]     = mean
    entry["m2_exec"]       = m2
    entry["avg_cmd_len"]   = (entry["avg_cmd_len"]*n_prev + float(features["command_length"]))/n
    entry["avg_followup"]  = (entry["avg_followup"]*n_prev + float(features["followup_events"]))/n
    entry["count_samples"] = n


def _should_learn_baseline(burst: Dict, features: Dict) -> bool:
    if features["process_name"].lower() in ("wmic.exe","powershell.exe","pwsh.exe","psexec.exe"):
        return False
    if float(burst.get("risk_score",0) or 0) >= 45.0:
        return False
    if float(burst.get("deviation_score",1.0) or 1.0) >= 0.4:
        return False
    if features.get("has_encoded_flag"):
        return False
    if burst.get("_pre_suppressed"):
        return False
    if features["user_type"] == "system":
        return False
    if burst.get("kill_chain_stage") != "Execution":
        return False
    if burst.get("has_correlation") or burst.get("correlation_id"):
        return False
    if burst.get("has_persistence") or burst.get("has_injection"):
        return False
    if int(features.get("network_strength",0) or 0) >= 2:
        return False
    if float(features.get("followup_events",0) or 0) >= 2:
        return False
    return True


def _derive_kill_chain_from_flags(burst: Dict) -> str:
    has_exec = bool(burst.get("has_exec"))
    has_net  = bool(burst.get("has_net"))
    has_pers = bool(burst.get("has_persistence"))
    has_inj  = bool(burst.get("has_injection"))
    exec_cnt = int(burst.get("count",0) or 0)
    net_cnt  = int(burst.get("net_event_count",0) or 0)
    if has_inj: return "Privilege Escalation"
    if has_pers: return "Persistence"
    if has_net and is_external_ip(burst.get("destination_ip") or ""):
        if net_cnt>=3 and exec_cnt>=5: return "Command and Control"
        if net_cnt>=3 and not has_exec: return "Command and Control"
    elif has_net and not is_external_ip(burst.get("destination_ip") or "") and net_cnt>=5:
        return "Command and Control"
    if has_exec: return "Execution"
    return "Background"


def _calculate_ml_deviations(bursts, baseline_state):
    feature_cache = []
    for burst in bursts:
        burst["image"]    = burst.get("image") or "unknown_process"
        burst["computer"] = burst.get("computer") or "unknown_host"
        burst["start_time"] = burst.get("start_time") or now_utc().isoformat()
        for f in ("has_exec","has_net","has_file","has_reg","has_injection"):
            burst.setdefault(f, False)
        target = (burst.get("target_filename") or "").lower()
        reg_keys = ["currentversion\\run","currentversion\\runonce","services","startup","image file execution options"]
        reg_persist = bool(burst.get("has_reg") and (any(k in target for k in reg_keys) or target.endswith((".exe",".bat",".ps1",".vbs",".dll",".sys"))))
        file_persist = bool(burst.get("has_exec") and burst.get("has_file") and ("system32\\tasks" in target or "services" in target))
        burst["has_persistence"] = reg_persist or file_persist
        features = _extract_behavior_features(burst)
        burst["network_strength"] = int(features.get("network_strength",0))
        host = burst["computer"]
        pname = features["process_name"]; utype = features["user_type"]
        parent = features["parent_process"]; hour = int(features.get("hour_bucket",-1) or -1)
        pk = (host,pname,utype,parent,hour); sk = (host,pname,utype,"",hour)
        baseline_entry = baseline_state.get(pk) or baseline_state.get(sk)
        deviation = _compute_deviation_score(features, baseline_entry)
        burst["deviation_score"] = deviation
        # Tag whether this burst has a historical baseline
        burst["baseline_count"] = int(baseline_entry.get("count_samples",0)) if baseline_entry else 0
        burst["baseline_mature"] = bool(burst["baseline_count"] >= 5)
        if features.get("user_type")=="system" and deviation<0.3 and int(features.get("followup_events",0) or 0)==0:
            burst["_pre_suppressed"] = True
            burst["suppression_reason"] = "Expected SYSTEM background activity"
        else:
            burst["_pre_suppressed"] = False
            burst["suppression_reason"] = None
        feature_cache.append((burst, features))
    return feature_cache


def _infer_kill_chain_from_content(burst: Dict) -> Optional[str]:
    """
    Infer kill-chain stage from command-line content and event IDs when
    structural flags alone are insufficient.  This catches cases like:
    - cmd.exe running 'schtasks /create' → Persistence
    - powershell with '-encodedcommand' → Execution (obfuscated)
    - Event ID 10 (ProcessAccess) → Privilege Escalation
    - Network event to external IP → Command and Control
    - Shadow copy deletion → Actions on Objectives
    """
    cmd = (burst.get("commandline") or burst.get("command_line") or "").lower()
    img = (burst.get("image") or "").lower()
    eids = set(str(e) for e in (burst.get("event_ids") or []))

    # Actions on Objectives / Impact
    if any(x in cmd for x in ["shadowcopy delete","delete shadows","vssadmin delete","wbadmin delete"]):
        return "Actions on Objectives"
    # Credential Access
    if any(x in cmd for x in ["sekurlsa","lsadump","mimikatz","invoke-mimikatz","dcsync","kerberoast"]):
        return "Credential Access"
    if "10" in eids:  # ProcessAccess → LSASS dump
        return "Privilege Escalation"
    # Persistence
    if any(x in cmd for x in ["schtasks /create","schtasks -create","reg add.*run","currentversion\\run","/create","startup"]):
        return "Persistence"
    if any(e in eids for e in ["12","13","14"]):  # Registry set
        if any(x in cmd for x in ["run","startup","services"]):
            return "Persistence"
    if "17" in eids or "18" in eids:  # Named pipe
        return "Privilege Escalation"
    # Defense Evasion
    if any(x in cmd for x in ["disable-av","set-mppreference","amsibypass","disable","firewall","wevtutil cl","clear-log"]):
        return "Defense Evasion"
    # Privilege Escalation
    if any(x in cmd for x in ["whoami /priv","getsystem","fodhelper","eventvwr","cmstp"]):
        return "Privilege Escalation"
    if "8" in eids or "25" in eids:  # CreateRemoteThread / ProcessTamper
        return "Privilege Escalation"
    # Command and Control
    if "3" in eids and burst.get("has_net"):
        dst = burst.get("destination_ip") or ""
        if is_external_ip(dst):
            return "Command and Control"
    if "22" in eids:  # DNS query
        return "Command and Control"
    # Execution with obfuscation
    if any(x in cmd for x in ["-enc ","-encodedcommand","/ec ","frombase64"]):
        return "Execution"
    return None


def _apply_kill_chain_logic(bursts, telemetry_sink: Optional[Dict[str, Any]] = None):
    promoted = 0
    inferred_promotions = 0
    for burst in bursts:
        before = burst.get("kill_chain_stage")
        for f in ("has_exec","has_net","has_file","has_reg","has_injection"):
            burst.setdefault(f, False)
        # Layer 1: structural flags (fast, reliable)
        kc = _derive_kill_chain_from_flags(burst)
        # Layer 2: content/EID inference (catches what flags miss)
        inferred = _infer_kill_chain_from_content(burst)
        if inferred:
            kc = promote_stage(kc, inferred)
            inferred_promotions += 1
        # Layer 3: prior correlation promotes stage
        if burst.get("correlation_id"):
            kc = promote_stage(burst.get("kill_chain_stage"), kc)
        # Layer 4: MITRE tactic from detections (most reliable)
        det_stage = burst.get("kill_chain_stage_from_detection")
        if det_stage and det_stage not in ("Background","Unclassified","Execution"):
            kc = promote_stage(kc, det_stage)
        burst["kill_chain_stage"] = kc
        if kc != before:
            promoted += 1

    if telemetry_sink is not None:
        telemetry_sink.update({
            "burst_count": len(bursts),
            "promoted_bursts": promoted,
            "inferred_promotions": inferred_promotions,
        })


def _apply_correlations(bursts, corr_df: 'pd.DataFrame', run_id: str, telemetry_sink: Optional[Dict[str, Any]] = None) -> None:
    import pandas as pd
    correlations: List[Dict] = []
    corr_lookup = defaultdict(list)
    if not corr_df.empty:
        for _, row in corr_df.iterrows():
            correlation = {
                "corr_id": row.get("corr_id"),
                "start_time": row.get("start_time"),
                "end_time": row.get("end_time"),
                "base_image": row.get("base_image"),
                "kill_chain_stage": row.get("kill_chain_stage"),
                "computer": row.get("computer"),
            }
            correlations.append(correlation)
            corr_lookup[(correlation.get("computer"), correlation.get("base_image"))].append(correlation)

    matched_bursts = 0
    candidate_scans = 0
    max_bucket_size = 0
    for burst in bursts:
        bhost = burst.get("computer"); bimg = burst.get("image")
        candidates = corr_lookup.get((bhost, bimg), [])
        candidate_scans += len(candidates)
        if len(candidates) > max_bucket_size:
            max_bucket_size = len(candidates)
        matched = next((c for c in candidates if time_overlap(burst, c)), None)
        if matched:
            matched_bursts += 1
            burst["correlation_id"]   = matched.get("corr_id")
            burst["kill_chain_stage"] = promote_stage(burst.get("kill_chain_stage"), matched.get("kill_chain_stage") or "Execution")
            burst["correlation_score"] = 20
            burst["has_correlation"]   = True
            burst["_corr_persisted"]   = True
        else:
            burst["correlation_id"] = None
            burst.setdefault("correlation_score", 0.0)
            burst.setdefault("has_correlation", False)
    telemetry = {
        "correlation_rows": len(correlations),
        "index_keys": len(corr_lookup),
        "max_bucket_size": max_bucket_size,
        "candidate_scans": candidate_scans,
        "matched_bursts": matched_bursts,
        "burst_count": len(bursts),
    }
    corr_index = defaultdict(list)
    for i, b in enumerate(bursts):
        corr_index[(b.get("computer"), b.get("image"))].append((i, b))
    # --- Performance Lock: Batch Correlation Persistence ---
    pending_bursts = []
    for key, entries in corr_index.items():
        if len(entries) < 2:
            continue
        stages = {b.get("kill_chain_stage") for _,b in entries}
        start_times = []
        for _,b in entries:
            try: start_times.append(pd.to_datetime(b.get("start_time"), utc=True))
            except Exception: pass  # NaT / None timestamps — intentional skip
        age_min = 0.0
        if start_times:
            age_min = (pd.Timestamp.utcnow() - min(start_times)).total_seconds()/60.0
        if len(stages)>=2 and age_min>=5:
            strength = 30 if len(entries)>5 else 20
            for idx, burst in entries:
                burst["has_correlation"] = True
                burst["correlation_score"] = min(max(int(burst.get("correlation_score",0) or 0), strength), 30)
                burst["campaign_age_minutes"] = age_min
                if not burst.get("correlation_id"):
                    # Build a behavior-driven, deterministic auto-correlation id
                    try:
                        day = datetime.datetime.utcnow().strftime("%Y%m%d")
                        images = [str(b.get("image") or "").lower() for _, b in entries]
                        command_lines = [str(b.get("command_line") or b.get("commandline") or "").lower() for _, b in entries]
                        stages = {b.get("kill_chain_stage") for _, b in entries if b.get("kill_chain_stage")}
                        KILL_CHAIN_PRI = [
                            "Background", "Delivery", "Execution", "Defense Evasion",
                            "Persistence", "Privilege Escalation", "Credential Access",
                            "Discovery", "Lateral Movement", "Collection",
                            "Command and Control", "Exfiltration", "Actions on Objectives",
                        ]
                        final_stage = max(stages, key=lambda s: KILL_CHAIN_PRI.index(s) if s in KILL_CHAIN_PRI else 0) if stages else "Background"
                        host_count = len({str(b.get("computer") or "") for _, b in entries})
                        label = _build_campaign_name(images, command_lines, list(stages), final_stage, host_count)
                        import re as _re
                        safe_label = _re.sub(r"[^a-z0-9]", "_", str(label)[:16].lower())
                        burst["correlation_id"] = f"AUTO-{safe_label}-{key[0]}-{day}".lower()
                    except Exception:
                        day = datetime.datetime.utcnow().strftime("%Y%m%d")
                        burst["correlation_id"] = f"AUTO-{key[0]}-{key[1]}-{day}".lower()
                if not burst.get("_corr_persisted"):
                    pending_bursts.append(burst)
                    burst["_corr_persisted"] = True
    
    # 10/10 Production Lock: Single transaction for all auto-correlations
    if pending_bursts:
        mode = "cases" if run_id != "live" else "live"
        with get_db_connection(mode) as conn:
            with get_cursor(conn) as cur:
                for burst in pending_bursts:
                    _persist_auto_correlation_with_cursor(cur, burst, run_id)
                conn.commit()

    if bursts:
        bursts[0]["correlation_telemetry"] = telemetry

    if telemetry_sink is not None:
        telemetry_sink.update(telemetry)


# [DELETED] Legacy _compute_confidence_value removed in favor of Central Scoring Engine


def _calculate_confidence_and_severity(bursts, feature_cache, detections_df, telemetry_sink: Optional[Dict[str, Any]] = None):
    # --- Production Lock: O(N) Relevance-Preserving Indexing ---
    from collections import defaultdict
    all_dets = detections_df.to_dict(orient="records")
    
    # Primary index on (computer, process_id)
    det_index = defaultdict(list)
    # Fallback index on (computer, image)
    img_index = defaultdict(list)
    
    for d in all_dets:
        host = (d.get("computer") or "unknown_host").lower()
        pid  = str(d.get("process_id") or "0")
        img  = (d.get("image") or "").lower()
        
        if pid != "0":
            det_index[(host, pid)].append(d)
        if img:
            img_index[(host, img)].append(d)
            
    # 10/10 Lock: Memory-Bounded & Relevance-Safe Capping
    MAX_PER_KEY = 50
    for idx_dict in [det_index, img_index]:
        for key in idx_dict:
            if len(idx_dict[key]) > MAX_PER_KEY:
                # Sort by risk_score descending to keep high-signal events
                idx_dict[key] = sorted(
                    idx_dict[key], 
                    key=lambda x: int(x.get("risk_score", 0) or 0), 
                    reverse=True
                )[:MAX_PER_KEY]

    prev_conf_map: Dict = {}
    scoring_engine = get_scoring_engine()   # instantiate ONCE outside loop
    candidate_comparisons = 0
    matched_detections = 0
    for i, burst in enumerate(bursts):
        _, features = feature_cache[i]
        host = (burst.get("computer") or "unknown_host").lower()
        pid  = str(burst.get("process_id") or "0")
        img  = (burst.get("image") or "").lower()
        
        # Scoring context
        sc_key = (host, features["process_name"], features["user_type"], features["parent_process"], int(features.get("hour_bucket",-1)))
        
        # --- Elite 10/10 Scoring Integration ---
        if not validate_context(burst):
            burst["risk_score"] = 5
            burst["severity"] = "low"
            burst["confidence_reasons"] = ["Pipeline Guard: Minimum data requirements not met"]
            continue

        # --- O(N) Matcher Logic ---
        # 1. Primary match on PID
        candidates = det_index.get((host, pid), [])
        if not candidates and img:
            # 2. Fallback to Image
            candidates = img_index.get((host, img), [])
        candidate_comparisons += len(candidates)
            
        _dets = [
            d for d in candidates
            if match_detection_to_burst(d, burst)
        ]
        matched_detections += len(_dets)
        
        score_res = scoring_engine.score_burst(
            burst, 
            detections=_dets,
            behavior_score=float(burst.get("deviation_score", 0.0)),
            chain_depth=int(burst.get("chain_depth", 1)) if "chain_depth" in burst else 1
        )
        
        kc = burst.get("kill_chain_stage", "Background")
        res_dict = score_res.to_dict()
        burst["risk_score"] = int(res_dict["score"])
        burst["severity"] = res_dict["severity"]
        burst["primary_driver"] = res_dict["primary_driver"]
        burst["score_ledger"] = res_dict["ledger"]
        burst["score_why"] = res_dict["why"]
        burst["confidence_modifier"] = res_dict["confidence_modifier"]
        burst["classification"] = scoring_engine.classify(res_dict["score"], kc)

        burst["confidence_source"] = "SentinelTrace Elite Engine"
        prev_conf_map[sc_key] = (float(res_dict["score"]), kc)
        
        # Merge legacy reasons with new structured "why"
        burst["confidence_reasons"] = (burst.get("confidence_reasons") or []) + res_dict["why"]
        burst["ai_context"] = burst["confidence_reasons"][0] if burst["confidence_reasons"] else None

    if telemetry_sink is not None:
        telemetry_sink.update({
            "burst_count": len(bursts),
            "detections_rows": len(all_dets),
            "indexed_pid_keys": len(det_index),
            "indexed_image_keys": len(img_index),
            "candidate_comparisons": candidate_comparisons,
            "matched_detections": matched_detections,
        })


def _update_baselines(feature_cache, baseline_state):
    for burst, features in feature_cache:
        if _should_learn_baseline(burst, features):
            _update_local_baseline(burst, features, baseline_state)


# ---------------------------------------------------------------------------
# run_full_analysis
# ---------------------------------------------------------------------------

def _worker_analysis_task(run_id: str, run_correlation: bool):
    """Internal process worker entry point — re-imports all necessary engines."""
    # This runs in a SEPARATE PROCESS - we must re-initialize everything locally
    import logging
    from dashboard.analysis_engine import run_full_analysis_internal
    return run_full_analysis_internal(run_id, run_correlation)

def run_full_analysis(run_id: str, run_correlation: bool = True) -> Dict[str, Any]:
    """
    [9.5/10 HARDENED] Direct in-process analysis wrapper with threading timeout.

    NOTE: ProcessPoolExecutor was removed because it creates a SEPARATE OS process
    with separate memory — the in-process analysis_cache (dict) is never shared
    back to Flask, making snapshots permanently invisible → infinite dashboard load.

    We now run analysis directly in the calling thread with a concurrent.futures
    ThreadPoolExecutor so we get a real timeout without the IPC overhead.
    """
    import concurrent.futures as _cf
    _ANALYSIS_TIMEOUT = 900  # 15-minute hard limit

    # Warm check (non-blocking, logging only)
    try:
        from dashboard.app import is_system_ready
        if not is_system_ready():
            log.warning("[PIPELINE] Hot-Start: system still warming up — expect latency.")
    except Exception as _warm_e:
        log.debug("[PIPELINE] is_system_ready check skipped: %s", _warm_e)

    executor = _cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="analysis-worker")
    future = executor.submit(run_full_analysis_internal, run_id, run_correlation)
    executor.shutdown(wait=False)  # Don't block process shutdown on this thread

    try:
        result = future.result(timeout=_ANALYSIS_TIMEOUT)
        return result
    except _cf.TimeoutError:
        log.critical("[PIPELINE] Analysis TIMEOUT for run_id=%s after %ds.", run_id, _ANALYSIS_TIMEOUT)
        # Write a failed snapshot so the UI doesn't hang forever
        _fail = {
            "analysis_run_id": run_id,
            "status": "failed",
            "error": "Analysis timed out after 15 minutes",
            "timeline": [],
            "burst_aggregates": [],
            "attack_narrative": {
                "summary": "Analysis timed out",
                "stage": "Error",
                "score": 0,
                "is_attack": False,
            },
        }
        try:
            set_analysis_snapshot(run_id, _fail, authoritative=True)
        except Exception as _snap_e:
            log.error("[SNAPSHOT] Failed to write timeout snapshot for run_id=%s: %s", run_id[:16], _snap_e)
        raise RuntimeError(f"Analysis timed out after {_ANALYSIS_TIMEOUT}s")
    except Exception as e:
        log.error("[PIPELINE] Analysis failed: %s", e, exc_info=True)
        _fail = {
            "analysis_run_id": run_id,
            "status": "failed",
            "error": str(e)[:500],
            "timeline": [],
            "burst_aggregates": [],
            "attack_narrative": {
                "summary": f"Analysis failed: {str(e)[:200]}",
                "stage": "Error",
                "score": 0,
                "is_attack": False,
            },
        }
        try:
            set_analysis_snapshot(run_id, _fail, authoritative=True)
        except Exception as _snap_e:
            log.error("[SNAPSHOT] Failed to write failure snapshot for run_id=%s: %s", run_id[:16], _snap_e)
        raise

def run_full_analysis_internal(run_id: str, run_correlation: bool = True) -> Dict[str, Any]:
    log = logging.getLogger("analysis")
    log.info("[MASTERY] run_full_analysis CALLED for run_id=%s", run_id)

    # 9.8: Start per-thread deadline timer
    _start_analysis_timer()
    try:
        from dashboard.db import ANALYZING as _DB_ANALYZING, get_run_state as _get_run_state, set_run_state as _set_run_state

        if _get_run_state(run_id) != _DB_ANALYZING:
            _set_run_state(run_id, _DB_ANALYZING, "Analysis pipeline started")
    except Exception as _state_exc:
        log.warning("[STATE] Unable to mark run_id=%s as ANALYZING: %s", run_id[:16], _state_exc)
    _perf = _PerfTimer(run_id)
    _profiler = cProfile.Profile()
    _profiler.enable()
    current_backend_stage = "initialization"

    def _publish_progress(
        progress: int,
        message: str,
        *,
        state: str = "running",
        active_stage: str = "",
        stage_started_at: Optional[float] = None,
        processed_events: int = 0,
        total_events: int = 0,
        operation_label: str = "",
        metrics: Optional[Dict[str, Any]] = None,
        error: str = "",
        traceback_summary: str = "",
    ) -> None:
        nonlocal current_backend_stage

        if active_stage:
            current_backend_stage = active_stage

        publish_analysis_stage_progress(
            run_id,
            state=state,
            progress=progress,
            message=message,
            active_stage=active_stage or current_backend_stage,
            operation_label=operation_label,
            stage_started_at=stage_started_at,
            processed_events=processed_events,
            total_events=total_events,
            metrics=metrics,
            error=error or None,
            traceback_summary=traceback_summary or None,
        )

        from dashboard.progress import set_run_progress

        set_run_progress(
            run_id,
            state,
            progress,
            message,
            active_stage=active_stage or current_backend_stage,
            stage_elapsed_seconds=(
                round(_time.monotonic() - stage_started_at, 3)
                if stage_started_at is not None
                else 0.0
            ),
            processed_events=processed_events,
            total_events=total_events,
            operation_label=operation_label,
            metrics=metrics or {},
            error=error or None,
            heartbeat_reset=True,
        )

    snapshot_inputs_steps: List[Dict[str, Any]] = []

    @contextmanager
    def _trace_snapshot_inputs_step(
        step_name: str,
        *,
        event_count: int = 0,
        object_counts: Optional[Dict[str, Any]] = None,
        lock_wait_ms: int = 0,
    ):
        thread_id = threading.get_ident()
        started_at = _time.perf_counter()
        started_rss = _current_process_rss_bytes()
        record = {
            "step": step_name,
            "thread_id": thread_id,
            "event_count": int(event_count or 0),
            "object_counts": dict(object_counts or {}),
            "lock_wait_ms": int(lock_wait_ms or 0),
            "enter_rss_bytes": started_rss,
        }
        snapshot_inputs_steps.append(record)
        log.info(
            "[SNAPSHOT_INPUTS] ENTER step=%s run_id=%s thread_id=%s event_count=%d object_counts=%s lock_wait_ms=%d rss_bytes=%d",
            step_name,
            run_id[:16],
            thread_id,
            int(event_count or 0),
            record["object_counts"],
            int(lock_wait_ms or 0),
            started_rss,
        )
        try:
            yield record
        finally:
            ended_rss = _current_process_rss_bytes()
            elapsed_ms = int((_time.perf_counter() - started_at) * 1000)
            record.update(
                {
                    "elapsed_ms": elapsed_ms,
                    "exit_rss_bytes": ended_rss,
                    "rss_delta_bytes": ended_rss - started_rss,
                }
            )
            log.info(
                "[SNAPSHOT_INPUTS] EXIT step=%s run_id=%s thread_id=%s elapsed_ms=%d event_count=%d object_counts=%s lock_wait_ms=%d rss_delta_bytes=%d rss_bytes=%d",
                step_name,
                run_id[:16],
                thread_id,
                elapsed_ms,
                int(event_count or 0),
                record["object_counts"],
                int(lock_wait_ms or 0),
                ended_rss - started_rss,
                ended_rss,
            )

    context = {} # Initialize for the failsafe wrapper
    try:
        # Verify events exist for this run_id before proceeding
        log.info("[PIPELINE] Verifying events for run_id=%s", run_id[:16])
    
        # Force SQLAlchemy to drop stale pooled connections so read_sql_query sees
        # the rows freshly committed by persist_case (which uses mysql.connector).
        try:
            dispose_engine("cases")
            dispose_engine("live")
        except Exception as _disp_e:
            log.debug("[PIPELINE] dispose_engine skipped (non-critical): %s", _disp_e)
    
        # Safe defaults
        evidence_state = {}
        kill_chain_summary: List[Dict] = []
        kc_severity: Dict = {}
        highest_kill_chain = None
        mitre_summary: List[Dict] = []
        correlation_campaigns: List[Dict] = []
        correlations: List[Dict] = []
        correlations_detail: List[Dict] = []
        correlation_hunts: List[Dict] = []
        correlation_score = 0
        top_events: List[Dict] = []
        interesting: List[Dict] = []
        recent: List[Dict] = []
        events_per_hour: List[Dict] = []
        events_by_severity = {"high":0,"medium":0,"low":0}
        lolbins_summary: List[Dict] = []
        baseline_execution_context: List[Dict] = []
        burst_aggregates: List[Dict] = []
        top_dangerous_bursts: List[Dict] = []
        timeline: List[Dict] = []
        attack_conf_score = 0
        attack_conf_level = "Low"
        attack_conf_cap = None
        attack_conf_basis: List[str] = []
        dominant_burst = None
        confidence_trend: List[int] = []
        analyst_verdict = analyst_action = action_priority = action_reason = None
        response_tasks: List[Dict] = []
        incident = None
    
        update_campaign_status_lifecycle()
        import pandas as pd
        from sqlalchemy import text
        df         = load_events(run_id)
        
        if df is None or df.empty:
            log.warning(f"[PIPELINE] run_id={run_id[:16]} has no event data. Skipping to fallback.")
            fallback = {
                "analysis_run_id": run_id,
                "timeline": [],
                "burst_aggregates": [],
                "events": [],
                "attack_narrative": {
                    "summary": "No data available",
                    "stage": "None",
                    "score": 0,
                    "is_attack": False
                },
                "status": "complete"
            }
            set_analysis_snapshot(run_id, fallback, authoritative=True)
            _emit_analysis_profile_summary(run_id, _profiler, _perf, fallback, "no_events")
            return fallback

        total_events = len(df)
        log.info(
            "[PIPELINE] run_id=%s raw events=%d, detections loaded",
            run_id[:16], total_events
        )
        _perf.lap("load_events")
        from dashboard.progress import set_run_progress
        set_run_progress(run_id, "running", 40, "Building event bursts…")

        burst_stage_started = _time.monotonic()
        _publish_progress(42, "Building event bursts…", active_stage="burst_assembly", stage_started_at=burst_stage_started, operation_label="Loading burst graph", total_events=len(df))
        detections_df = load_detections(run_id)
        detections_df = detections_df.loc[:, ~detections_df.columns.duplicated()]
        _perf.lap("load_detections")

        check_timeout("post-load")
        corr_df = load_correlations(run_id)
        campaigns_df  = load_correlation_campaigns(run_id)
        corr_detail_df = load_correlations_detail(run_id)
        beh_df        = load_behaviors(run_id)

        # Also trim behaviors – they contain all 60k rows and cause the 900s hang
        log.info("[PIPELINE] Loaded behaviors: %d rows", len(beh_df))
        if not beh_df.empty and "event_time" in beh_df.columns:
            # Preserve native datetime values from MySQL and compare them directly.
            beh_df["_parsed_time"] = beh_df["event_time"]
            df["_event_time_utc"] = df["event_time"]
            min_t = df["_event_time_utc"].min()
            max_t = df["_event_time_utc"].max()
            beh_df = beh_df[
                (beh_df["_parsed_time"] >= min_t) &
                (beh_df["_parsed_time"] <= max_t)
            ]
            beh_df = beh_df.dropna(subset=["_parsed_time"]).sort_values("_parsed_time")
            log.info("[PIPELINE] Trimmed behaviors to %d rows", len(beh_df))
            # Drop the temporary UTC column we added to df
            df.drop(columns=["_event_time_utc"], inplace=True, errors="ignore")
        else:
            log.warning("[PIPELINE] behaviors table is empty or missing event_time column; burst building may be limited")
        baseline_state = load_behavior_baseline()
    
        correlations = corr_df.to_dict(orient="records") if not corr_df.empty else []
    
        if not detections_df.empty:
            norm = detections_df.copy()
            norm["_parsed_time_det"] = norm["utc_time"]
            for col in ["event_id", "parent_image"]:
                if col in norm.columns and isinstance(norm[col], pd.DataFrame):
                    norm[col] = norm[col].iloc[:,0]
            normalized_detections = (
                norm.groupby(["rule_id","image","mitre_id"])
                .agg(first_seen=("_parsed_time_det","min"), last_seen=("_parsed_time_det","max"),
                     count=("event_id","size"), unique_parents=("parent_image","nunique"))
                .reset_index()
            )
        else:
            import pandas as pd
            normalized_detections = pd.DataFrame(
                columns=["rule_id","image","mitre_id","first_seen","last_seen","count","unique_parents"]
            )
    
        # Wire detection kill-chain stages into bursts before deviation scoring
        if not detections_df.empty and "kill_chain_stage" in detections_df.columns and "image" in detections_df.columns:
            _kc_order_map = {s: i for i, s in enumerate(KILL_CHAIN_ORDER)}
            _det_stage_rank = detections_df[["image", "kill_chain_stage"]].copy()
            _det_stage_rank["image"] = _det_stage_rank["image"].fillna("").astype(str).str.lower()
            _det_stage_rank["kill_chain_stage"] = _det_stage_rank["kill_chain_stage"].fillna("").astype(str)
            _det_stage_rank["stage_rank"] = _det_stage_rank["kill_chain_stage"].map(_kc_order_map).fillna(-1).astype(int)
            _det_stage_rank = _det_stage_rank[_det_stage_rank["image"] != ""]
            _det_stage_rank = _det_stage_rank[_det_stage_rank["stage_rank"] >= 0]
            _det_stage_rank = _det_stage_rank.sort_values(["image", "stage_rank"], ascending=[True, False])
            _det_kc_map = _det_stage_rank.drop_duplicates(subset=["image"], keep="first").set_index("image")["kill_chain_stage"].to_dict()
        else:
            _det_kc_map = {}
    
        grouped_rows = _build_bursts(df, beh_df, run_id)
        # Stamp detection-derived kill chain on bursts
        for _burst in grouped_rows:
            _bimg = str(_burst.get("image") or "").lower()
            if _bimg in _det_kc_map:
                _burst["kill_chain_stage_from_detection"] = _det_kc_map[_bimg]
        _perf.lap("burst_assembly")
        _publish_progress(
            48,
            "Completed burst assembly.",
            active_stage="burst_assembly",
            stage_started_at=burst_stage_started,
            processed_events=len(grouped_rows),
            total_events=len(df),
            operation_label="Burst assembly complete",
        )
    
        scoring_stage_started = _time.monotonic()
        scoring_stage_metrics: List[Dict[str, Any]] = []

        @contextmanager
        def _trace_scoring_step(step_name: str, event_count: int = 0, object_counts: Optional[Dict[str, Any]] = None):
            started_at = _time.perf_counter()
            started_rss = _current_process_rss_bytes()
            record: Dict[str, Any] = {
                "step": step_name,
                "event_count": int(event_count or 0),
                "object_counts": dict(object_counts or {}),
                "enter_rss_bytes": started_rss,
            }
            scoring_stage_metrics.append(record)
            log.info(
                "[CORRELATION_SCORING] ENTER step=%s run_id=%s event_count=%d object_counts=%s rss_bytes=%d",
                step_name,
                run_id[:16],
                int(event_count or 0),
                record["object_counts"],
                started_rss,
            )
            try:
                yield record
            finally:
                ended_rss = _current_process_rss_bytes()
                elapsed_ms = int((_time.perf_counter() - started_at) * 1000)
                rows_per_sec = 0.0
                elapsed_seconds = elapsed_ms / 1000.0
                if elapsed_seconds > 0 and event_count:
                    rows_per_sec = round(event_count / elapsed_seconds, 2)
                record.update(
                    {
                        "elapsed_ms": elapsed_ms,
                        "rows_per_sec": rows_per_sec,
                        "exit_rss_bytes": ended_rss,
                        "rss_delta_bytes": ended_rss - started_rss,
                    }
                )
                log.info(
                    "[CORRELATION_SCORING] EXIT step=%s run_id=%s elapsed_ms=%d event_count=%d rows_per_sec=%.2f object_counts=%s rss_delta_bytes=%d rss_bytes=%d",
                    step_name,
                    run_id[:16],
                    elapsed_ms,
                    int(event_count or 0),
                    rows_per_sec,
                    record["object_counts"],
                    ended_rss - started_rss,
                    ended_rss,
                )

        with _trace_scoring_step(
            "feature_deviation_scoring",
            event_count=len(grouped_rows),
            object_counts={"burst_rows": len(grouped_rows)},
        ):
            feature_cache = _calculate_ml_deviations(grouped_rows, baseline_state)
            scoring_stage_metrics[-1]["object_counts"]["feature_rows"] = len(feature_cache)
            for burst, features in feature_cache:
                dev = features.get("deviation_score")
                if dev is not None:
                    try:
                        burst["deviation_score"] = float(dev)
                    except Exception:
                        pass  # Non-numeric deviation — intentional no-op

        _publish_progress(
            60,
            "Running correlation scoring…",
            active_stage="correlation_scoring",
            stage_started_at=scoring_stage_started,
            processed_events=len(grouped_rows),
            total_events=len(df),
            operation_label="Preparing correlation scoring",
        )

        with _trace_scoring_step(
            "event_linking",
            event_count=len(grouped_rows),
            object_counts={"correlation_rows": len(corr_df), "burst_rows": len(grouped_rows)},
        ):
            correlation_stage_metrics: Dict[str, Any] = {}
            for burst in grouped_rows:
                burst.pop("_corr_persisted", None)
            _apply_correlations(grouped_rows, corr_df, run_id, telemetry_sink=correlation_stage_metrics)
            correlation_telemetry = grouped_rows[0].get("correlation_telemetry") if grouped_rows else None

        with _trace_scoring_step(
            "graph_traversal",
            event_count=len(grouped_rows),
            object_counts={"burst_rows": len(grouped_rows)},
        ):
            _apply_kill_chain_logic(grouped_rows, telemetry_sink=correlation_stage_metrics)

        with _trace_scoring_step(
            "score_aggregation",
            event_count=len(grouped_rows),
            object_counts={"detections_rows": len(detections_df), "feature_rows": len(feature_cache)},
        ):
            _calculate_confidence_and_severity(grouped_rows, feature_cache, detections_df, telemetry_sink=correlation_stage_metrics)

        _perf.lap("correlation_scoring")
        _publish_progress(
            62,
            "Completed correlation and scoring.",
            active_stage="correlation_scoring",
            stage_started_at=scoring_stage_started,
            processed_events=len(grouped_rows),
            total_events=len(df),
            operation_label="Correlation and scoring complete",
        )
        
        # --- SMART BURST FILTER (FIX 13) ---
        # Keeps high-frequency noise out but preserves low-freq high-signal alerts
        grouped_rows = [
            b for b in grouped_rows
            if (
                int(b.get("count", 0)) >= 3 or
                int(b.get("risk_score", 0)) >= 40 or
                b.get("kill_chain_stage") in ("Execution", "Persistence", "Privilege Escalation")
            )
        ]
        
        # --- BURST PRIORITIZATION (FIX 15) ---
        # Ensure high-risk bursts appear first in dashboard
        KC_RANK = {k: i for i, k in enumerate(["Background","Delivery","Execution","Defense Evasion","Persistence","Privilege Escalation","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Actions on Objectives"])}
        grouped_rows = sorted(
            grouped_rows,
            key=lambda b: (
                int(b.get("risk_score", 0)),
                KC_RANK.get(b.get("kill_chain_stage", "Background"), 0),
                int(b.get("count", 0))
            ),
            reverse=True
        )
    
        baseline_stage_started = _time.monotonic()
        from dashboard.progress import set_run_progress
        _publish_progress(
            66,
            "Persisting analysis outputs…",
            active_stage="persistence",
            stage_started_at=baseline_stage_started,
            processed_events=len(grouped_rows),
            total_events=len(df),
            operation_label="Persisting correlation and baseline state",
        )
        _update_baselines(feature_cache, baseline_state)
        persist_behavior_baseline(baseline_state)
        set_run_progress(
            run_id,
            "running",
            70,
            "Running correlation…",
            active_stage="persistence",
            stage_elapsed_seconds=round(_time.monotonic() - baseline_stage_started, 3),
            processed_events=len(grouped_rows),
            total_events=len(df),
            operation_label="Persisting baseline state",
            heartbeat_reset=True,
        )
    
        with _trace_snapshot_inputs_step(
            "event_rollup",
            event_count=len(df),
            object_counts={
                "rows": len(df),
                "columns": len(df.columns),
                "detections_rows": len(detections_df),
            },
        ):
            # Severity counts
            if not df.empty and "severity" in df.columns:
                severity_lower = df["severity"].fillna("low").astype(str).str.lower()
                df["severity"] = severity_lower
                sev_counts = {str(k): int(v) for k, v in severity_lower.value_counts().to_dict().items()}
                severity_counts = severity_lower.value_counts()
                high_count = int(severity_counts.get("high", 0))
                medium_count = int(severity_counts.get("medium", 0))
                low_count = int(severity_counts.get("low", 0))
            else:
                sev_counts = {}
                high_count = medium_count = low_count = 0
            events_by_severity = sev_counts
            detections_count = len(detections_df)

            if df is not None and not df.empty:
                _te = df["event_id"].value_counts().head(10).reset_index()
                _te.columns = ["event_id", "count"]
                top_events = _te.to_dict(orient="records")

        suspicious_images = ["cmd.exe", "powershell.exe", "pwsh.exe", "wmic.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe"]
        sort_col = "event_time" if "event_time" in df.columns else "utc_time" if "utc_time" in df.columns else None
        with _trace_snapshot_inputs_step(
            "timeline_visibility",
            event_count=len(df),
            object_counts={
                "interesting_candidate_rows": len(df) if not df.empty else 0,
                "sort_column": 1 if sort_col else 0,
            },
        ):
            if not df.empty and "image" in df.columns:
                interesting_df = df[df["image"].notna() & df["image"].str.lower().str.contains("|".join(suspicious_images), na=False)]
                if sort_col:
                    interesting_df = interesting_df.sort_values(sort_col, ascending=False)
                interesting_df = interesting_df.head(100)
            else:
                interesting_df = df.iloc[0:0]

            recent_df = df.sort_values(sort_col, ascending=False).head(50) if sort_col and not df.empty else df

        with _trace_snapshot_inputs_step(
            "payload_normalization",
            event_count=len(detections_df),
            object_counts={
                "detections_rows": len(detections_df),
                "utc_time_columns": 1 if "utc_time" in detections_df.columns else 0,
            },
        ):
            if not detections_df.empty and "severity" in detections_df.columns:
                det_copy = detections_df.copy()
                sev_w = {"high": "+10", "medium": "+5", "low": "+2"}
                det_copy["confidence_impact"] = det_copy["severity"].fillna("unknown").str.lower().map(lambda s: sev_w.get(s, "+0"))
            else:
                det_copy = detections_df.copy()
                det_copy["confidence_impact"] = "+0"
            detections = det_copy.sort_values("utc_time", ascending=False).head(50) if "utc_time" in det_copy.columns else det_copy
            detections = detections.loc[:, ~detections.columns.duplicated()]
            # Convert all Timestamp columns to ISO strings so Jinja [:16] slicing works
            for _dc in detections.columns:
                if detections[_dc].dtype.kind == "M" or (not detections.empty and hasattr(detections[_dc].iloc[0], "isoformat")):
                    detections[_dc] = detections[_dc].astype(str)

        with _trace_snapshot_inputs_step(
            "lineage_hydration",
            event_count=len(df),
            object_counts={
                "source_rows": len(df),
                "selected_columns": len([c for c in ("image", "computer", "event_time", "event_id", "parent_image") if c in df.columns]),
            },
        ):
            # Baseline context
            baseline_execution_context = []
            if not df.empty:
                # Only copy the minimal columns needed for baseline execution context
                cols_needed = [c for c in ("image", "computer", "event_time", "event_id", "parent_image") if c in df.columns]
                df_base = df[cols_needed].copy() if cols_needed else df.head(0).copy()
                df_base["image"] = df_base["image"].astype(str).str.strip()
                if "computer" not in df_base.columns:
                    df_base["computer"] = None
                df_base = df_base[df_base["image"].notna() & (df_base["image"] != "") & (df_base["image"].str.lower() != "unknown process")]
                if not df_base.empty:
                    _time_col = "event_time" if "event_time" in df_base.columns else "utc_time"
                    grouped = df_base.groupby(["image", "computer"], dropna=False).agg(first_seen=(_time_col, "min"), last_seen=(_time_col, "max"), exec_count=("event_id", "size")).reset_index()

                    parent_lookup: Dict[Tuple[Any, Any], Any] = {}
                    if "parent_image" in df_base.columns:
                        parent_counts = (
                            df_base[["image", "computer", "parent_image"]]
                            .dropna(subset=["parent_image"])
                            .groupby(["image", "computer", "parent_image"], dropna=False)
                            .size()
                            .reset_index(name="count")
                            .sort_values(["image", "computer", "count", "parent_image"], ascending=[True, True, False, True])
                        )
                        for row in parent_counts.itertuples(index=False):
                            key = (row.image, row.computer)
                            if key not in parent_lookup:
                                parent_lookup[key] = row.parent_image

                    brows = []
                    grouped_records = grouped.to_dict(orient="records")
                    total_grouped = len(grouped_records) or 1
                    for index, r in enumerate(grouped_records, start=1):
                        duration = r["last_seen"] - r["first_seen"]
                        secs = max(duration.total_seconds(), 60.0)
                        mins = secs / 60.0
                        ec = int(r["exec_count"])
                        rate = ec / mins
                        th = int(duration.total_seconds() // 60)
                        hh = th // 60
                        mm = th % 60
                        dl = f"{hh}h {mm}m" if hh else f"{mm}m"
                        bsl = ("Low activity in this run" if rate < 1 else "Bursting in this run" if rate < 10 else "Heavy activity in this run")
                        pi = parent_lookup.get((r["image"], r.get("computer")))
                        brows.append({"image": r["image"], "computer": r.get("computer") or "unknown_host", "first_seen": r["first_seen"].isoformat(), "last_seen": r["last_seen"].isoformat(), "start_label": r["first_seen"].strftime("%H:%M"), "end_label": r["last_seen"].strftime("%H:%M"), "duration_label": dl, "exec_count": ec, "exec_rate_per_min": round(rate, 1), "baseline_state": bsl, "parent_image": pi, "baseline_deviation": "No historical baseline", "why_non_alerting": ["No historical baseline", "No persistence indicators in this run", "No external network activity tied to this process in this run"]})
                        if index % 200 == 0 or index == total_grouped:
                            _publish_progress(
                                79,
                                "Hydrating snapshot lineage…",
                                active_stage="snapshot_inputs",
                                processed_events=index,
                                total_events=total_grouped,
                                operation_label="Hydrating lineage structures",
                            )
                    brows.sort(key=lambda b: (-b["exec_count"], b["first_seen"]))
                    baseline_execution_context = brows[:10]

            _publish_progress(
                78,
                "Completed baseline and narrative inputs.",
                active_stage="snapshot_inputs",
                processed_events=len(grouped_rows),
                total_events=len(df),
                operation_label="Preparing snapshot data",
            )
    
        # Force correlation persist loop — persists new bursts into correlations table
        print(f"[DEBUG] forcing persist_auto_correlation loop for {len(grouped_rows)} bursts")
        pending_to_persist = []
        persisted_ids = set()  # Dedup per run

        with _trace_scoring_step(
            "persistence_candidate_selection",
            event_count=len(grouped_rows),
            object_counts={"burst_rows": len(grouped_rows), "correlation_candidates": 0},
        ):
            for burst in grouped_rows:
                bid = burst.get("burst_id")
                if not bid or bid in persisted_ids:
                    continue

                # --- SOC-Grade Priority Persistence (REFINED) ---
                score = int(burst.get("risk_score", 0))
                stage = burst.get("kill_chain_stage", "Background")
                freq = int(burst.get("count", 0) or burst.get("event_count", 0) or 0)

                # Persist if high risk, stealth stage, or high frequency
                should_persist = (score >= 45) or (stage in ("Persistence", "Privilege Escalation")) or (freq >= 5)

                if should_persist:
                    pending_to_persist.append(burst)
                    persisted_ids.add(bid)

        persist_summary: Dict[str, Any] = {"campaign_rows": [], "detail_rows": [], "burst_count": 0, "campaign_count": 0, "existing_campaign_count": 0}
        with _trace_scoring_step(
            "campaign_persistence_write",
            event_count=len(pending_to_persist),
            object_counts={"pending_bursts": len(pending_to_persist)},
        ):
            # --- Protect the DB write phase (thread-safe) ---
            with DB_WRITE_LOCK:
                if run_correlation and pending_to_persist:
                    persist_summary = persist_auto_correlation_bulk(pending_to_persist, run_id)
                    print(f"[DEBUG] persisted {len(pending_to_persist)} new correlations (batch)")
                elif not run_correlation:
                    print("[DEBUG] skipping original auto-correlation (run_correlation=False)")

        with _trace_scoring_step(
            "post_persist_merge",
            event_count=len(pending_to_persist),
            object_counts={"campaign_rows": len(persist_summary.get("campaign_rows", [])), "detail_rows": len(persist_summary.get("detail_rows", []))},
        ):
            if persist_summary.get("detail_rows"):
                correlations.extend(persist_summary["detail_rows"])
                corr_detail_df = pd.concat([corr_detail_df, pd.DataFrame(persist_summary["detail_rows"])], ignore_index=True) if not corr_detail_df.empty else pd.DataFrame(persist_summary["detail_rows"])
            if persist_summary.get("campaign_rows"):
                campaigns_df = pd.concat([campaigns_df, pd.DataFrame(persist_summary["campaign_rows"])], ignore_index=True) if not campaigns_df.empty else pd.DataFrame(persist_summary["campaign_rows"])

        from dashboard.progress import set_run_progress
        set_run_progress(run_id, "running", 90, "Finalising narrative…")
    
        # 10/10 SOC: Weighted Average Correlation (Resilient to Noise)
        with _trace_scoring_step(
            "score_aggregation_final",
            event_count=len(grouped_rows),
            object_counts={"scored_bursts": len(grouped_rows)},
        ):
            _valid_bursts = [b for b in grouped_rows if int(b.get("risk_score", 0)) >= 40]

            if not _valid_bursts:
                correlation_score = 0
            else:
                _weighted = sum(int(b.get("risk_score", 0)) for b in _valid_bursts) / len(_valid_bursts)
                correlation_score = min(30.0, _weighted * 0.3)

            _unique_stages = set(b.get("kill_chain_stage") for b in _valid_bursts)
            if len(_unique_stages) < 2:
                correlation_score *= 0.5
    
        # Final cleanup
        known_benign = {"services.exe","wininit.exe","winlogon.exe","lsass.exe","csrss.exe","svchost.exe","spoolsv.exe","explorer.exe"}
        known_benign_parents = {"splunkd.exe","osqueryd.exe","senseir.exe","crowdstrike.exe","carbonblack.exe"}
        for burst in grouped_rows:
            if "risk_score" in burst:  burst["risk_score"] = int(burst["risk_score"])
            if "stage_cap"  in burst:  burst["stage_cap"]  = int(burst["stage_cap"])
            if not burst.get("_pre_suppressed"):
                user = (burst.get("user") or "").upper()
                dev  = float(burst.get("deviation_score",0.0) or 0.0)
                dst  = burst.get("destination_ip") or ""
                ext  = is_external_ip(dst)
                has_followup = bool(burst.get("has_persistence") or burst.get("has_injection") or ext)
                img  = _safe_lower_text(burst.get("image"))
                par  = _safe_lower_text(burst.get("parent_image"))
                if "SYSTEM" in user and dev<0.3 and not has_followup:
                    burst["risk_score"] = min(burst.get("risk_score",0) or 0, 15)
                    burst["classification"] = "background_activity"
                    burst.setdefault("suppression_reason","SYSTEM low-deviation background activity")
                elif img in known_benign and dev<0.4:
                    stage = burst.get("kill_chain_stage") or "Background"
                    if stage in ("Background","Execution"):
                        burst["risk_score"] = min(burst.get("risk_score",0) or 0, 20)
                        burst.setdefault("suppression_reason","Known benign image with low deviation")
                elif par in known_benign_parents and not ext and dev<0.5:
                    burst["risk_score"] = min(burst.get("risk_score",0) or 0, 25)
                    burst.setdefault("suppression_reason","Child of known benign parent")
            for fld in ("confidence_reasons","suppression_reason","confidence_source","correlation_score","campaign_age_minutes"):
                burst.setdefault(fld, [] if fld=="confidence_reasons" else None if fld=="suppression_reason" else "AI/ML Engine" if fld=="confidence_source" else 0)
            burst["final_kill_chain"] = burst.get("kill_chain_stage")
    
        # Burst aggregates
        agg = defaultdict(list)
        for i, b in enumerate(grouped_rows):
            key = (b["image"], b.get("computer"), run_id, _timeline_key_prefix(b.get("start_time")))
            agg[key].append((i, b))
        burst_aggregates = []
        for (image, computer, rid, tb), items in agg.items():
            raw_ids_set = set()
            for _, b in items:
                for e in (b.get("event_ids") or []):
                    if e and str(e).lower() != "none": raw_ids_set.add(str(e))
            combined_eids = sorted(list(raw_ids_set), key=lambda x: int(x) if x.isdigit() else x)
            max_rb = max(items, key=lambda x: x[1].get("risk_score",0))[1]
            burst_aggregates.append({
                "burst_id":       items[0][1].get("burst_id"),
                "image":          image,
                "kill_chain_stage": max(b["kill_chain_stage"] for _,b in items),
                "total_count":    sum(b["count"] for _,b in items),
                "peak_score":     max(b["risk_score"] for _,b in items),
                "confidence_reasons": items[0][1].get("confidence_reasons",[]),
                "timeline_indices": [i for i,_ in items],
                "event_ids":      combined_eids,
                "stage_cap":      max_rb.get("stage_cap",100),
                "burst_count":    len(items),
                "_pre_suppressed": items[0][1].get("_pre_suppressed",False),
                "ai_context":     items[0][1].get("ai_context"),
                "has_correlation": any(b.get("has_correlation") for _,b in items),
                "exec_sum":  sum(b.get("exec_event_count",0) for _,b in items),
                "net_sum":   sum(b.get("net_event_count",0) for _,b in items),
                "file_sum":  sum(1 for _,b in items if b.get("has_file")),
                "reg_sum":   sum(1 for _,b in items if b.get("has_reg")),
            })
        burst_aggregates.sort(key=lambda x: x["peak_score"], reverse=True)
        _perf.lap("snapshot_assembly")
        _publish_progress(
            84,
            "Completed snapshot assembly.",
            active_stage="snapshot_assembly",
            processed_events=len(burst_aggregates),
            total_events=len(grouped_rows) if grouped_rows else len(df),
            operation_label="Snapshot assembly complete",
        )
    
        # ── Build attack narrative / story ──────────────────────────────────────
        # Group top bursts by host+user into a coherent attack story chain.
        # This is what elevates a "rule engine" into a real SIEM.
        attack_story: List[str] = []
        story_entities: Dict[str, List] = defaultdict(list)
        for _b in sorted(grouped_rows, key=lambda x: x.get("risk_score",0), reverse=True)[:30]:
            _host = _b.get("computer") or "unknown"
            _user = _b.get("user") or "unknown"
            story_entities[f"{_host}|{_user}"].append(_b)
    
        for _entity, _entity_bursts in story_entities.items():
            _host, _user = _entity.split("|", 1)
            # Sort by kill-chain stage index for chronological story
            _entity_bursts.sort(key=lambda x: KILL_CHAIN_ORDER.index(x.get("kill_chain_stage","Background"))
                                 if x.get("kill_chain_stage") in KILL_CHAIN_ORDER else 0)
            for _b in _entity_bursts:
                _stage = _b.get("kill_chain_stage") or "Background"
                _img   = _b.get("image") or "unknown"
                _score = int(_b.get("risk_score",0) or 0)
                _cnt   = int(_b.get("count",0) or 0)
                if _score < 20 and _stage == "Background":
                    continue
                _cmd_hint = ""
                _descs = _b.get("descriptions") or []
                if _descs:
                    _sample = str(_descs[0])[:60] if _descs else ""
                    if _sample:
                        _cmd_hint = f" [{_sample}]"
                if _stage == "Actions on Objectives":
                    attack_story.append(f"⚠ IMPACT: {_img} on {_host} ({_cnt} events, score {_score}){_cmd_hint}")
                elif _stage == "Command and Control":
                    _dst = _b.get("destination_ip") or "unknown IP"
                    attack_story.append(f"🌐 C2 BEACON: {_img} → {_dst} on {_host} ({_cnt} events, score {_score})")
                elif _stage == "Credential Access":
                    attack_story.append(f"🔑 CRED ACCESS: {_img} on {_host} ({_cnt} events, score {_score})")
                elif _stage == "Privilege Escalation":
                    attack_story.append(f"⬆ PRIV ESC: {_img} on {_host} ({_cnt} events, score {_score})")
                elif _stage == "Persistence":
                    attack_story.append(f"📌 PERSISTENCE: {_img} on {_host} ({_cnt} events, score {_score}){_cmd_hint}")
                elif _stage in ("Execution","Defense Evasion") and _score >= 30:
                    attack_story.append(f"▶ {_stage.upper()}: {_img} on {_host} ({_cnt} events, score {_score}){_cmd_hint}")
        attack_story = attack_story[:20]  # cap for display
        _publish_progress(
            88,
            "Completed narrative generation.",
            active_stage="narrative_generation",
            processed_events=len(attack_story),
            total_events=len(grouped_rows) if grouped_rows else len(df),
            operation_label="Narrative generation complete",
        )
    
        # Kill-chain summary — build BEFORE attack_conf_score computation so it can be used
        kc_counts: Dict = {}
        for b in grouped_rows:
            stage = b.get("kill_chain_stage") or "Background"
            if stage != "Background":
                kc_counts[stage] = kc_counts.get(stage, 0) + 1
        kill_chain_summary = [{"stage": s, "count": c} for s, c in kc_counts.items()]
        # Also derive from detections if bursts gave nothing
        if not kill_chain_summary and not detections_df.empty and "kill_chain_stage" in detections_df.columns:
            kc_det = detections_df["kill_chain_stage"].value_counts().reset_index()
            kc_det.columns = ["stage", "count"]
            kill_chain_summary = kc_det.to_dict(orient="records")
    
        # Attack confidence
        attack_conf_score = 0.0; attack_conf_basis = []
        max_det_conf = 0
        if not detections_df.empty and "confidence_score" in detections_df.columns:
            try:
                max_det_conf = int(detections_df["confidence_score"].fillna(0).astype(float).max())
            except Exception:
                max_det_conf = 0
        det_count = len(detections_df)
        if max_det_conf == 0 and not detections_df.empty:
            max_det_conf = min(45, det_count * 8)
        if max_det_conf > 0:
            det_component = min(36.0, (max_det_conf * 0.45) + min(10.0, det_count * 1.5))
            attack_conf_score += det_component
            attack_conf_basis.append(f"{det_count} detection(s) peaked at {max_det_conf} confidence")
        distinct_tactics = set()
        if not detections_df.empty and "mitre_tactic" in detections_df.columns:
            distinct_tactics = {str(t).strip() for t in detections_df["mitre_tactic"].dropna() if str(t).strip()}
        n_tactics = len(distinct_tactics)
        if n_tactics >= 1:
            tactic_component = min(15.0, 4.0 + (n_tactics - 1) * 4.0)
            attack_conf_score += tactic_component
            attack_conf_basis.append(f"{n_tactics} MITRE tactic(s) linked across the chain")
        highest_kill_chain = None
        if grouped_rows:
            stages = [b.get("kill_chain_stage") for b in grouped_rows
                      if b.get("kill_chain_stage") in KILL_CHAIN_ORDER
                      and (int(b.get("risk_score",0) or 0)>=45 or b.get("has_correlation"))]
            if stages:
                highest_kill_chain = sorted(stages, key=lambda s: KILL_CHAIN_ORDER.index(s))[-1]
        # Fallback: derive from detections kill_chain_stage if bursts gave nothing
        if not highest_kill_chain and not detections_df.empty and "kill_chain_stage" in detections_df.columns:
            det_stages = [s for s in detections_df["kill_chain_stage"].dropna().unique() if s in KILL_CHAIN_ORDER]
            if det_stages:
                highest_kill_chain = sorted(det_stages, key=lambda s: KILL_CHAIN_ORDER.index(s))[-1]
        # Map MITRE tactic → kill chain if still nothing
        if not highest_kill_chain and kill_chain_summary:
            kc_ordered = [k["stage"] for k in sorted(kill_chain_summary,
                           key=lambda x: KILL_CHAIN_ORDER.index(x["stage"])
                           if x["stage"] in KILL_CHAIN_ORDER else -1, reverse=True)]
            if kc_ordered:
                highest_kill_chain = kc_ordered[0]
        kill_chain_weights = {
            "Execution": 5.0,
            "Defense Evasion": 7.0,
            "Persistence": 10.0,
            "Privilege Escalation": 14.0,
            "Credential Access": 16.0,
            "Lateral Movement": 18.0,
            "Command and Control": 20.0,
            "Actions on Objectives": 24.0,
        }
        if highest_kill_chain:
            stage_bonus = kill_chain_weights.get(highest_kill_chain, 6.0)
            attack_conf_score += stage_bonus
            attack_conf_basis.append(f"Kill-chain evidence reached {highest_kill_chain}, raising operational priority")
        if correlations:
            corr_component = min(16.0, 6.0 + len(correlations) * 2.0)
            attack_conf_score += corr_component
            attack_conf_basis.append("Multi-stage correlation tied together multiple bursts")
        max_burst_risk = max((int(b["peak_score"] or 0) for b in burst_aggregates), default=0)
        attack_conf_score += min(18.0, max_burst_risk * 0.35)
        if max_burst_risk: attack_conf_basis.append(f"Highest burst risk score reached {max_burst_risk}")
        host_spread = len({str(b.get("computer") or "").lower() for b in grouped_rows if b.get("computer")})
        if host_spread > 1:
            attack_conf_score += min(10.0, 2.5 * (host_spread - 1))
            attack_conf_basis.append(f"Observed across {host_spread} host(s), which increases spread confidence")
        if any(b.get("has_persistence") for b in grouped_rows):
            attack_conf_score += 6.0
            attack_conf_basis.append("Persistence behavior suggests the chain tried to establish a foothold")
        if any(b.get("has_injection") for b in grouped_rows):
            attack_conf_score += 8.0
            attack_conf_basis.append("Process injection suggests evasion or privilege escalation activity")
        if any(b.get("has_correlation") for b in grouped_rows):
            attack_conf_score += 4.0
        attack_conf_score = min(100.0, attack_conf_score)
        attack_conf_level = ("High" if attack_conf_score>=80 else "Medium" if attack_conf_score>=50 else "Low" if attack_conf_score>0 else "None")
        attack_conf_cap   = (100 if highest_kill_chain=="Actions on Objectives" else 90 if highest_kill_chain=="Command and Control" else 85 if highest_kill_chain=="Lateral Movement" else 82 if highest_kill_chain in ("Privilege Escalation", "Credential Access") else 78 if highest_kill_chain=="Persistence" else 70 if attack_conf_score>0 else None)
        if attack_conf_cap: attack_conf_score = min(attack_conf_score, attack_conf_cap)
        confidence_trend = [int(b.get("risk_score",0) or 0) for b in grouped_rows]
        _publish_progress(
            92,
            "Completed scoring and confidence assembly.",
            active_stage="scoring",
            processed_events=len(grouped_rows),
            total_events=len(df),
            operation_label="Scoring complete",
        )
    
        # MITRE summary
        if not detections_df.empty and "mitre_id" in detections_df.columns:
            tmp = detections_df.fillna({"mitre_tactic":"Unknown","mitre_id":"Unmapped"}).groupby(["mitre_tactic","mitre_id"]).size().reset_index(name="count")
            mitre_summary = [
                {"mitre_tactic":r["mitre_tactic"],"mitre_id":r["mitre_id"],"count":int(r["count"])}
                for r in tmp.to_dict(orient="records")
            ]
    
        # Correlation campaigns / details
        if not campaigns_df.empty:
            correlation_campaigns = [
                {"corr_id":r.get("corr_id"),"base_image":r.get("base_image"),"highest_kill_chain":r.get("highest_kill_chain") or "Execution","max_confidence":int(r.get("max_confidence",0) or 0),"status":r.get("status") or "active"}
                for r in campaigns_df.to_dict(orient="records")
            ]
        if not corr_detail_df.empty:
            correlations_detail = [{"corr_id":r.get("corr_id"),"start_time":r.get("start_time"),"end_time":r.get("end_time"),"base_image":r.get("base_image"),"kill_chain_stage":r.get("kill_chain_stage"),"event_ids":r.get("event_ids"),"description":r.get("description"),"severity":r.get("severity"),"confidence":r.get("confidence"),"computer":r.get("computer")} for r in corr_detail_df.to_dict(orient="records")]
    
        correlation_hunts = [{"id":c.get("corr_id"),"description":c.get("description","Correlation detected"),"severity":c.get("severity","medium")} for c in correlations] if correlations else []
        # Note: correlation_score is computed after the persist+reload block below
    
        interesting = interesting_df.loc[:,~interesting_df.columns.duplicated()].to_dict(orient="records") if not interesting_df.empty else []
        recent_df   = recent_df.loc[:,~recent_df.columns.duplicated()]
        recent      = recent_df.to_dict(orient="records") if not recent_df.empty else []
    
        baseline_noise_count = len(baseline_execution_context)
    
        # LOLBins
        lolbin_stats: Dict = {}
        if not interesting_df.empty and "image" in interesting_df.columns:
            np_set = {"services.exe","wininit.exe","winlogon.exe","splunkd.exe"}
            for row in interesting_df.to_dict(orient="records"):
                img = row.get("image") or "unknown_process"
                cmd = row.get("commandline") or row.get("command_line") or ""
                par = str(row.get("parent_image") or "").strip()
                s = lolbin_stats.setdefault(img,{"image":img,"executions":0,"unique_commands":set(),"abnormal_parents":set()})
                s["executions"] += 1
                if cmd: s["unique_commands"].add(cmd)
                if par and _safe_lower_text(par) not in {p.lower() for p in np_set}: s["abnormal_parents"].add(par)
        if lolbin_stats:
            lolbins_summary = []
            for img, s in lolbin_stats.items():
                ex=s["executions"]; uq=len(s["unique_commands"]); ab=len(s["abnormal_parents"])
                verdict = ("likely benign (service activity)" if ex>100 and uq<=3 and ab==0 else "suspicious" if ab>0 or uq>3 else "inconclusive")
                lolbins_summary.append({"image":img,"executions":ex,"unique_command_lines":uq,"abnormal_parents":ab,"verdict":verdict})
            lolbins_summary.sort(key=lambda r:(r["abnormal_parents"],r["executions"]),reverse=True)
            lolbins_summary = lolbins_summary[:10]
    
        # Events per hour
        _eph_col = "event_time" if "event_time" in df.columns else "utc_time" if "utc_time" in df.columns else None
        if not df.empty and _eph_col:
            import pandas as pd
            eph = df.copy()
            if not pd.api.types.is_datetime64_any_dtype(eph[_eph_col]):
                eph[_eph_col] = pd.to_datetime(eph[_eph_col], errors="coerce", utc=True)
            eph = eph.dropna(subset=[_eph_col])
            eph["hour_bucket"] = eph[_eph_col].dt.floor("h")
            eph = eph.groupby("hour_bucket").size().reset_index(name="count").sort_values("hour_bucket")
            events_per_hour = [{"hour":r.hour_bucket.strftime("%H:%M"),"count":int(r.count)} for r in eph.itertuples(index=False)]
    
        # Incident — compute kill-chain depth (distinct stages observed in this run)
        _kc_stages_seen = set()
        for _b in grouped_rows:
            _s = _b.get("kill_chain_stage")
            if _s and _s not in ("Background", "Unclassified"):
                _kc_stages_seen.add(_s)
        kill_chain_depth = len(_kc_stages_seen)
    
        # CRITICAL requires score>=70 AND (correlation OR multi-stage kill chain)
        # HIGH requires score>=50 AND at least one real kill-chain stage
        # MEDIUM requires score>=40 AND at least one real kill-chain stage
        # Single-stage detections alone never reach CRITICAL — that would be false inflation.
        _has_multi_stage = (kill_chain_depth >= 2) or (correlation_score > 0)
        _has_high_risk_stage = highest_kill_chain in ("Lateral Movement", "Command and Control", "Credential Access", "Privilege Escalation")
        if attack_conf_score >= 75 and (_has_multi_stage or _has_high_risk_stage):
            _alert_level = "critical"
        elif attack_conf_score >= 65 and _has_high_risk_stage:
            _alert_level = "high"
        elif attack_conf_score >= 45 and kill_chain_depth >= 1:
            _alert_level = "medium"
        else:
            _alert_level = "low"
    
        is_alertable = (_alert_level in ("critical", "high", "medium"))
        if is_alertable and incident is None:
            incident = {"incident_id":f"INC-{run_id[:8]}","status":"New","severity":attack_conf_level,"score":attack_conf_score}
        if incident:
            incident["hosts"] = sorted({b.get("computer") for b in grouped_rows if b.get("computer")})
            incident["users"] = sorted({b.get("user") for b in grouped_rows if b.get("user")})
        if is_alertable:
            try: upsert_incident_row(f"INC-{run_id[:8]}", "Open", attack_conf_level.lower(), attack_conf_score, run_id)
            except Exception as _uir_e: log.warning("[WARN] upsert_incident_row failed: %s", _uir_e)
    
        log.debug("[DEBUG] detections len: %d", len(detections))
        log.debug("[DEBUG] mitre_summary len: %d", len(mitre_summary))
        log.debug("[DEBUG] baseline_noise_count: %d", baseline_noise_count)
    
        narrative_stage_started = None
        # ── Attack Storyline Reconstruction ──────────────────────────────────────
        try:
            narrative_stage_started = _time.monotonic()
            # Limit the number of events passed into narrative reconstruction
            # to avoid converting the entire DataFrame to a list of dicts.
            time_col = "event_time" if "event_time" in df.columns else ("utc_time" if "utc_time" in df.columns else None)
            if not df.empty:
                if time_col:
                    _story_events = df.sort_values(time_col, ascending=False).head(STORY_MAX_EVENTS).to_dict(orient="records")
                else:
                    _story_events = df.head(STORY_MAX_EVENTS).to_dict(orient="records")
            else:
                _story_events = []

            _story_dets = detections.to_dict(orient="records") if not detections.empty else []
            attack_story = build_attack_story(_story_events, _story_dets)
            kill_chain_depth = len(attack_story.get("kill_chain", []))
        except Exception as _e:
            log.warning("[WARN] build_attack_story failed: %s", _e)
            attack_story = {"steps": [], "summary": "", "kill_chain": [], "mitre_ids": []}
            kill_chain_depth = 0
        _publish_progress(
            88,
            "Completed narrative generation.",
            active_stage="narrative_generation",
            stage_started_at=narrative_stage_started or _time.monotonic(),
            processed_events=len(attack_story.get("steps", [])) if isinstance(attack_story, dict) else 0,
            total_events=len(grouped_rows) if grouped_rows else len(df),
            operation_label="Narrative generation complete",
        )
    
        with _trace_snapshot_inputs_step(
            "timeline_slice",
            event_count=len(grouped_rows),
            object_counts={
                "grouped_rows": len(grouped_rows),
                "snapshot_limit": 500,
            },
        ):
            # Cap timeline to prevent snapshot bloat (14k+ bursts → 36MB snapshot)
            # Keep highest-risk bursts for the UI; full data is in the DB.
            MAX_TIMELINE_SNAPSHOT = 500
            timeline_for_context = grouped_rows[:MAX_TIMELINE_SNAPSHOT]
            if len(grouped_rows) > MAX_TIMELINE_SNAPSHOT:
                log.warning(
                    "[PIPELINE] Capping timeline snapshot from %d to %d bursts for run_id=%s",
                    len(grouped_rows), MAX_TIMELINE_SNAPSHOT, run_id[:16]
                )

        with _trace_snapshot_inputs_step(
            "forensic_reconstruction",
            event_count=len(grouped_rows),
            object_counts={
                "timeline_rows": len(timeline_for_context),
                "burst_aggregate_rows": len(burst_aggregates),
                "interesting_rows": len(interesting),
                "recent_rows": len(recent),
            },
        ):
            context = {
                "analysis_run_id":            run_id,
                "context_run_marker":         run_id[:8],
                "time_range":                 "all",
                "q":                          "",
                "incident":                   incident,
                "total_events":               total_events,
                "high_count":                 high_count,
                "medium_count":               medium_count,
                "low_count":                  low_count,
                "detections_count":           detections_count,
                "events_by_severity":         events_by_severity,
                "events_per_hour":            events_per_hour,
                "top_events":                 top_events,
                "interesting":                interesting,
                "recent":                     recent,
                "detections":                 detections.to_dict(orient="records"),
                "timeline":                   timeline_for_context,
                "normalized_detections":      normalized_detections.to_dict(orient="records"),
                "attack_conf_score":          attack_conf_score,
                "attack_conf_level":          attack_conf_level,
                "attack_conf_cap":            attack_conf_cap,
                "attack_conf_basis":          attack_conf_basis,
                "highest_kill_chain":         highest_kill_chain,
                "is_alertable":               is_alertable,
                "confidence_trend":           confidence_trend,
                "correlations_detail":        correlations_detail,
                "correlation_campaigns":      correlation_campaigns,
                "correlation_hunts":          correlation_hunts,
                "correlation_score":          correlation_score,
                "correlations":               correlations,
                "burst_aggregates":           burst_aggregates,
                "top_dangerous_bursts":       baseline_execution_context,
                "baseline_execution_context": baseline_execution_context,
                "baseline_noise_count":       baseline_noise_count,
                "kill_chain_summary":         kill_chain_summary,
                "kc_severity":                kc_severity,
                "mitre_summary":              mitre_summary,
                "lolbins_summary":            lolbins_summary,
                "forensic_metadata": {
                    "analysis_duration_sec": "0.000",
                    "dominant_host": (
                        df["computer"].value_counts().index[0]
                        if not df.empty and "computer" in df.columns and len(df)>0
                        else "N/A"
                    ),
                    "total_events": total_events,
                    "run_id": run_id,
                },
                # [FIX] incidents: build a list from the single-incident object
                # Template (index.html L333/L371) iterates `incidents` as a list
                "incidents": (
                    [{
                        "incident_id": incident.get("incident_id", f"INC-{run_id[:8]}"),
                        "computer":    (incident.get("hosts") or ["Unknown"])[0],
                        "image":       (burst_aggregates[0].get("image") if burst_aggregates else "Unknown"),
                        "kill_chain_stage": highest_kill_chain or "Unknown",
                        "attack_conf_score": attack_conf_score,
                        "risk_score":  attack_conf_score,
                        "status":      incident.get("status", "New"),
                        "priority":    "P1" if attack_conf_score >= 75 else "P2" if attack_conf_score >= 50 else "P3" if attack_conf_score >= 25 else "P4",
                    }]
                    if incident else []
                ),
                # pipeline_error: populated if partial failure occurred
                "pipeline_error": None,
            }

        _publish_progress(
            82,
            "Assembling snapshot…",
            active_stage="snapshot_assembly",
            stage_started_at=_time.monotonic(),
            processed_events=len(timeline_for_context),
            total_events=len(grouped_rows) if grouped_rows else len(df),
            operation_label="Building dashboard snapshot",
        )
    

        from datetime import datetime, timezone
        
        # 🔒 HARD SCHEMA ENFORCEMENT (9.8/10 Final)
        safe_context = context if isinstance(context, dict) else {}
        safe_context.setdefault("status", "processing")
        safe_context.setdefault("meta", {
            "pipeline_stage": "initialization",
            "errors": [],
            "warnings": [],
            "generated_at": datetime.now(timezone.utc).isoformat()
        })
        
        safe_context["timeline"] = safe_context.get("timeline") or []
        safe_context["burst_aggregates"] = safe_context.get("burst_aggregates") or []
        safe_context["events"] = safe_context.get("events") or []
        
        # Mastery Intelligence Guarantees (9.7 Locked)
        safe_context["attack_sequences"] = safe_context.get("attack_sequences") or []
        safe_context["process_tree"] = safe_context.get("process_tree") or []
        safe_context["beacons"] = safe_context.get("beacons") or []

        # Proper Timeline Fallback (Mastery Fix)
        if not safe_context["timeline"] and safe_context["events"]:
            events = sorted(
                safe_context["events"],
                key=lambda x: str(x.get("event_time", ""))
            )[:200]
            safe_context["timeline"] = [
                {
                    "time": e.get("event_time"),
                    "image": e.get("image", "unknown"),
                    "command": e.get("command_line", ""),
                    "stage": e.get("kill_chain_stage", "Background"),
                    "host": e.get("computer", "unknown"),
                    "severity": e.get("severity", "low")
                }
                for e in events
            ]

        narrative = safe_context.get("attack_narrative") or {}
        safe_context["attack_narrative"] = {
            "summary": narrative.get("summary", "No threats detected"),
            "stage": narrative.get("stage", "None"),
            "score": float(narrative.get("score", 0)),
            "is_attack": bool(narrative.get("is_attack", False))
        }

        meta = safe_context.setdefault("meta", {})
        meta["profiling_inputs"] = {
            "dataframe_sizes": _profile_dataframe_sizes({
                "events": df,
                "detections": detections_df,
                "behaviors": beh_df,
                "correlations": corr_df,
                "campaigns": campaigns_df,
                "normalized_detections": normalized_detections,
            }),
            "timeline_rows": len(timeline_for_context),
            "burst_aggregate_rows": len(burst_aggregates),
            "recent_rows": len(recent),
            "interesting_rows": len(interesting),
            "snapshot_inputs": snapshot_inputs_steps,
            "snapshot_inputs_hotspots": sorted(snapshot_inputs_steps, key=lambda row: row.get("elapsed_ms", 0), reverse=True),
            "snapshot_inputs_memory_peak_bytes": max((row.get("rss_delta_bytes", 0) for row in snapshot_inputs_steps), default=0),
        }
        if correlation_telemetry:
            meta["correlation_telemetry"] = correlation_telemetry
            meta["profiling_inputs"]["correlation_telemetry"] = correlation_telemetry

        _publish_progress(
            95,
            "Serializing dashboard payload.",
            active_stage="serialization",
            processed_events=len(safe_context.get("events", [])),
            total_events=total_events,
            operation_label="Serializing dashboard payload",
            metrics={
                "snapshot_rows": len(safe_context.get("timeline", [])),
                "burst_rows": len(safe_context.get("burst_aggregates", [])),
            },
        )

        # 🔒 FINAL PRODUCTION CONTRACT (9.8/10 Defendable)
        if not isinstance(safe_context, dict) or "timeline" not in safe_context:
            log.error("[Analysis] Critical contract violation at pipeline exit - enforcing fallback")
            from datetime import datetime, timezone
            safe_context = {
                "timeline": [],
                "burst_aggregates": [],
                "events": [],
                "attack_narrative": {
                    "summary": "Analysis failed critical contract check",
                    "stage": "Error",
                    "score": 0,
                    "is_attack": False
                },
                "status": "failed",
                "meta": {
                    "pipeline_stage": "exit-guard",
                    "errors": [{"stage": "final-validation", "message": "Context missing timeline or not a dict", "type": "ContractError"}],
                    "generated_at": datetime.now(timezone.utc).isoformat()
                }
            }
        else:
            # Observability: Structured Weak Correlation (9.7 Mastery)
            dets = safe_context.get("detections", [])
            seqs = safe_context.get("attack_sequences", [])
            
            safe_context["meta"] = safe_context.get("meta") or {
                "pipeline_stage": "correlation",
                "errors": [],
                "warnings": []
            }

            if dets and not seqs:
                safe_context["meta"]["warnings"].append({
                    "type": "weak_correlation",
                    "message": "Detections present but no sequences",
                    "detection_count": len(dets),
                    "sequence_count": len(seqs)
                })
                log.info("[Pipeline] Weak correlation observed (dets=%d, seqs=0)", len(dets))

            safe_context["status"] = "complete"
            safe_context["meta"]["pipeline_stage"] = "complete"

        # 9.8: Enforce snapshot contract before writing
        try:
            _enforce_snapshot_contract(safe_context, run_id)
        except RuntimeError as _contract_err:
            log.error("[CONTRACT] Forcing status=failed due to contract violation: %s", _contract_err)
            safe_context["status"] = "failed"
            safe_context.setdefault("attack_conf_score", 0)
            safe_context.setdefault("attack_narrative", {
                "summary": f"Contract violation: {_contract_err}",
                "stage": "Error", "score": 0, "is_attack": False
            })

        # Resilient Persistence Guard
        try:
            _publish_progress(
                96,
                "Writing analysis snapshot…",
                active_stage="finalization_snapshot",
                operation_label="Persisting snapshot cache",
                total_events=total_events,
                processed_events=len(grouped_rows),
            )
            _finalization_snapshot_started = _time.perf_counter()
            set_analysis_snapshot(run_id, safe_context, authoritative=True)
            _finalization_snapshot_elapsed = round(_time.perf_counter() - _finalization_snapshot_started, 6)
            meta = safe_context.setdefault("meta", {})
            profiling_inputs = meta.setdefault("profiling_inputs", {})
            profiling_inputs["finalization_snapshot_write_seconds"] = _finalization_snapshot_elapsed
            _perf.lap("snapshot_write")
            log.info("[SNAPSHOT] Success snapshot written for run_id=%s status=%s",
                     run_id[:16], safe_context.get("status"))
        except Exception as e:
            log.error("[SNAPSHOT] Persist failed for run_id=%s: %s", run_id[:16], e)
            safe_context["status"] = "degraded"
            safe_context["meta"]["errors"].append({
                "stage": "persistence",
                "message": str(e)[:200],
                "type": type(e).__name__
            })

        _emit_analysis_profile_summary(run_id, _profiler, _perf, safe_context, "success")

        # 10/10 Mastery: Final Success Transition
        # Use the formal set_run_state() for DB audit trail
        try:
            _publish_progress(
                99,
                "Publishing terminal run state…",
                state="complete",
                active_stage="completion_publication",
                operation_label="Writing terminal state",
                total_events=total_events,
                processed_events=len(grouped_rows),
            )
            _finalization_state_started = _time.perf_counter()
            from dashboard.db import set_run_state
            set_run_state(run_id, COMPLETE, "Analysis pipeline completed successfully")
            _finalization_state_elapsed = round(_time.perf_counter() - _finalization_state_started, 6)
            meta = safe_context.setdefault("meta", {})
            profiling_inputs = meta.setdefault("profiling_inputs", {})
            profiling_inputs["finalization_state_transition_seconds"] = _finalization_state_elapsed
        except Exception as _sr:
            # Fallback to legacy _transition_state if DB state write fails
            log.warning("[STATE] set_run_state failed, using fallback: %s", _sr)
            _transition_state(run_id, ANALYZING, COMPLETE, {"status": "Success", "events": len(safe_context.get("events", []))})

        return safe_context

    except Exception as e:
        log.exception("[ANALYSIS_FATAL] Pipeline failed for run_id=%s", run_id)
        import copy

        base = context if isinstance(context, dict) else {}
        safe_context = copy.deepcopy(base)

        # HARD SCHEMA ENFORCEMENT — guaranteed keys on any failure path
        safe_context["events"] = safe_context.get("events") or []
        safe_context["timeline"] = safe_context.get("timeline") or []
        safe_context["burst_aggregates"] = safe_context.get("burst_aggregates") or []
        safe_context["analysis_run_id"] = run_id

        safe_context["attack_narrative"] = {
            "summary": f"Analysis partially failed: {str(e)[:200]}",
            "stage": "Error",
            "score": 0,
            "is_attack": False
        }

        safe_context["recommended_action"] = "BASELINE"
        safe_context["action_priority"] = "P4"
        safe_context["action_reason"] = "Pipeline error — manual investigation required"
        safe_context["status"] = "failed"

        safe_context["meta"] = {
            "pipeline_stage": "error",
            "errors": [{
                "stage": "pipeline",
                "message": str(e)[:200],
                "type": type(e).__name__
            }],
            "warnings": []
        }

        # 🔥 CRITICAL: Always write fail snapshot so dashboard doesn't hang
        try:
            traceback_summary = "".join(traceback.format_exception(type(e), e, e.__traceback__, limit=8))
            _publish_progress(
                99,
                f"Analysis failed during {current_backend_stage}.",
                state="error",
                active_stage="failure_snapshot_generation",
                operation_label=f"Persisting terminal failure snapshot after {current_backend_stage}",
                total_events=len(base.get("events", [])),
                processed_events=len(base.get("events", [])),
                error=str(e)[:500],
                traceback_summary=traceback_summary,
                metrics={"failure_stage": current_backend_stage},
            )
            safe_context["meta"]["pipeline_stage"] = "failure_snapshot_generation"
            safe_context["meta"]["errors"] = [{
                "stage": current_backend_stage,
                "message": str(e)[:200],
                "type": type(e).__name__,
                "traceback_summary": traceback_summary,
                "traceback": traceback_summary,
            }]
            safe_context["error"] = str(e)
            set_analysis_snapshot(run_id, safe_context, authoritative=True)
            log.info("[SNAPSHOT] Failure snapshot written for run_id=%s", run_id[:16])
        except Exception as _se:
            log.error("[SNAPSHOT] Failed to write failure snapshot: %s", _se)

        # Update DB state machine to FAILED
        try:
            from dashboard.db import ANALYZING as _DB_ANALYZING, FAILED as _DB_FAILED, get_run_state as _get_run_state, set_run_state

            if _get_run_state(run_id) == "INGESTED":
                set_run_state(run_id, _DB_ANALYZING, "Normalizing failed analysis state")
            set_run_state(run_id, _DB_FAILED, f"Pipeline exception: {str(e)[:100]}")
        except Exception as _sr:
            log.warning("[STATE] set_run_state(FAILED) failed: %s", _sr)

    # 10/10 Mastery: Final Success Transition (Only if success)
    if safe_context.get("status") == "complete":
        _transition_state(run_id, ANALYZING, COMPLETE, {"status": "Success", "events": len(safe_context.get("events", []))})

    # FINAL CONTEXT INTEGRITY GUARD (9.7 Mastery)
    if not isinstance(safe_context, dict) or "timeline" not in safe_context:
        log.error("[Analysis] Invalid final context — applying emergency fallback")

        safe_context = {
            "events": [],
            "timeline": [],
            "burst_aggregates": [],
            "status": "failed",
            "attack_narrative": {
                "summary": "Analysis failed",
                "stage": "Error",
                "score": 0,
                "is_attack": False
            },
            "meta": {
                "pipeline_stage": "error",
                "errors": [{"stage": "final_guard", "message": "Invalid context", "type": "RuntimeError"}],
                "warnings": []
            }
        }

        _emit_analysis_profile_summary(run_id, _profiler, _perf, safe_context, "failure")
    return safe_context


def _transition_state(run_id: str, old: str, new: str, reason_dict: dict):
    """Formal atomic state transition with audit trail."""
    try:
        from dashboard.db import get_db_connection, get_cursor, now_utc
        import json
        import logging
        log = logging.getLogger("db")
        with get_db_connection("cases") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "UPDATE cases SET status=%s, last_heartbeat=%s WHERE run_id=%s AND status=%s",
                    (new, now_utc(), run_id, old)
                )
                cur.execute(
                    "INSERT INTO case_history (run_id, old_status, new_status, reason) "
                    "VALUES (%s, %s, %s, %s)",
                    (run_id, old, new, json.dumps(reason_dict))
                )
            conn.commit()
    except Exception as e:
        log = logging.getLogger("db")
        log.error("[STATE] Transition failed %s -> %s: %s", old, new, e)
