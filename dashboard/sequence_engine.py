"""
sequence_engine.py — SentinelTrace v3 Sequence Detection Engine
===============================================================
PROBLEM 1 FIX: Event-centric → Attack-centric detection

Instead of detecting each event in isolation, this engine tracks
ATTACK CHAINS: ordered sequences of process launches that match
known attacker playbooks.

Examples it catches:
  winword.exe → powershell.exe → cmd.exe → network  (phishing macro)
  mshta.exe → powershell.exe → regsvr32.exe         (fileless malware)
  cmd.exe → schtasks.exe + reg.exe                  (persistence)
  lsass access → mimikatz keywords                  (credential dump)

Architecture:
  - SequencePattern: defines a multi-hop attack chain
  - SequenceTracker: stateful per-host tracker (sliding window)
  - SequenceEngine: batch-processes a DataFrame of events
"""

from __future__ import annotations

import re
import hashlib
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Kill chain ordering
# ---------------------------------------------------------------------------

KILL_CHAIN_ORDER = [
    "Background", "Delivery", "Execution", "Defense Evasion",
    "Persistence", "Privilege Escalation", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Actions on Objectives",
]


# ---------------------------------------------------------------------------
# Sequence Pattern Definition
# ---------------------------------------------------------------------------

@dataclass
class SequenceStep:
    """One hop in an attack chain."""
    image_contains: Optional[str] = None        # partial image name match
    image_any: Optional[List[str]] = None        # OR list of exact names
    cmd_contains: Optional[str] = None           # command line substring
    event_id: Optional[int] = None               # Sysmon event ID filter
    max_gap_seconds: int = 3600                  # max time to next step
    max_skip_steps: int = 1                      # max intermediate events to ignore (Audit v2 Final)


@dataclass
class SequencePattern:
    """A named multi-hop attack chain pattern."""
    pattern_id: str
    name: str
    description: str
    steps: List[SequenceStep]
    mitre_id: str
    mitre_tactic: str
    kill_chain_stage: str
    base_confidence: int = 80                    # confidence when fully matched
    min_steps_to_fire: int = 0                   # 0 = must complete all steps


# ---------------------------------------------------------------------------
# Built-in Attack Patterns
# ---------------------------------------------------------------------------

BUILTIN_PATTERNS: List[SequencePattern] = [

    # ── Phishing macro execution chain ──────────────────────────────────────
    SequencePattern(
        pattern_id="SEQ-001",
        name="Office macro → PowerShell execution",
        description="Office application spawns PowerShell — classic phishing macro payload",
        mitre_id="T1566.001",
        mitre_tactic="Initial Access",
        kill_chain_stage="Execution",
        base_confidence=90,
        steps=[
            SequenceStep(image_any=["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"],
                         event_id=1, max_gap_seconds=300),
            SequenceStep(image_contains="powershell", event_id=1, max_gap_seconds=300),
        ],
    ),

    # ── Office → PowerShell → network (full phishing chain) ─────────────────
    SequencePattern(
        pattern_id="SEQ-002",
        name="Office macro → PowerShell → C2 download",
        description="Office spawns PowerShell which makes outbound network connection — staged payload delivery",
        mitre_id="T1566.001",
        mitre_tactic="Initial Access",
        kill_chain_stage="Command and Control",
        base_confidence=95,
        steps=[
            SequenceStep(image_any=["winword.exe", "excel.exe", "outlook.exe"], event_id=1),
            SequenceStep(image_contains="powershell", event_id=1, max_gap_seconds=600),
            SequenceStep(image_contains="powershell", event_id=3, max_gap_seconds=120),
        ],
    ),

    # ── Encoded PowerShell → file drop ──────────────────────────────────────
    SequencePattern(
        pattern_id="SEQ-003",
        name="Encoded PowerShell → file drop",
        description="PowerShell with encoded command followed by file creation — dropper activity",
        mitre_id="T1059.001",
        mitre_tactic="Execution",
        kill_chain_stage="Execution",
        base_confidence=85,
        steps=[
            SequenceStep(image_contains="powershell", cmd_contains="-enc", event_id=1),
            SequenceStep(image_contains="powershell", event_id=11, max_gap_seconds=300),
        ],
    ),

    # ── PowerShell → cmd → network (lateral movement) ───────────────────────
    SequencePattern(
        pattern_id="SEQ-004",
        name="PowerShell → cmd.exe → network connection",
        description="PowerShell spawns cmd.exe which makes network connection — lateral movement pattern",
        mitre_id="T1021",
        mitre_tactic="Lateral Movement",
        kill_chain_stage="Lateral Movement",
        base_confidence=80,
        steps=[
            SequenceStep(image_contains="powershell", event_id=1),
            SequenceStep(image_any=["cmd.exe"], event_id=1, max_gap_seconds=120),
            SequenceStep(image_any=["cmd.exe"], event_id=3, max_gap_seconds=60),
        ],
    ),

    # ── Credential dumping chain ─────────────────────────────────────────────
    SequencePattern(
        pattern_id="SEQ-005",
        name="LSASS access → credential tool execution",
        description="Process opens LSASS followed by credential dumping tool — active credential theft",
        mitre_id="T1003.001",
        mitre_tactic="Credential Access",
        kill_chain_stage="Credential Access",
        base_confidence=95,
        steps=[
            SequenceStep(event_id=10, max_gap_seconds=300),   # ProcessAccess (LSASS)
            SequenceStep(cmd_contains="sekurlsa", event_id=1, max_gap_seconds=300),
        ],
    ),

    # ── Registry persistence after execution ────────────────────────────────
    SequencePattern(
        pattern_id="SEQ-006",
        name="Execution → registry Run key persistence",
        description="Process execution followed by Run key modification — establishing persistence",
        mitre_id="T1547.001",
        mitre_tactic="Persistence",
        kill_chain_stage="Persistence",
        base_confidence=85,
        steps=[
            SequenceStep(image_any=["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"],
                         event_id=1),
            SequenceStep(event_id=13, max_gap_seconds=600),   # Registry value set
        ],
    ),

    # ── Scheduled task persistence ───────────────────────────────────────────
    SequencePattern(
        pattern_id="SEQ-007",
        name="Shell → scheduled task creation",
        description="Shell spawns schtasks.exe with /create — scheduled task persistence",
        mitre_id="T1053.005",
        mitre_tactic="Persistence",
        kill_chain_stage="Persistence",
        base_confidence=82,
        steps=[
            SequenceStep(image_any=["powershell.exe", "cmd.exe"], event_id=1),
            SequenceStep(image_contains="schtasks", cmd_contains="/create", event_id=1,
                         max_gap_seconds=120),
        ],
    ),

    # ── Shadow copy deletion (ransomware indicator) ───────────────────────────
    SequencePattern(
        pattern_id="SEQ-008",
        name="Shell → shadow copy deletion",
        description="Shell executes vssadmin/wmic to delete shadow copies — pre-ransomware indicator",
        mitre_id="T1490",
        mitre_tactic="Impact",
        kill_chain_stage="Actions on Objectives",
        base_confidence=95,
        steps=[
            SequenceStep(image_any=["cmd.exe", "powershell.exe"], event_id=1),
            SequenceStep(cmd_contains="shadowcopy", event_id=1, max_gap_seconds=300),
        ],
    ),

    # ── Firewall disable → C2 ────────────────────────────────────────────────
    SequencePattern(
        pattern_id="SEQ-009",
        name="Firewall disabled → outbound connection",
        description="netsh disables firewall followed by outbound network — clearing path for C2",
        mitre_id="T1562.004",
        mitre_tactic="Defense Evasion",
        kill_chain_stage="Command and Control",
        base_confidence=90,
        steps=[
            SequenceStep(image_contains="netsh", cmd_contains="firewall", event_id=1),
            SequenceStep(event_id=3, max_gap_seconds=300),
        ],
    ),

    # ── MSHTA → network → file drop (HTA dropper) ────────────────────────────
    SequencePattern(
        pattern_id="SEQ-010",
        name="MSHTA → network → file drop",
        description="MSHTA makes network connection then drops file — HTA-based dropper chain",
        mitre_id="T1218.005",
        mitre_tactic="Defense Evasion",
        kill_chain_stage="Execution",
        base_confidence=92,
        steps=[
            SequenceStep(image_contains="mshta", event_id=1),
            SequenceStep(image_contains="mshta", event_id=3, max_gap_seconds=120),
            SequenceStep(event_id=11, max_gap_seconds=120),
        ],
    ),

    # ── Discovery → lateral movement ─────────────────────────────────────────
    SequencePattern(
        pattern_id="SEQ-011",
        name="Network enumeration → remote execution",
        description="net.exe enumeration followed by PsExec/WMI — pre-lateral movement reconnaissance",
        mitre_id="T1018",
        mitre_tactic="Discovery",
        kill_chain_stage="Lateral Movement",
        base_confidence=80,
        steps=[
            SequenceStep(image_any=["net.exe", "net1.exe", "nltest.exe"], event_id=1),
            SequenceStep(image_any=["psexec.exe", "psexec64.exe", "wmic.exe"],
                         event_id=1, max_gap_seconds=1800),
        ],
    ),

    # ── Certutil download → execution ────────────────────────────────────────
    SequencePattern(
        pattern_id="SEQ-012",
        name="Certutil download → new process execution",
        description="Certutil downloads file, then new process spawns — LOLBin staging and execution",
        mitre_id="T1105",
        mitre_tactic="Command and Control",
        kill_chain_stage="Execution",
        base_confidence=88,
        steps=[
            SequenceStep(image_contains="certutil", cmd_contains="-urlcache", event_id=1),
            SequenceStep(event_id=1, max_gap_seconds=300),
        ],
    ),
]


def normalize_command(cmd: str) -> str:
    """SOC-grade command line normalization with evasion resilience (Base64/backticks)."""
    if not cmd: return ""
    c = cmd.lower().strip()
    
    # 1. Remove PowerShell backtick obfuscation: P`o`w`e`r -> power
    c = c.replace("`", "")
    
    # 2. Handle Base64 space splitting: "-enc Z m 9 v" -> "-enc Zm9v"
    # Look for -enc, -e, -encodedcommand followed by spaces/chars
    if any(x in c for x in ["-enc ", "-e ", "-encoded"]):
        # Simple heuristic: if we see lots of spaces in a long string after -enc
        match = re.search(r"(-enc|-e|-encoded\w+)\s+([a-z0-9+/= ]{10,})", c)
        if match:
            flag, payload = match.groups()
            normalized_payload = payload.replace(" ", "")
            c = c.replace(payload, normalized_payload)

    # 3. Strip hex payloads / random strings ([a-f0-9]{20,})
    c = re.sub(r"[a-f0-9]{20,}", "[HEX]", c)
    
    # 4. Normalize whitespace
    c = " ".join(c.split())
    
    # Trace for debug
    # print(f"[NORM] {cmd[:30]}... -> {c[:30]}...")
    
    # 5. Truncate for stable comparison
    return c[:100]


# ---------------------------------------------------------------------------
# Step matching helper
# ---------------------------------------------------------------------------

def _step_matches(event: Dict[str, Any], step: SequenceStep) -> bool:
    """Return True if a single event dict satisfies a sequence step."""
    # Event ID filter
    if step.event_id is not None:
        try:
            if int(event.get("event_id") or 0) != step.event_id:
                return False
        except (TypeError, ValueError):
            return False

    img = str(event.get("image") or "").lower()
    cmd = str(event.get("command_line") or event.get("commandline") or "").lower()

    if step.image_contains and step.image_contains.lower() not in img:
        return False

    if step.image_any:
        if not any(x.lower() in img for x in step.image_any):
            return False

    if step.cmd_contains and step.cmd_contains.lower() not in cmd:
        return False

    return True


# ---------------------------------------------------------------------------
# Per-host sequence tracker
# ---------------------------------------------------------------------------

class _ChainState:
    """One in-progress chain match attempt."""
    __slots__ = ("step_idx", "last_time", "matched_evs", "skip_count")

    def __init__(self, step_idx: int, last_time: datetime, matched_evs: list, skip_count: int = 0):
        self.step_idx   = step_idx
        self.last_time  = last_time
        self.matched_evs = matched_evs
        self.skip_count  = skip_count # Tracks skipped events since last step


class _HostTracker:
    """
    Multi-chain state tracker per (host, pattern).

    FIXED: previously only one active chain per pattern per host.
    Now supports MULTIPLE concurrent in-progress chains per pattern.
    This prevents state overwrite when:
      - attacker runs: ps → cmd → ps → cmd
      - parallel attack paths run simultaneously on the same host
      - chain restarts before previous chain completes

    State: {pattern_id → List[_ChainState]}
    Each pattern can have up to MAX_CHAINS_PER_PATTERN concurrent chains.
    """

    MAX_CHAINS_PER_PATTERN = 8   # max concurrent in-progress chains per pattern

    def __init__(self, window_seconds: int = 3600):
        # {pattern_id → List[_ChainState]}
        self._state: Dict[str, List[_ChainState]] = defaultdict(list)
        self._window = window_seconds

    def _prune_timed_out(
        self, chains: List[_ChainState], pat: SequencePattern, now: datetime
    ) -> List[_ChainState]:
        """Remove chains whose last-matched step has exceeded its time window with 5s tolerance."""
        live = []
        WINDOW_TOLERANCE = 5  # seconds
        for chain in chains:
            if chain.step_idx < len(pat.steps):
                step       = pat.steps[chain.step_idx]
                max_gap    = step.max_gap_seconds + WINDOW_TOLERANCE
                elapsed    = (now - chain.last_time).total_seconds()
                if elapsed <= max_gap:
                    live.append(chain)
        return live

    def process_event(
        self,
        event: Dict[str, Any],
        patterns: List[SequencePattern],
        now: datetime,
    ) -> List[Dict[str, Any]]:
        """
        Feed one event.  Returns list of completed sequence detections.

        Algorithm per pattern:
          1. Prune timed-out chains
          2. Advance any chain whose NEXT step matches this event
          3. If any chain completed → emit detection, remove it
          4. If step 0 of this pattern matches → start a NEW chain
             (allows parallel chains for the same pattern)
        """
        completed: List[Dict[str, Any]] = []

        for pat in patterns:
            pid = pat.pattern_id

            # Step 1: prune timed-out chains
            self._state[pid] = self._prune_timed_out(self._state[pid], pat, now)

            still_active: List[_ChainState] = []
            newly_completed: List[_ChainState] = []

            # Step 2 + 3: try to advance each existing chain
            for chain in self._state[pid]:
                current_step = pat.steps[chain.step_idx]
                
                # Check max_skip_steps constraint (Audit v2 Final)
                if chain.skip_count > current_step.max_skip_steps:
                    # This chain has skipped too many events, let it time out or be pruned
                    continue

                if _step_matches(event, current_step):
                    new_idx  = chain.step_idx + 1
                    new_evs  = chain.matched_evs + [event]
                    if new_idx >= 2:
                        # Partial or complete match (Audit v2 Final)
                        completed.append(_build_sequence_detection(pat, new_evs))

                    if new_idx >= len(pat.steps):
                        # Chain complete, don't keep tracking this specific instance
                        pass
                    else:
                        still_active.append(_ChainState(new_idx, now, new_evs, skip_count=0))
                else:
                    # No progress match at this step, increment skip_count and keep alive (Audit v2 Final)
                    still_active.append(_ChainState(chain.step_idx, chain.last_time, chain.matched_evs, chain.skip_count + 1))

            # Step 4: check if step 0 matches → start fresh chain
            # This runs regardless of whether we advanced existing chains,
            # allowing parallel tracking of the same pattern from a new anchor.
            if _step_matches(event, pat.steps[0]):
                if len(pat.steps) == 1:
                    # Single-step pattern — fires immediately
                    completed.append(
                        _build_sequence_detection(pat, [event])
                    )
                else:
                    new_chain = _ChainState(1, now, [event], skip_count=0)
                    still_active.append(new_chain)

            # --- Adaptive Memory Limit (Audit v2 Final) ---
            # host_event_rate isn't explicitly passed, we use the backlog length as a proxy
            # or we assume a high-load system if many chains are active.
            host_event_rate = len(still_active) * 100 # Rough heuristic for adaptive scaling
            max_chains = min(50, max(8, host_event_rate // 200))
            if len(still_active) > max_chains:
                # Keep most-advanced chains (highest step_idx)
                still_active.sort(key=lambda c: c.step_idx, reverse=True)
                still_active = still_active[:max_chains]

            self._state[pid] = still_active

        return completed


def _build_sequence_detection(
    pat: SequencePattern,
    matched_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a detection dict from a completed sequence match."""
    first_ev = matched_events[0]
    last_ev  = matched_events[-1]
    chain_str = " → ".join(
        str(e.get("image") or "").split("\\")[-1] or str(e.get("event_id"))
        for e in matched_events
    )
    return {
        "detection_id":     f"SEQ-DET-{uuid.uuid4().hex[:10]}",
        "pattern_id":       pat.pattern_id,
        "rule_id":          pat.pattern_id,
        "rule_name":        pat.name,
        "description":      f"{pat.description} | Chain: {chain_str}",
        "mitre_id":         pat.mitre_id,
        "mitre_tactic":     pat.mitre_tactic,
        "kill_chain_stage": pat.kill_chain_stage,
        "confidence_score": int(pat.base_confidence * (len(matched_events) / len(pat.steps))),
        "severity":         _confidence_to_severity(pat.base_confidence),
        "chain_depth":      len(matched_events),
        "chain_str":        chain_str,
        "image":            str(first_ev.get("image") or ""),
        "parent_image":     str(first_ev.get("parent_image") or "").lower(),
        "computer":         str(first_ev.get("computer") or ""),
        "utc_time":         first_ev.get("event_time") or first_ev.get("utc_time"),
        "event_time":       first_ev.get("event_time") or first_ev.get("utc_time"),
        "end_time":         last_ev.get("event_time") or last_ev.get("utc_time"),
        "matched_event_ids": [str(e.get("event_id")) for e in matched_events],
        "run_id":           str(first_ev.get("run_id") or ""),
        "detection_source": "sequence",
        "is_sequence":      True,
    }


def _confidence_to_severity(conf: int) -> str:
    if conf >= 90: return "critical"
    if conf >= 75: return "high"
    if conf >= 55: return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Public SequenceEngine
# ---------------------------------------------------------------------------

class SequenceEngine:
    """
    Stateful sequence detection engine.

    Usage:
        engine = SequenceEngine()
        detections = engine.process_dataframe(events_df)

    Returns a list of sequence detection dicts, one per completed chain match.
    Each detection has the same schema as a YAML-rule detection so it can be
    inserted directly into the detections table and displayed in the dashboard.
    """

    def __init__(
        self,
        patterns: Optional[List[SequencePattern]] = None,
        window_seconds: int = 3600,
    ):
        self.patterns = patterns if patterns is not None else BUILTIN_PATTERNS
        self.window   = window_seconds
        # Per-host trackers:  host → _HostTracker
        self._trackers: Dict[str, _HostTracker] = defaultdict(
            lambda: _HostTracker(window_seconds)
        )
        # 🔥 Memory-capped fired cache (prevents duplicate firing)
        # Key: (pattern_id, computer, first_event_ts, last_event_ts)
        self._fired_sequences: Dict[Tuple[str, str, float, float], float] = {}
        self._max_fired_cache = 20000

    def _evict_fired_cache(self) -> None:
        """Stable-sort eviction: drop oldest 25% of entries."""
        if len(self._fired_sequences) < self._max_fired_cache:
            return
        
        # 🔥 Stable sort (time + key) as requested
        items = sorted(
            self._fired_sequences.items(),
            key=lambda x: (x[1], x[0])
        )
        # Drop 25%
        drop_count = self._max_fired_cache // 4
        to_drop = items[:drop_count]
        for key, _ in to_drop:
            del self._fired_sequences[key]

    def process_dataframe(self, df: 'pd.DataFrame') -> List[Dict[str, Any]]:
        """
        Process a sorted DataFrame of events and return all sequence detections.
        Events MUST be sorted by event_time ascending for correct ordering.
        """
        import pandas as pd
        if df.empty:
            return []

        detections: List[Dict[str, Any]] = []

        # Ensure sorted
        time_col = "event_time" if "event_time" in df.columns else "utc_time"
        if time_col in df.columns:
            df = df.sort_values(time_col, na_position="last")

        for _, row in df.iterrows():
            event = row.to_dict()
            # Coerce NaN → None for safety
            event = {k: (None if (isinstance(v, float) and v != v) else v)
                     for k, v in event.items()}
            
            # --- Issue 6: Normalize command line before tracking ---
            if "command_line" in event:
                event["command_line"] = normalize_command(event["command_line"])
            elif "commandline" in event:
                event["commandline"] = normalize_command(event["commandline"])

            computer = str(event.get("computer") or "unknown_host")

            # Parse timestamp
            ts_raw = event.get("event_time") or event.get("utc_time")
            try:
                if isinstance(ts_raw, datetime):
                    now = ts_raw.replace(tzinfo=timezone.utc) if ts_raw.tzinfo is None else ts_raw
                elif ts_raw is not None:
                    now = pd.to_datetime(ts_raw, errors="coerce", utc=True).to_pydatetime()
                else:
                    now = datetime.now(tz=timezone.utc)
            except Exception:
                now = datetime.now(tz=timezone.utc)

            tracker   = self._trackers[computer]
            completed = tracker.process_event(event, self.patterns, now)
            
            # 🔥 Deduplicate against fired cache
            for det in completed:
                # Key: (pattern, host, start_ts, end_ts)
                import pandas as pd
                start_ts = pd.to_datetime(det["event_time"], utc=True).timestamp()
                end_ts   = pd.to_datetime(det["end_time"], utc=True).timestamp()
                f_key = (det["pattern_id"], computer, start_ts, end_ts)
                
                if f_key not in self._fired_sequences:
                    self._evict_fired_cache()
                    self._fired_sequences[f_key] = now.timestamp()
                    detections.append(det)

        # Performance cap: excessive sequences → O(N²) downstream processing
        MAX_SEQUENCES = 1000
        if len(detections) > MAX_SEQUENCES:
            import logging as _logging
            _logging.getLogger("sequence_engine").warning(
                "[SeqEngine] Capping %d sequence detections to %d for performance",
                len(detections), MAX_SEQUENCES
            )
            # Keep highest-confidence detections
            detections.sort(key=lambda d: d.get("confidence_score", 0), reverse=True)
            detections = detections[:MAX_SEQUENCES]

        return detections

    def process_event(
        self,
        event: Dict[str, Any],
        now: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Process a single live event dict (for streaming use)."""
        computer = str(event.get("computer") or "unknown_host")
        if now is None:
            now = datetime.now(tz=timezone.utc)
        tracker = self._trackers[computer]
        return tracker.process_event(event, self.patterns, now)

    def reset(self) -> None:
        """Clear all in-progress tracking state."""
        self._trackers.clear()


# ---------------------------------------------------------------------------
# Module-level singleton (used by detection_engine.analyze_burst_batch)
# ---------------------------------------------------------------------------

_sequence_engine: Optional[SequenceEngine] = None


def get_sequence_engine() -> SequenceEngine:
    global _sequence_engine
    if _sequence_engine is None:
        _sequence_engine = SequenceEngine()
    return _sequence_engine


def reset_sequence_engine() -> None:
    global _sequence_engine
    _sequence_engine = None
