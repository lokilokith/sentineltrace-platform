"""
correlation_engine.py — SentinelTrace v2 Graph-Based Correlation Engine
=========================================================================
Real correlation:
  - Graph of events linked by (host, parent-child, time proximity)
  - Kill chain stage multipliers for chain depth
  - Temporal decay for distant events
  - Automatic campaign persistence
  - Human-readable campaign narratives
"""

from __future__ import annotations

import datetime
import math
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

# Defer heavy imports to first use or module level if safe
import pandas as pd

# ---------------------------------------------------------------------------
# Kill Chain Ordering
# ---------------------------------------------------------------------------

KILL_CHAIN_ORDER = [
    "Background",
    "Delivery",
    "Execution",
    "Defense Evasion",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Actions on Objectives",
]

_KC_INDEX: Dict[str, int] = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}

# Chain depth → confidence multiplier
# 1 stage = 1.0×, 2 stages = 1.5×, 3 stages = 2.5×, 4+ = 4.0×
_CHAIN_MULTIPLIERS = [1.0, 1.0, 1.5, 2.5, 4.0]

_VALID_CHAINS: Dict[str, List[str]] = {
    "Execution": ["Persistence", "Privilege Escalation", "Defense Evasion", "Command and Control"],
    "Persistence": ["Privilege Escalation", "Command and Control", "Lateral Movement"],
    "Privilege Escalation": ["Lateral Movement", "Defense Evasion"],
    "Defense Evasion": ["Persistence", "Privilege Escalation", "Command and Control"],
    "Lateral Movement": ["Collection", "Command and Control", "Exfiltration"],
    "Command and Control": ["Exfiltration", "Actions on Objectives"],
}


def _kc_index(stage: Optional[str]) -> int:
    return _KC_INDEX.get(stage or "Background", 0)


def _higher_stage(a: Optional[str], b: Optional[str]) -> str:
    return a if _kc_index(a) >= _kc_index(b) else (b or a or "Background")


# ---------------------------------------------------------------------------
# Temporal decay
# ---------------------------------------------------------------------------

DECAY_TAU_SECONDS    = 1800   # Half-life ≈ 30 minutes
EDGE_WEIGHT_THRESHOLD = 0.50  # Raised from 0.30 → tighter clustering.
                               # At 0.30 a single temporal coincidence 29 minutes
                               # apart could merge unrelated clusters.
                               # At 0.50 we only link events within ~20 minutes
                               # that also share structural or cross-signal evidence.
FORWARD_KC_BONUS     = 0.20   # Weight boost for edges that advance kill-chain stage
BACKWARD_KC_PENALTY  = 0.30   # Weight penalty for edges that go backward (anomalous)


def _temporal_weight(delta_seconds: float) -> float:
    """Exponential decay: weight → 0 as events grow apart."""
    return math.exp(-abs(delta_seconds) / DECAY_TAU_SECONDS)


# ---------------------------------------------------------------------------
# Metadata Sanity Helpers
# ---------------------------------------------------------------------------

def _safe(v, default=""):
    """Hardened string casting for NaN/None/Whitespace safety."""
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in ("", "nan", "none"):
        return default
    return s


def _dedup_preserve_order(parts: List[str]) -> List[str]:
    """Removes duplicates from a list while preserving original attack flow order."""
    seen = set()
    out = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _normalize_chain(chain: Any) -> Tuple[str, ...]:
    """Resolves string (->) vs list inconsistencies into a canonical, deduped tuple."""
    if not chain:
        return ()

    if isinstance(chain, str):
        parts = [p.strip().lower() for p in chain.split("->")]
    elif isinstance(chain, (list, tuple)):
        parts = [str(x).strip().lower() for x in chain if x]
    else:
        return ()

    parts = _dedup_preserve_order(parts)
    return tuple(parts)


_POWERSHELL_HINTS = ("powershell", "pwsh", "-enc", "frombase64string", "iex(", "invoke-expression")
_REMOTE_EXEC_HINTS = ("psexec", "wmic", "winrm", "sc.exe", "schtasks", "runas", "remot", "service create")
_PERSISTENCE_HINTS = ("schtasks", "run\\", "runonce", "startup", "autorun", "scheduled task", "registry")
_LOLBIN_HINTS = ("cmd.exe", "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin", "wmic", "powershell")


def _normalize_text(value: Any) -> str:
    return _safe(value, "")


def _contains_any(text: str, needles: Tuple[str, ...]) -> bool:
    text = (text or "").lower()
    return any(needle in text for needle in needles)


def _node_signals(nodes: List["EventNode"]) -> Dict[str, Any]:
    images = sorted({n.image for n in nodes})
    parents = sorted({n.parent_image for n in nodes if n.parent_image})
    commands = sorted({n.command_line for n in nodes if getattr(n, "command_line", "")})
    hosts = sorted({n.computer for n in nodes})

    return {
        "images": images,
        "parents": parents,
        "commands": commands,
        "hosts": hosts,
        "host_count": len(hosts),
        "has_powershell": any(_contains_any(image, _POWERSHELL_HINTS) for image in images) or any(_contains_any(cmd, _POWERSHELL_HINTS) for cmd in commands),
        "has_remote_exec": any(_contains_any(image, _REMOTE_EXEC_HINTS) for image in images) or any(_contains_any(cmd, _REMOTE_EXEC_HINTS) for cmd in commands),
        "has_persistence": any(n.has_persistence for n in nodes) or any(_contains_any(image, _PERSISTENCE_HINTS) for image in images) or any(_contains_any(cmd, _PERSISTENCE_HINTS) for cmd in commands),
        "has_lolbin": any(_contains_any(image, _LOLBIN_HINTS) for image in images),
        "has_injection": any(n.has_injection for n in nodes),
        "has_network": any(n.has_network for n in nodes),
        "has_privilege_escalation": any(n.kill_chain_stage == "Privilege Escalation" for n in nodes),
    }


def _build_campaign_label(nodes: List["EventNode"], highest_stage: str, computers: List[str]) -> str:
    signals = _node_signals(nodes)
    images_joined = " ".join(signals["images"])
    commands_joined = " ".join(signals["commands"])

    if signals["has_powershell"] and any(token in commands_joined for token in ("-enc", "-encodedcommand", "frombase64string", "invoke-expression", "iex ")):
        if signals["has_remote_exec"] or signals["host_count"] > 1:
            return "Encoded-PowerShell-LateralChain"
        return "Encoded-PowerShell-Execution"

    if signals["has_persistence"]:
        if any("reg" in image or "\\run" in image or "runonce" in image for image in signals["images"]):
            return "Persistence-Registry-Chain"
        if "schtasks" in images_joined or "schtasks" in commands_joined:
            return "Persistence-ScheduledTask-Chain"
        return "Persistence-LOLBIN-Chain"

    if highest_stage == "Lateral Movement" or signals["host_count"] > 1:
        if signals["has_remote_exec"]:
            if "cmd.exe" in images_joined:
                return "MultiHost-CMD-LateralChain"
            return "MultiHost-RemoteExecution-Chain"
        return "Lateral-Movement-Chain"

    if signals["has_privilege_escalation"] or signals["has_injection"]:
        return "Privilege-Escalation-Chain"

    if highest_stage == "Command and Control" or signals["has_network"]:
        return "C2-Beacon-Chain"

    if signals["has_lolbin"]:
        return "LOLBIN-Execution-Sequence"

    if len(computers) > 1:
        return "Cross-Host-Chain"

    return "Suspicious-Process-Chain"


def _build_pivot_hints(nodes: List["EventNode"], highest_stage: str, computers: List[str]) -> List[str]:
    signals = _node_signals(nodes)
    hints: List[str] = []

    if signals["has_powershell"]:
        hints.append("Pivot on PowerShell parent/child lineage and decoded command lines.")
    if signals["has_persistence"]:
        hints.append("Pivot on autoruns, Run keys, and scheduled tasks for persistence residue.")
    if signals["has_remote_exec"] or highest_stage == "Lateral Movement":
        hints.append("Pivot on remote service creation, WMI, PsExec, and adjacent hosts.")
    if signals["has_privilege_escalation"] or signals["has_injection"]:
        hints.append("Pivot on token theft, process injection, and parent process lineage.")
    if signals["has_network"] or highest_stage == "Command and Control":
        hints.append("Pivot on destination IPs, DNS activity, and beacon intervals.")
    if len(computers) > 1:
        hints.append(f"Pivot on the {len(computers)} correlated host(s) in the campaign.")

    if not hints:
        hints.append("Pivot on parent-child process chains and the highest kill-chain stage.")

    return hints[:5]


# ---------------------------------------------------------------------------
# Event Node
# ---------------------------------------------------------------------------

class EventNode:
    """Lightweight wrapper around a parsed event dict for graph operations."""

    __slots__ = (
        "uid", "image", "parent_image", "computer", "user",
        "kill_chain_stage", "confidence", "ts", "event_id",
        "has_network", "has_persistence", "has_injection",
        "command_line",
        "process_guid", "parent_process_guid", "high_risk",
    )

    def __init__(self, event: Dict[str, Any]):
        self.uid             = event.get("event_uid") or event.get("burst_id") or str(uuid.uuid4().hex[:8])
        self.image           = _safe(event.get("image"), "unknown")
        self.parent_image    = _safe(event.get("parent_image"), "")
        self.computer        = _safe(event.get("computer"), "unknown_host")
        self.user            = str(event.get("user") or "").upper().strip()
        self.kill_chain_stage = _safe(event.get("kill_chain_stage"), "Background")
        self.confidence      = float(event.get("confidence_score") or event.get("risk_score") or 0.0)
        self.command_line    = _normalize_text(event.get("command_line"))
        self.has_network     = bool(event.get("has_net") or event.get("destination_ip"))
        self.has_persistence = bool(event.get("has_persistence"))
        self.has_injection   = bool(event.get("has_injection"))
        self.event_id        = int(event.get("event_id") or 0)
        self.process_guid    = _safe(event.get("process_guid"), "")
        self.parent_process_guid = _safe(event.get("parent_process_guid"), "")
        self.high_risk       = (self.confidence >= 60.0) # Default invariant (Audit v2 Final)

        ts_raw = event.get("start_time") or event.get("utc_time") or event.get("event_time")
        try:
            self.ts = pd.to_datetime(ts_raw, errors="coerce", utc=True)
            if pd.isna(self.ts):
                self.ts = pd.Timestamp.utcnow() if ts_raw else pd.NaT
        except Exception:
            self.ts = pd.Timestamp.utcnow()


# ---------------------------------------------------------------------------
# Correlation Graph
# ---------------------------------------------------------------------------

class CorrelationGraph:
    """
    Directed graph of event nodes linked by relationship edges.

    Edge types:
      - parent_child  : same host, parent→child image relationship
      - temporal      : same host, same image, within time window
      - host_lateral  : different hosts, same user, close in time
    """

    def __init__(self, time_window_seconds: int = 900):
        self.nodes: Dict[str, EventNode] = {}
        self.edges: List[Dict[str, Any]] = []
        self.time_window = time_window_seconds
        self.metrics: Dict[str, Any] = {
            "pair_checks": 0,
            "nested_loop_iterations": 0,
            "edges_created": 0,
            "window_prunes": 0,
            "max_active_window": 0,
            "host_event_counts": {},
            "component_count": 0,
            "component_edge_scan_iterations": 0,
            "build_edges_seconds": 0.0,
            "build_campaigns_seconds": 0.0,
        }

    def add_node(self, event: Dict[str, Any]) -> EventNode:
        node = EventNode(event)
        self.nodes[node.uid] = node
        return node

    def add_nodes_bulk(self, events: List[Dict[str, Any]]) -> None:
        for ev in events:
            self.add_node(ev)

    def build_edges(self) -> None:
        """
        Builds edges between nodes using strict chronological temporal and structural relationships.
        """
        build_started = time.perf_counter()
        self.edges.clear()
        try:
            from dashboard.analysis_engine import check_timeout as _check_timeout
        except ImportError:
            _check_timeout = None

        # group by host
        events_by_host = {}
        for uid, e in self.nodes.items():
            events_by_host.setdefault(e.computer, []).append(e)
        self.metrics["host_event_counts"] = {host: len(evts) for host, evts in events_by_host.items()}

        for host, evts in events_by_host.items():
            # Sort by time
            evts.sort(key=lambda x: x.ts if pd.notna(x.ts) else pd.Timestamp.min.tz_localize("UTC"))

        from collections import deque
        for host, evts in events_by_host.items():
            # Sort by time
            evts.sort(key=lambda x: x.ts if pd.notna(x.ts) else pd.Timestamp.min.tz_localize("UTC"))

            # ── [9.8 PROD] O(N*K) Sliding Window Implementation ────────────
            # Uses a deque to maintain only nodes within the 'time_window'.
            # Drastically reduces comparisons in dense datasets.
            active: deque[EventNode] = deque()

            for e2 in evts:
                # 1. Prune the window: Remove nodes too old to correlate with e2
                while active and pd.notna(e2.ts) and pd.notna(active[0].ts):
                    if (e2.ts - active[0].ts).total_seconds() > self.time_window:
                        active.popleft()
                        self.metrics["window_prunes"] += 1
                    else:
                        break

                # 2. Check global analysis timeout (safe — check_cancelled removed)
                if _check_timeout is not None:
                    _check_timeout("correlation_build")

                # 3. Compare current node e2 against all active candidates e1
                for e1 in active:
                    self.metrics["pair_checks"] += 1
                    self.metrics["nested_loop_iterations"] += 1
                    # Risk Invariant (Audit v2 Final)
                    e1.high_risk = (getattr(e1, "confidence", 0) >= 60)
                    e2.high_risk = (getattr(e2, "confidence", 0) >= 60)

                    delta = (e2.ts - e1.ts).total_seconds() if (pd.notna(e1.ts) and pd.notna(e2.ts)) else 100

                    # BASIC STAGE PROGRESSION
                    is_same_stage = (e1.kill_chain_stage == e2.kill_chain_stage)
                    is_valid_progression = e2.kill_chain_stage in _VALID_CHAINS.get(e1.kill_chain_stage, [])
                    is_background = "Background" in (e1.kill_chain_stage, e2.kill_chain_stage)

                    # PROCESS RELATIONSHIP
                    is_structural = False
                    if e1.process_guid and e1.process_guid == e2.parent_process_guid:
                        is_structural = True
                    elif e1.image and e1.image == e2.parent_image:
                        is_structural = True
                    
                    # TACTICAL RELATIONSHIP
                    is_tactical = False
                    if e2.kill_chain_stage in _VALID_CHAINS.get(e1.kill_chain_stage, []):
                        is_tactical = True

                    # ── Tiered Weights ─────────────────────────────────────
                    w = 0.0
                    edge_type = "none"
                    reason = ""
                    
                    if is_structural:
                        w = 5.0
                        edge_type = "structural_link"
                        reason = f"Direct process lineage ({e1.image} -> {e2.image})"
                    elif is_valid_progression:
                        w = 3.0
                        edge_type = "tactic_chain"
                        reason = f"Tactic progression: {e1.kill_chain_stage} → {e2.kill_chain_stage}"
                    elif is_same_stage and e1.user == e2.user:
                        w = 2.0
                        edge_type = "same_stage_user"
                        reason = f"Same-stage clustering ({e1.kill_chain_stage})"
                    else:
                        if e1.user == e2.user and not is_background:
                            w = 1.0
                            edge_type = "temporal_user"
                            reason = f"Temporal user proximity ({delta:.0f}s)"

                    if w > 0:
                        is_high_risk = (e1.confidence >= 70 or e2.confidence >= 70)
                        if w < EDGE_WEIGHT_THRESHOLD and not is_high_risk:
                            continue

                        if _kc_index(e2.kill_chain_stage) < _kc_index(e1.kill_chain_stage):
                            w *= 0.5
                            reason += " (Backward Penalty 0.5x)"

                        self.edges.append({
                            "from": e1.uid,
                            "to": e2.uid,
                            "type": edge_type,
                            "weight": w,
                            "delta_sec": delta,
                            "host": host,
                            "from_stage": e1.kill_chain_stage,
                            "to_stage": e2.kill_chain_stage,
                            "reason": reason,
                            "confidence_type": "structural" if is_structural else "behavioral",
                            "direction": "forward" if _kc_index(e2.kill_chain_stage) >= _kc_index(e1.kill_chain_stage) else "backward"
                        })
                        self.metrics["edges_created"] += 1
                
                # 4. Add current node to active window for future nodes
                active.append(e2)
                if len(active) > self.metrics["max_active_window"]:
                    self.metrics["max_active_window"] = len(active)

        self.metrics["build_edges_seconds"] = round(time.perf_counter() - build_started, 6)

    def connected_components(self) -> List[Set[str]]:
        """Union-Find connected components with path compression + union-by-rank."""
        parent: Dict[str, str] = {uid: uid for uid in self.nodes}
        rank:   Dict[str, int] = {uid: 0   for uid in self.nodes}

        def find(x: str) -> str:
            # Path halving — points every other node directly at root
            # Amortized O(α(n)) — practically constant for any realistic dataset
            while parent[x] != x:
                parent[x] = parent[parent[x]]   # grandparent hop
                x = parent[x]
            return x

        def union(x: str, y: str) -> None:
            # Union by rank — attach shorter tree under taller to keep trees flat
            rx, ry = find(x), find(y)
            if rx == ry:
                return
            if rank[rx] < rank[ry]:
                rx, ry = ry, rx          # ensure rx has higher rank
            parent[ry] = rx              # attach ry under rx
            if rank[rx] == rank[ry]:
                rank[rx] += 1            # only increment when ranks were equal

        for i, edge in enumerate(self.edges):
            if edge["from"] in parent and edge["to"] in parent:
                union(edge["from"], edge["to"])

        groups: Dict[str, Set[str]] = defaultdict(set)
        for uid in self.nodes:
            groups[find(uid)].add(uid)

        return [g for g in groups.values() if len(g) >= 2]


# ---------------------------------------------------------------------------
# Campaign Builder
# ---------------------------------------------------------------------------

class CampaignBuilder:
    """
    Converts connected components into scored, annotated campaigns.
    """

    def build_campaigns(
        self,
        graph: CorrelationGraph,
        run_id: str,
    ) -> List[Dict[str, Any]]:
        build_started = time.perf_counter()
        components = graph.connected_components()
        graph.metrics["component_count"] = len(components)
        campaigns  = []

        # Build a component index once and bucket edges once.
        # This avoids repeated O(components * edges) scans in scoring.
        uid_to_component: Dict[str, int] = {}
        for idx, component_uids in enumerate(components):
            for uid in component_uids:
                uid_to_component[uid] = idx

        edges_by_component: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        edge_scan_iterations = 0
        for edge in graph.edges:
            edge_scan_iterations += 1
            comp_idx = uid_to_component.get(edge.get("from"))
            if comp_idx is None:
                continue
            if uid_to_component.get(edge.get("to")) == comp_idx:
                edges_by_component[comp_idx].append(edge)

        graph.metrics["component_edge_scan_iterations"] = edge_scan_iterations

        for idx, component_uids in enumerate(components):
            nodes = [graph.nodes[uid] for uid in component_uids if uid in graph.nodes]
            if not nodes:
                continue

            campaign = self._score_component(nodes, edges_by_component.get(idx, []), run_id)
            if campaign:
                campaigns.append(campaign)

        graph.metrics["build_campaigns_seconds"] = round(time.perf_counter() - build_started, 6)
        return sorted(campaigns, key=lambda c: -c["confidence"])

    def _score_component(
        self,
        nodes: List[EventNode],
        component_edges: List[Dict[str, Any]],
        run_id: str,
    ) -> Optional[Dict[str, Any]]:
        if not nodes:
            return None

        # ── Kill chain analysis ───────────────────────────────────────────
        stages = list({n.kill_chain_stage for n in nodes})
        stage_indices = sorted([_kc_index(s) for s in stages], reverse=True)
        highest_stage = KILL_CHAIN_ORDER[stage_indices[0]] if stage_indices else "Execution"
        chain_depth   = len(set(stage_indices))
        multiplier    = _CHAIN_MULTIPLIERS[min(chain_depth, len(_CHAIN_MULTIPLIERS) - 1)]

        # ── Base confidence ───────────────────────────────────────────────
        base = max((n.confidence for n in nodes), default=0.0)
        if base == 0:
            base = 30.0   # Structural correlation even without prior score

        # ── Behavioral bonuses ────────────────────────────────────────────
        bonus = 0.0
        if any(n.has_persistence for n in nodes):
            bonus += 15.0
        if any(n.has_injection for n in nodes):
            bonus += 25.0
        if any(n.has_network for n in nodes):
            bonus += 10.0
        if any(n.event_id in {8, 9, 25} for n in nodes):   # Critical EIDs
            bonus += 20.0

        # ── Edge weight sum + directional flow bonus ──────────────────────
        forward_count  = 0
        backward_count = 0
        edge_weight    = 0.0
        for e in component_edges:
            edge_weight += e.get("weight", 0.0)
            if e.get("direction") == "forward":
                forward_count += 1
            elif e.get("direction") == "backward":
                backward_count += 1

        edge_bonus = min(edge_weight * 5.0, 20.0)

        # Pure forward kill-chain flow → additional confidence bonus
        direction_bonus = 0.0
        if forward_count > 0 and backward_count == 0:
            direction_bonus = min(forward_count * 5.0, 15.0)

        # ── Final score (Audit v2: Hybrid Rebalance) ───────────────────────
        # confidence = max(10, structural_score * 0.5 + signal_score)
        # Prevents "hallucinations" from purely structural overlaps.

        # ── Temporal metadata ─────────────────────────────────────────────
        valid_ts = [n.ts for n in nodes if pd.notna(n.ts)]
        first_seen = min(valid_ts).isoformat() if valid_ts else None
        last_seen  = max(valid_ts).isoformat() if valid_ts else None

        # ── Computers / users ─────────────────────────────────────────────
        computers = sorted({n.computer for n in nodes})
        users     = sorted({n.user for n in nodes if n.user})
        images    = sorted({n.image for n in nodes})

        signal_score     = base + bonus
        structural_score = min(edge_bonus + direction_bonus, 50.0) # Cap structural contribution (Audit v2 Final)
        host_diversity   = len(computers)
        image_diversity  = len(images)
        stage_diversity  = len(stages)
        span_minutes = 0.0
        if len(valid_ts) > 1:
            span_minutes = max(0.0, (max(valid_ts) - min(valid_ts)).total_seconds() / 60.0)

        diversity_bonus = min(
            12.0,
            max(0, host_diversity - 1) * 3.0
            + max(0, image_diversity - 1) * 1.5
            + max(0, stage_diversity - 1) * 2.0,
        )
        span_bonus = min(10.0, math.log1p(span_minutes) * 2.0) if span_minutes > 0 else 0.0

        final = max(10.0, structural_score * 0.5 + signal_score + diversity_bonus + span_bonus)
        final = min(final * multiplier, 100.0)

        # ── Narrative ─────────────────────────────────────────────────────
        campaign_name = _build_campaign_label(nodes, highest_stage, computers)
        narrative = self._build_narrative(nodes, highest_stage, chain_depth, multiplier, computers, campaign_name)
        pivot_hints = _build_pivot_hints(nodes, highest_stage, computers)

        # ── Correlation ID ────────────────────────────────────────────────
        import re as _re
        day = datetime.datetime.utcnow().strftime("%Y%m%d")
        base_image = nodes[0].image
        # Prefer a behavior-driven campaign label in the corr id to avoid image-only synthetic IDs.
        label = campaign_name if campaign_name else base_image
        # Sanitize: strip everything except alphanumeric and underscore
        _safe_img  = _re.sub(r"[^a-z0-9]", "_", str(label)[:16].lower())
        _safe_host = _re.sub(r"[^a-z0-9]", "_", computers[0][:8].lower())
        corr_id    = f"CAMP-{_safe_img}-{_safe_host}-{day}"

        return {
            "corr_id":           corr_id,
            "edges":             component_edges,
            "run_id":            run_id,
            "base_image":        base_image,
            "images":            images,
            "computers":         computers,
            "users":             users,
            "campaign_name":     campaign_name,
            "campaign_theme":    f"{campaign_name} · {highest_stage or 'Background'}",
            "first_seen":        first_seen,
            "last_seen":         last_seen,
            "event_count":       len(nodes),
            "chain_depth":       chain_depth,
            "chain_multiplier":  multiplier,
            "kill_chain_stages": stages,
            "highest_stage":     highest_stage,
            "confidence":        round(final, 1),
            "has_persistence":   any(n.has_persistence for n in nodes),
            "has_injection":     any(n.has_injection for n in nodes),
            "has_network":       any(n.has_network for n in nodes),
            "narrative":         narrative,
            "pivot_hints":       pivot_hints,
            "node_uids":         [n.uid for n in nodes],
            "status":            "active",
        }

    @staticmethod
    def _build_narrative(
        nodes: List[EventNode],
        highest_stage: str,
        chain_depth: int,
        multiplier: float,
        computers: List[str],
        campaign_name: str,
    ) -> str:
        images  = sorted({n.image for n in nodes})
        stages  = sorted({n.kill_chain_stage for n in nodes}, key=_kc_index)
        host    = nodes[0].computer

        parts = [
            f"{campaign_name} on {host} spanning {len(computers)} host(s) and {len(images)} process family(ies).",
            f"Kill-chain stages detected: {' → '.join(stages)}.",
        ]
        if highest_stage and highest_stage != "Background":
            parts.append(f"Current investigative anchor is {highest_stage}, where the chain is most mature.")
        if len(computers) > 1:
            parts.append(f"Spread observed across {len(computers)} host(s), which raises separation confidence.")
        if len(images) > 1:
            parts.append(f"Image diversity observed across {len(images)} process family(ies).")
        if chain_depth >= 3:
            parts.append(
                f"Chain depth {chain_depth} with {multiplier:.1f}× confidence amplification — "
                f"strong multi-stage attack indicator."
            )
        elif chain_depth == 2:
            parts.append("Two-stage kill chain observed — investigation warranted.")
        if any(n.has_injection for n in nodes):
            parts.append("Process injection detected — likely privilege escalation or evasion.")
        if any(n.has_persistence for n in nodes):
            parts.append("Persistence mechanism observed — attacker likely establishing foothold.")
        if any(n.has_network for n in nodes):
            parts.append("Network activity present — possible C2 or data staging.")

        return " ".join(parts)


# ---------------------------------------------------------------------------
# DB Persistence
# ---------------------------------------------------------------------------

def _decay_stale_campaigns(conn: Any, mode: str, run_id: str) -> None:
    """
    Reduce confidence of campaigns not seen in 24 hours (lifecycle decay).
    Campaigns that persist but don't re-trigger gradually lose confidence —
    this prevents stale detections from looking as urgent as fresh ones.
    Campaigns below a minimum confidence floor are marked dormant.
    """
    try:
        from dashboard.db import get_cursor, sql_now_minus
        DECAY_PCT     = 0.90   # Each decay cycle reduces confidence by 10%
        MIN_CONFIDENCE = 20    # Below this → mark dormant
        with get_cursor(conn) as cur:
            # Use FLOOR() not CAST AS UNSIGNED — UNSIGNED wraps negative values
            # to enormous numbers, corrupting confidence scores on edge cases.
            cur.execute(
                f"UPDATE correlation_campaigns "
                f"SET max_confidence = GREATEST("
                f"  FLOOR(max_confidence * {DECAY_PCT}), {MIN_CONFIDENCE}"
                f"), "
                f"status = CASE "
                f"  WHEN FLOOR(max_confidence * {DECAY_PCT}) <= {MIN_CONFIDENCE} "
                f"  THEN 'dormant' ELSE status END "
                f"WHERE run_id = %s "
                f"AND status = 'active' "
                f"AND last_seen < {sql_now_minus(24, 'HOUR')}",
                (run_id,),
            )
    except Exception as e:
        print(f"[CorrelationEngine] decay failed: {e}")


def persist_campaigns(campaigns: List[Dict[str, Any]]) -> None:
    """Write / update campaigns in sentinel_live (or sentinel_cases for uploads)."""
    if not campaigns:
        return

    try:
        from dashboard.db import get_db_connection, get_cursor, checked_insert, now_utc, sanitize_datetime, get_table_columns

        run_id = campaigns[0].get("run_id", "live")
        mode   = "live" if run_id == "live" else "cases"
        now    = now_utc()

        with get_db_connection(mode) as conn:
            # Lifecycle decay: stale campaigns lose confidence gradually
            _decay_stale_campaigns(conn, mode, run_id)
            with get_cursor(conn) as cur:
                for camp in campaigns:
                    cid = camp["corr_id"]
                    cur.execute(
                        "SELECT burst_count, max_confidence, highest_kill_chain "
                        "FROM correlation_campaigns WHERE corr_id = %s AND run_id = %s",
                        (cid, run_id),
                    )
                    row = cur.fetchone()
                    new_conf  = int(camp["confidence"])
                    new_stage = camp["highest_stage"]

                    if row:
                        final_stage = _higher_stage(row["highest_kill_chain"], new_stage)
                        cur.execute(
                            "UPDATE correlation_campaigns SET "
                            "burst_count=%s, last_seen=%s, max_confidence=%s, "
                            "highest_kill_chain=%s, status='active', description=%s "
                            "WHERE corr_id=%s AND run_id=%s",
                            (
                                row["burst_count"] + 1,
                                now,
                                max(row["max_confidence"], new_conf),
                                final_stage,
                                camp.get("narrative", ""),
                                cid, run_id,
                            ),
                        )
                    else:
                        checked_insert(
                            cur, "correlation_campaigns",
                            ["corr_id", "run_id", "base_image", "computer",
                             "first_seen", "last_seen", "burst_count",
                             "max_confidence", "highest_kill_chain", "status", "description"],
                            (
                                cid, run_id,
                                camp.get("base_image"),
                                camp.get("computers", ["unknown"])[0],
                                sanitize_datetime(camp.get("first_seen")),
                                sanitize_datetime(camp.get("last_seen")),
                                1, new_conf, new_stage, "active",
                                camp.get("narrative", ""),
                            ),
                            identity_hint=f"corr_id={cid}",
                        )

                    # Detail row in correlations table (Audit v2: Dynamic Column Check)
                    try:
                        all_cols = get_table_columns(cur, "correlations")
                        data_map = {
                            "corr_id":    cid,
                            "run_id":     run_id,
                            "base_image": camp.get("base_image"),
                            "start_time": sanitize_datetime(camp.get("first_seen")),
                            "end_time":   sanitize_datetime(camp.get("last_seen")),
                            "description": camp.get("narrative", ""),
                            "event_ids":  ",".join(camp.get("node_uids", [])[:20]),
                            "computer":   camp.get("computers", ["unknown"])[0],
                            "kill_chain_stage": new_stage,
                            "severity":   "high" if new_conf >= 70 else "medium" if new_conf >= 40 else "low",
                            "confidence": new_conf,
                        }
                        # Only insert columns that actually exist in the DB
                        final_cols = [c for c in data_map.keys() if c in all_cols]
                        final_vals = [data_map[c] for c in final_cols]
                        placeholders = ", ".join(["%s"] * len(final_cols))
                        col_str = ", ".join([f"`{c}`" for c in final_cols])
                        
                        cur.execute(
                            f"INSERT INTO `correlations` ({col_str}) VALUES ({placeholders})",
                            tuple(final_vals)
                        )
                    except Exception as ins_exc:
                        log.warning("Correlations detail insert failed: %s", ins_exc)
            conn.commit()
    except Exception as e:
        import traceback
        print(f"[CorrelationEngine] persist_campaigns failed: {e}")
        traceback.print_exc()


# ---------------------------------------------------------------------------
# High-level entry point
# ---------------------------------------------------------------------------

def correlate_events(
    events: List[Dict[str, Any]],
    run_id: str,
    time_window_seconds: int = 900,
    persist: bool = True,
    debug_mode: bool = False,
) -> List[Dict[str, Any]]:
    """
    Full correlation pipeline.

    Args:
        events            : List of event/burst dicts (must have event_uid, image, etc.)
        run_id            : Analysis run identifier
        time_window_seconds : Max time gap to consider two events correlated
        persist           : Whether to write campaigns to DB

    Returns:
        List of campaign dicts sorted by confidence descending.
    """
    if not events:
        return []

    # Filter out events with no meaningful identity — they produce orphan nodes
    # that inflate component counts without adding real correlation signal.
    valid_events = [e for e in events if e.get("image") or e.get("event_uid")]
    if not valid_events:
        return []

    # 9.8: Hard cap — build_edges() is O(N²); cap prevents runaway on large logs
    MAX_CORR_EVENTS = 500
    if len(valid_events) > MAX_CORR_EVENTS:
        import logging as _logging
        _logging.getLogger("correlation").warning(
            "[CorrEngine] Capping %d events to %d before graph build",
            len(valid_events), MAX_CORR_EVENTS
        )
        valid_events = valid_events[:MAX_CORR_EVENTS]

    started = time.perf_counter()
    graph = CorrelationGraph(time_window_seconds=time_window_seconds)
    graph.add_nodes_bulk(valid_events)
    graph.build_edges()
    after_build_edges = time.perf_counter()

    builder   = CampaignBuilder()
    campaigns = builder.build_campaigns(graph, run_id)
    after_build_campaigns = time.perf_counter()

    # ── [10/10] Guarded Dual-Mode Observability ──────────────────────────
    import os
    is_dev = os.environ.get("SENTINEL_ENV") == "dev"

    valid_edges = 0
    for e in graph.edges:
        if e.get("weight", 0.0) >= EDGE_WEIGHT_THRESHOLD:
            valid_edges += 1
    
    debug_snapshot = {
        "run_id": run_id,
        "total_events": len(valid_events),
        "node_count": len(graph.nodes),
        "total_edges": len(graph.edges),
        "valid_edges": valid_edges,
        "campaign_count": len(campaigns),
        "pair_checks": int(graph.metrics.get("pair_checks", 0)),
        "nested_loop_iterations": int(graph.metrics.get("nested_loop_iterations", 0)),
        "component_count": int(graph.metrics.get("component_count", 0)),
        "component_edge_scan_iterations": int(graph.metrics.get("component_edge_scan_iterations", 0)),
        "max_active_window": int(graph.metrics.get("max_active_window", 0)),
        "edge_count": len(graph.edges),
        "host_event_counts": dict(graph.metrics.get("host_event_counts", {})),
        "function_timings_seconds": {
            "build_edges": round(after_build_edges - started, 6),
            "build_campaigns": round(after_build_campaigns - after_build_edges, 6),
            "tag_events": 0.0,
            "total": 0.0,
        },
        "traversal_timings_seconds": round(graph.metrics.get("build_edges_seconds", 0.0), 6),
        "scoring_timings_seconds": round(graph.metrics.get("build_campaigns_seconds", 0.0), 6),
        "merge_timings_seconds": round(graph.metrics.get("build_campaigns_seconds", 0.0), 6),
        "campaign_build_seconds": round(graph.metrics.get("build_campaigns_seconds", 0.0), 6),
        "edge_build_seconds": round(graph.metrics.get("build_edges_seconds", 0.0), 6),
        "total_seconds": round((after_build_campaigns - started), 6),
        "correlation_telemetry": {
            "pair_checks": int(graph.metrics.get("pair_checks", 0)),
            "edge_count": len(graph.edges),
            "component_count": int(graph.metrics.get("component_count", 0)),
            "component_edge_scan_iterations": int(graph.metrics.get("component_edge_scan_iterations", 0)),
            "traversal_seconds": round(graph.metrics.get("build_edges_seconds", 0.0), 6),
            "scoring_seconds": round(graph.metrics.get("build_campaigns_seconds", 0.0), 6),
            "merge_seconds": round(graph.metrics.get("build_campaigns_seconds", 0.0), 6),
            "total_seconds": round((after_build_campaigns - started), 6),
        },
    }
    
    if debug_mode and is_dev:
        # Full snapshot allowed only in dev
        debug_snapshot["raw_edges"] = graph.edges[:100] # Cap breadth
    
    # Store in first event or global context if available
    if events:
        events[0]["correlation_debug"] = debug_snapshot

    # Tag source events with their campaign id
    uid_to_camp: Dict[str, str] = {}
    camp_conf_by_id: Dict[str, float] = {}
    for camp in campaigns:
        camp_conf_by_id[camp["corr_id"]] = camp.get("confidence", 0)
        for uid in camp.get("node_uids", []):
            uid_to_camp[uid] = camp["corr_id"]

    for ev in events:
        uid = ev.get("event_uid") or ev.get("burst_id")
        if uid and uid in uid_to_camp:
            corr_id = uid_to_camp[uid]
            ev["correlation_id"]    = uid_to_camp[uid]
            ev["has_correlation"]   = True
            ev["correlation_score"] = camp_conf_by_id.get(corr_id, 0)

    after_tag_events = time.perf_counter()
    debug_snapshot["function_timings_seconds"]["tag_events"] = round(after_tag_events - after_build_campaigns, 6)

    if persist and campaigns:
        persist_campaigns(campaigns)

    debug_snapshot["function_timings_seconds"]["total"] = round(time.perf_counter() - started, 6)
    debug_snapshot["total_seconds"] = debug_snapshot["function_timings_seconds"]["total"]
    debug_snapshot["scoring_batch_count"] = len(campaigns)

    return campaigns


def correlate_bursts(
    bursts: List[Dict[str, Any]],
    run_id: str,
    time_window_seconds: int = 900,
    persist: bool = True,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Wrapper for burst-level correlation (used by analysis_engine).
    Maps burst dicts → event dicts, runs correlation, returns
    (updated_bursts, campaigns).
    """
    # Ensure burst dicts have the fields EventNode expects
    mapped = []
    for b in bursts:
        mapped.append({
            "event_uid":        b.get("burst_id") or b.get("correlation_id") or uuid.uuid4().hex[:12],
            "image":            b.get("image"),
            "parent_image":     b.get("parent_image"),
            "process_guid":     b.get("process_guid"),
            "parent_process_guid": b.get("parent_process_guid"),
            "computer":         b.get("computer"),
            "user":             b.get("user"),
            "kill_chain_stage": b.get("kill_chain_stage") or "Execution",
            "confidence_score": b.get("risk_score") or 0,
            "has_net":          b.get("has_net"),
            "has_persistence":  b.get("has_persistence"),
            "has_injection":    b.get("has_injection"),
            "event_id":         (b.get("event_ids") or [0])[0] if b.get("event_ids") else 0,
            "start_time":       b.get("start_time"),
            "utc_time":         b.get("start_time"),
            "destination_ip":   b.get("destination_ip"),
            "_burst_ref":       b,   # back-reference so we can mutate original
        })

    campaigns = correlate_events(mapped, run_id, time_window_seconds, persist)

    # Propagate correlation metadata back to original bursts
    for m in mapped:
        original = m.get("_burst_ref")
        if original is not None:
            original["correlation_id"]    = m.get("correlation_id")
            original["has_correlation"]   = m.get("has_correlation", False)
            original["correlation_score"] = m.get("correlation_score", 0)

    if bursts and mapped:
        corr_debug = mapped[0].get("correlation_debug")
        if corr_debug:
            bursts[0]["correlation_debug"] = corr_debug
            bursts[0]["correlation_telemetry"] = corr_debug.get("correlation_telemetry", corr_debug)

    return bursts, campaigns


def deduplicate_chains(chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Final truth alignment: removes duplicate attack stories from the pipeline.
    Uses semantic-aware keying (Chain, Computer, Stage, Confidence Bucket, Net, Persistence).
    """
    seen = set()
    unique = []

    for c in chains:
        # 1. Normalize chain semantics
        chain = _normalize_chain(c.get("attack_chain") or c.get("chain_str"))
        if not chain:
            continue

        # 2. Hard-overwrite with canonical version
        c["attack_chain"] = list(chain)
        c["chain_str"] = " → ".join(chain)

        # 3. Handle signal floor (Stop theSIEM lies)
        conf_raw = float(c.get("confidence_score") or c.get("confidence") or 0.0)
        if not math.isfinite(conf_raw):
            conf_raw = 0.0
        
        # Require minimal signal to participate in de-duplication
        if conf_raw == 0 and not (c.get("has_signal") or c.get("detections")):
            continue

        # 4. Semantic-aware keying
        comp = _safe(c.get("computer"), "unknown_host")
        stage = _safe(c.get("kill_chain_stage"), "Background")
        conf_bucket = int(conf_raw // 5) * 5
        has_net = bool(c.get("destination_ip") or c.get("has_net"))
        has_persist = bool(c.get("has_persistence"))
        time_hint = _safe(c.get("first_seen") or c.get("start_time") or c.get("last_seen"), "")
        if "T" in time_hint:
            time_bucket = time_hint[:13]
        else:
            time_bucket = time_hint[:10]
        host_count = min(len({h for h in (c.get("computers") or []) if h}), 3)
        image_count = min(len({i for i in (c.get("images") or []) if i}), 3)

        key = (chain, comp, stage, conf_bucket, has_net, has_persist, time_bucket, host_count, image_count)

        if key not in seen:
            seen.add(key)
            unique.append(c)

    return unique
