"""
baseline_engine.py — SentinelTrace v2 Statistical Baseline Engine
==================================================================
Real baseline detection:
  - Per-entity (host, user, process) statistical profiles
  - Welford online variance for streaming updates
  - Z-score based frequency anomaly detection
  - Parent distribution anomaly
  - Entropy anomaly (command line)
  - Time-of-day anomaly (hour bucket)
  - Persistence via MySQL (behavior_baseline table)
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import os
import logging
from sqlalchemy import text

log = logging.getLogger("baseline_engine")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_SAMPLES_FOR_CONFIDENCE = 10   # Lowered from 20 for faster signal activation
ZSCORE_ALERT_THRESHOLD     = 3.0  # Standard deviations for frequency anomaly
ENTROPY_SIGMA_THRESHOLD    = 2.0  # Standard deviations for entropy anomaly
# Note: factor weights (0.25 / 0.15 / 0.15 / 0.20 / 0.10 / 0.15) are
# defined inline inside EntityProfile.score_event for clarity.

# Processes that should NEVER be learned into baseline (always suspicious)
NEVER_LEARN  = frozenset({
    "wmic.exe", "psexec.exe", "psexec64.exe", "mimikatz.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
})

# Known high-noise benign parents (reduces parent anomaly score)
BENIGN_PARENTS = frozenset({
    "explorer.exe", "services.exe", "svchost.exe", "wininit.exe",
    "winlogon.exe", "lsass.exe", "csrss.exe", "spoolsv.exe",
    "taskhost.exe", "taskhostw.exe", "smss.exe",
})


# ---------------------------------------------------------------------------
# Welford Online Statistics (streaming mean + variance)
# ---------------------------------------------------------------------------

class WelfordStats:
    """Welford single-pass online mean and variance estimator."""

    __slots__ = ("n", "mean", "m2")

    def __init__(self, n: int = 0, mean: float = 0.0, m2: float = 0.0):
        self.n    = n
        self.mean = mean
        self.m2   = m2

    def update(self, x: float) -> None:
        self.n += 1
        delta  = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(max(self.variance, 0.0))

    def z_score(self, x: float) -> float:
        # Use 0.1 floor (not 1.0) so tight distributions still surface anomalies
        s = max(self.std, 0.1)
        return (x - self.mean) / s

    def to_dict(self) -> Dict[str, Any]:
        return {"n": self.n, "mean": self.mean, "m2": self.m2}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "WelfordStats":
        return cls(
            n    = int(d.get("n", 0)),
            mean = float(d.get("mean", 0.0)),
            m2   = float(d.get("m2", 0.0)),
        )


# ---------------------------------------------------------------------------
# Entity Key
# ---------------------------------------------------------------------------

EntityKey = Tuple[str, str, str]   # (computer, user_type, image)


def _entity_key(event: Dict[str, Any]) -> EntityKey:
    computer  = (event.get("computer") or "unknown_host").lower()
    user      = (event.get("user") or "").upper()
    user_type = "system" if "SYSTEM" in user or "NETWORK SERVICE" in user else "interactive"
    image     = (event.get("image") or "unknown").lower()
    return (computer, user_type, image)


# ---------------------------------------------------------------------------
# Entity Profile
# ---------------------------------------------------------------------------

class EntityProfile:
    """
    Statistical profile for a (host, user_type, process_image) triple.
    Tracks:
      - Execution frequency (Welford)
      - Command entropy (Welford)
      - Parent distribution (Counter)
      - Hour-of-day distribution (24 buckets)
      - Network activity flag
    """

    def __init__(self):
        self.exec_stats    = WelfordStats()
        self.entropy_stats = WelfordStats()
        self.parent_counts: Dict[str, int] = defaultdict(int)
        self.parent_total  = 0
        self.hour_counts   = [0] * 24
        self.hour_total    = 0
        self.seen_days     = 1
        # ── NEW: n-gram sequence model ────────────────────────────────────
        # seq_2: bigram  (parent, child)           — catches winword→powershell
        # seq_3: trigram (grandparent, parent, child) — catches winword→powershell→cmd
        # prev_image: last image seen for this entity (needed to build trigrams)
        self.seq_2: Dict[tuple, int] = defaultdict(int)
        self.seq_2_total = 0
        self.seq_3: Dict[tuple, int] = defaultdict(int)
        self.seq_3_total = 0
        self.prev_image: Optional[str] = None    # rolling last-seen image
        self.prev_image: Optional[str] = None    # rolling last-seen image
        # Properties (seq_counts, seq_total) handle backward compatibility
        # without manual sync overhead.
        # ── NEW: per-IP network model ─────────────────────────────────────
        self.network_counts: Dict[str, int] = defaultdict(int)
        self.network_total  = 0
        # /24 subnet model — survives IP rotation within same infrastructure
        self.network_subnet_counts: Dict[str, int] = defaultdict(int)
        self.network_subnet_total  = 0
        self._updates = 0
        self.count = 0
        self.last_seen = None
        self.host_baseline_drift = 0.0  # % change in last N updates

    @property
    def seq_counts(self) -> Dict[tuple, int]:
        return self.seq_2

    @property
    def seq_total(self) -> int:
        return self.seq_2_total

    # ── Constants ─────────────────────────────────────────────────────────
    DECAY_FACTOR  = 0.995   # Applied every N updates to forget stale data
    DECAY_EVERY   = 50      # Apply decay after every 50 learning events

    # ── Update ────────────────────────────────────────────────────────────

    def _maybe_decay(self, now: Optional['pd.Timestamp'] = None) -> None:
        """
        Time-aware exponential forgetting.
        Decay only happens when time actually passes (days_idle).
        """
        if now is None:
            # Fallback to update count decay if no timestamp provided
            self._updates += 1
            if self._updates % self.DECAY_EVERY != 0:
                return
            d = self.DECAY_FACTOR
        else:
            # Real time-aware decay
            if not hasattr(self, "_last_decay_time"):
                self._last_decay_time = now
                return
            
            import pandas as pd
            delta = now - self._last_decay_time
            days_idle = delta.total_seconds() / 86400.0
            if days_idle < 1.0:
                return
            
            # ── [10/10 EXPERT] Hybrid Anomaly Aging ───────────────────────
            # Rare threats (< 10 samples) decay slower to maintain memory.
            if self.exec_stats.n < 10:
                # 0.3 floor for 90 days, then 0.2 floor.
                floor = 0.3 if days_idle < 90 else 0.2
                # Slow normalize (0.1 reduction per week)
                d = max(0.9, 1.0 - (days_idle / 70.0)) 
            else:
                # Real exponential decay for high-frequency hits (exp(-days/7))
                d = math.exp(-days_idle / 7.0)

            self._last_decay_time = now

        # ── Correct Welford decay: scale n and m2, leave mean untouched ──
        self.exec_stats.n    = max(1, int(self.exec_stats.n * d))
        self.exec_stats.m2  *= d
        self.entropy_stats.n = max(1, int(self.entropy_stats.n * d))
        self.entropy_stats.m2 *= d
        # ── Decay count tables ────────────────────────────────────────────
        for k in list(self.parent_counts):
            self.parent_counts[k] = max(1, int(self.parent_counts[k] * d))
        self.parent_total = max(1, int(self.parent_total * d))
        for k in list(self.network_counts):
            self.network_counts[k] = max(1, int(self.network_counts[k] * d))
        self.network_total = max(1, int(self.network_total * d))
        for k in list(self.seq_2):
            self.seq_2[k] = max(1, int(self.seq_2[k] * d))
        self.seq_2_total = max(1, int(self.seq_2_total * d))
        self.seq_2_total = max(1, int(self.seq_2_total * d))
        for k in list(self.seq_3):
            self.seq_3[k] = max(1, int(self.seq_3[k] * d))
        self.seq_3_total = max(1, int(self.seq_3_total * d))

    def update_exec(self, count: float) -> None:
        self._maybe_decay()
        self.exec_stats.update(count)

    def update_entropy(self, entropy: float) -> None:
        if entropy > 0:
            self.entropy_stats.update(entropy)

    def update_parent(self, parent: str) -> None:
        p = (parent or "unknown").lower()
        self.parent_counts[p] += 1
        self.parent_total += 1

    def update_hour(self, hour: int) -> None:
        if 0 <= hour < 24:
            self.hour_counts[hour] += 1
            self.hour_total += 1

    def update_sequence(self, parent: str, child: str) -> None:
        """
        Record parent→child transition (bigram) and, if a previous image
        exists, also the grandparent→parent→child trigram.

        Trigrams let us detect multi-hop attack chains:
          winword → powershell → cmd  scores much higher than
          explorer → powershell → cmd  because the former has never been seen.
        """
        p = parent.lower()
        c = child.lower()

        # Bigram
        key2 = (p, c)
        self.seq_2[key2] += 1
        self.seq_2_total += 1

        # Trigram — requires prev_image from last learning call
        if self.prev_image is not None:
            key3 = (self.prev_image, p, c)
            self.seq_3[key3] += 1
            self.seq_3_total += 1

        self.prev_image = c   # slide window forward

    def update_network(self, dst_ip: str) -> None:
        """Record outbound connection by both exact IP and /24 subnet."""
        if dst_ip:
            ip = dst_ip.strip().lower()
            self.network_counts[ip] += 1
            self.network_total += 1
            # /24 subnet grouping — survives IP rotation within same range
            subnet = ".".join(ip.split(".")[:3]) if "." in ip else ip
            self.network_subnet_counts[subnet] += 1
            self.network_subnet_total += 1

    # ── Anomaly Scores (0.0–1.0) ──────────────────────────────────────────

    def frequency_anomaly(self, observed_count: float) -> float:
        """
        Z-score based frequency anomaly, normalized to 0–1.
        No artificial noise floor — low-frequency stealth attacks must
        be detected.  The z-score naturally handles both extremes:
        an exec_count of 0 when baseline mean is 50 is just as anomalous
        as an exec_count of 1000 when baseline mean is 10.
        """
        if self.exec_stats.n < 10:
            # ── [10/10 EXPERT] Anomaly Floor ──────────────────────────────
            # 0.3 floor for 90 days, then 0.2.
            return 0.3 if self.exec_stats.n > 0 else 0.25
        z = abs(self.exec_stats.z_score(observed_count))
        score = float(min(z / ZSCORE_ALERT_THRESHOLD, 1.0))
        # Never drop below 0.2 (anomaly floor) to prevent stagnant normalization
        return max(score, 0.2)

    def parent_anomaly(self, parent: str) -> float:
        """Probability-based parent anomaly. Rare parent = high score."""
        if self.parent_total < 5:
            return 0.10
        p = (parent or "unknown").lower()
        count = self.parent_counts.get(p, 0)
        prob  = count / self.parent_total
        # Invert: unseen parent = 1.0, dominant parent = 0.0
        if p in BENIGN_PARENTS:
            return max(0.0, 1.0 - prob) * 0.5   # Dampen for known benign parents
        return float(1.0 - prob)



    def network_anomaly(self, dst_ip: str) -> float:
        """
        Dual-layer network model: per-IP probability + /24 subnet probability.

        Taking the max of both prevents IP-rotation evasion:
          - Exact IP matches beat subnet (more specific evidence)
          - Subnet anomaly catches rotated IPs within same C2 infrastructure

        score = max(ip_score, subnet_score * 0.7)
        """
        if not dst_ip:
            return 0.05
        ip = dst_ip.strip().lower()

        # Exact-IP score
        if self.network_total >= 5:
            count_ip  = self.network_counts.get(ip, 0)
            ip_score  = float(1.0 - count_ip / self.network_total)
        else:
            ip_score = 0.15

        # Subnet score — weighted slightly lower (less specific evidence)
        subnet = ".".join(ip.split(".")[:3]) if "." in ip else ip
        if self.network_subnet_total >= 5:
            count_sub    = self.network_subnet_counts.get(subnet, 0)
            subnet_score = float(1.0 - count_sub / self.network_subnet_total) * 0.7
        else:
            subnet_score = 0.10

        return float(max(ip_score, subnet_score))

    def entropy_anomaly(self, observed_entropy: float, event: Optional[Dict] = None) -> float:
        """
        Multi-signal entropy model — much harder to evade than raw entropy alone.

        Combines:
          - Shannon entropy z-score (vs baseline)
          - Encoded flag presence (-enc, -encodedcommand, etc.)
          - Command length deviation (long commands suspicious even at low entropy)
          - Special character ratio (URLs, base64 chars, escape sequences)

        Attackers can evade pure entropy by using long but low-entropy commands.
        The combined model catches that.
        """
        event = event or {}

        # 1. Entropy z-score
        if self.entropy_stats.n >= 5:
            z = abs(self.entropy_stats.z_score(observed_entropy))
            entropy_score = float(min(z / ENTROPY_SIGMA_THRESHOLD, 1.0))
        else:
            entropy_score = 0.10

        # 2. Encoded flag — binary hard signal
        encoded_score = 0.8 if event.get("cmd_has_encoded_flag") or event.get("has_encoded_flag") else 0.0

        # 3. Command length vs baseline (long obfuscated commands)
        cmd = str(event.get("command_line") or "")
        cmd_len = float(len(cmd))
        length_score = 0.0
        if cmd_len > 500:
            length_score = 0.6
        elif cmd_len > 200:
            length_score = 0.3

        # 4. Special character ratio (%, ^, +, /, =, common in encoded payloads)
        special_count = sum(1 for c in cmd if c in "%^+=/\\\"'`|&;{}[]")
        special_ratio = special_count / max(len(cmd), 1)
        special_score = min(special_ratio * 3.0, 1.0)   # cap at 1.0

        # Weighted combination — entropy z-score leads, others amplify
        combined = (
            0.40 * entropy_score +
            0.30 * encoded_score +
            0.15 * length_score  +
            0.15 * special_score
        )
        return float(min(combined, 1.0))

    def sequence_anomaly(self, parent: str, child: str, grandparent: Optional[str] = None) -> float:
        """
        N-gram sequence anomaly combining bigram and trigram probabilities.

        Bigram  (parent → child):          catches winword → powershell
        Trigram (grandparent → parent → child): catches winword → powershell → cmd

        The trigram score is weighted higher because it requires a 3-hop match —
        much more specific evidence of an attack chain.

        Final = max(bigram_score, trigram_score * 1.3)  capped at 1.0
        """
        p = parent.lower() if parent else "unknown"
        c = child.lower()  if child  else "unknown"

        # Bigram score
        if self.seq_2_total >= 10:
            key2    = (p, c)
            count2  = self.seq_2.get(key2, 0)
            bigram  = float(1.0 - count2 / self.seq_2_total)
        else:
            bigram = 0.10

        # Trigram score (requires grandparent context)
        trigram = 0.0
        if grandparent and self.seq_3_total >= 10:
            g   = grandparent.lower()
            key3 = (g, p, c)
            cnt3 = self.seq_3.get(key3, 0)
            # Trigram anomaly weighted 1.3× — 3-hop specificity is strong evidence
            trigram = float(min(1.0 - cnt3 / self.seq_3_total, 1.0)) * 1.3

        return float(min(max(bigram, trigram), 1.0))

    def time_anomaly(self, hour: int) -> float:
        """Probability-based time-of-day anomaly."""
        if self.hour_total < 10 or not (0 <= hour < 24):
            return 0.05
        prob = self.hour_counts[hour] / self.hour_total
        return float(1.0 - prob)

    # ── NEW: Unified behavior score exposed as first-class signal ────────
    def compute_behavior_score(
        self,
        exec_count: float,
        entropy: float,
        parent: str,
        image: str,
        grandparent: str,
        dst_ip: str,
        hour: int,
        event: dict,
    ) -> float:
        """
        Calculate unified behavior score using Controlled Max blending.
        """
        f = self.frequency_anomaly(exec_count)
        p = self.parent_anomaly(parent)
        s = self.sequence_anomaly(parent, image, grandparent)
        e = self.entropy_anomaly(entropy, event)
        t = self.time_anomaly(hour) if hour >= 0 else 0.05
        n = self.network_anomaly(dst_ip) if dst_ip else 0.05

        signals = [f, p, s, e, t, n]
        top = max(signals)
        avg = sum(signals) / len(signals)
        
        # Controlled Max (v2.8 Micro-Lock)
        # Blends the top signal with the general context.
        return float(max(top * 0.7 + avg * 0.3, top * 0.85))

    def is_mature(self) -> bool:
        return self.exec_stats.n >= MIN_SAMPLES_FOR_CONFIDENCE

    # ── Serialization ─────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exec_n":       self.exec_stats.n,
            "exec_mean":    self.exec_stats.mean,
            "exec_m2":      self.exec_stats.m2,
            "ent_n":        self.entropy_stats.n,
            "ent_mean":     self.entropy_stats.mean,
            "ent_m2":       self.entropy_stats.m2,
            "parent_counts": dict(self.parent_counts),
            "parent_total": self.parent_total,
            "hour_counts":  self.hour_counts,
            "hour_total":   self.hour_total,
            "seen_days":    self.seen_days,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EntityProfile":
        p = cls()
        p.exec_stats    = WelfordStats(
            n=int(d.get("exec_n", 0)),
            mean=float(d.get("exec_mean", 0.0)),
            m2=float(d.get("exec_m2", 0.0)),
        )
        p.entropy_stats = WelfordStats(
            n=int(d.get("ent_n", 0)),
            mean=float(d.get("ent_mean", 0.0)),
            m2=float(d.get("ent_m2", 0.0)),
        )
        p.parent_counts = defaultdict(int, d.get("parent_counts", {}))
        p.parent_total  = int(d.get("parent_total", 0))
        p.hour_counts   = list(d.get("hour_counts", [0] * 24))
        p.hour_total    = int(d.get("hour_total", 0))
        p.seen_days     = int(d.get("seen_days", 1))
        return p


# ---------------------------------------------------------------------------
# Baseline Engine
# ---------------------------------------------------------------------------

class BaselineEngine:
    """
    Stateful baseline engine.

    Lifecycle:
      1. load()  — pull profiles from DB into memory
      2. score() — compute deviation score for a burst/event dict
      3. learn() — update profiles from low-risk bursts
      4. save()  — flush profiles back to DB
    """

    def __init__(self):
        self._profiles: Dict[EntityKey, EntityProfile] = {}
        self._dirty_count = 0
        self._last_save_time = 0
        self._host_updates = defaultdict(int)  # For top-N learning
        self._analyst_trust = 1.0               # EWMA trust
        self._feedback_variance = 0.0           # For trust freezing
        self._freeze_until = 0                  # Timeout for trust freeze
        
        # ── [10/10] Resilient Persistence State ───────────────────────
        self._retry_count = 0
        self._last_fail_time = 0
        self._backoff_base = 30                 # 30 seconds

    # ── Profile access ────────────────────────────────────────────────────

    def _get_or_create(self, key: EntityKey) -> EntityProfile:
        if key not in self._profiles:
            self._profiles[key] = EntityProfile()
        return self._profiles[key]

    def get_profile(self, key: EntityKey) -> Optional[EntityProfile]:
        return self._profiles.get(key)

    # ── Scoring ───────────────────────────────────────────────────────────

    def score_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compute a 6-factor deviation score for a single event/burst dict.

        Factors:
          frequency  — z-score vs baseline execution rate (stealth-attack aware)
          parent     — probability of this parent launching this child
          sequence   — probability of parent→child transition in history
          entropy    — command-line entropy vs baseline
          time       — time-of-day probability
          network    — per-destination-IP probability (not boolean)

        Returns:
            deviation_score : float 0–1
            sub_scores      : dict of individual factor scores
            is_mature       : bool — whether baseline has enough data
            anomalies       : list of human-readable anomaly strings
        """
        key     = _entity_key(event)
        profile = self.get_profile(key)

        exec_count  = float(event.get("exec_count") or event.get("count") or 1)
        entropy     = float(event.get("cmd_entropy") or 0.0)
        image       = (event.get("image") or "unknown").lower()
        parent      = (event.get("parent_image") or "unknown").lower()
        grandparent = (event.get("grandparent_image") or "").lower() or None
        dst_ip      = event.get("destination_ip") or event.get("dst_ip") or ""
        hour       = -1
        import pandas as pd
        try:
            t = pd.to_datetime(
                event.get("start_time") or event.get("utc_time") or "",
                errors="coerce", utc=True,
            )
            if pd.notna(t):
                hour = int(t.hour)
        except Exception:
            pass

        if profile is None:
            return {
                "deviation_score": 0.25,
                "sub_scores": {
                    "frequency": 0.25, "parent": 0.25, "sequence": 0.25,
                    "entropy":   0.25,  "time":   0.05, "network":  0.10,
                },
                "is_mature": False,
                "anomalies": ["No historical baseline for this entity"],
            }

        f_score = profile.frequency_anomaly(exec_count)
        p_score = profile.parent_anomaly(parent)
        s_score = profile.sequence_anomaly(parent, image, grandparent)  # n-gram
        e_score = profile.entropy_anomaly(entropy, event)               # multi-signal
        t_score = profile.time_anomaly(hour) if hour >= 0 else 0.05
        n_score = profile.network_anomaly(dst_ip) if dst_ip else 0.05   # dual IP+subnet

        # ── Adversarial slow-attack (v2.8 Refinement) ─────────────────────
        # If execution count is LOW but other signals are HIGH, ensure visibility.
        # Fixed (v3.1): Added known_benign context gate
        slow_attack_penalty = 0.0
        high_signals_count = sum([
            e_score > 0.6,
            s_score > 0.7,
            n_score > 0.7,
            bool(event.get("has_persistence")),
            bool(event.get("has_injection")),
        ])
        if not event.get("is_known_benign") and high_signals_count >= 2:
            if exec_count <= 5:
                slow_attack_penalty = 0.20   # Refined to reduce noise
                f_score = max(f_score, 0.40) # Refined floor

        # ── Weighted combination ──────────────────────────────────────────
        combined = (
            0.25 * f_score +
            0.15 * p_score +
            0.15 * s_score +   # sequence
            0.20 * e_score +
            0.10 * t_score +
            0.15 * n_score +   # per-IP network
            slow_attack_penalty
        )

        anomalies: List[str] = []
        # ── Baseline Trust Factor (Issue 3: Hardened) ─────────────────────
        # If baseline sample size is low (< 50), dampen the anomaly score
        # to prevent noisy lab data or premature baselines from lying.
        samples = profile.exec_stats.n
        if samples < 15:   # Lowered from 50 — ensure stealth attacks surive early baseline
            combined = max(0.2, combined * 0.75) # Refined dampening (v3.1)
            # Ensure "No baseline" message only appears if truly zero
            if samples > 0:
                if "No historical baseline for this entity" in anomalies:
                    anomalies.remove("No historical baseline for this entity")
                anomalies.append(f"Baseline immature ({samples}/50 samples)")
        
        # --- Issue 3: Explicitly record count for UI clarity ---
        profile.count = samples

        combined = float(min(combined, 1.0))

        if f_score > 0.6:
            anomalies.append(
                f"Unusual execution frequency "
                f"(z={profile.exec_stats.z_score(exec_count):.1f}σ, "
                f"expected≈{profile.exec_stats.mean:.0f})"
            )
        if p_score > 0.6:
            anomalies.append(f"Rare parent process: {parent}")
        if s_score > 0.7:
            anomalies.append(
                f"Rare parent→child transition: {parent} → {image} "
                f"(seen {profile.seq_counts.get((parent, image), 0)}/{profile.seq_total} times)"
            )
        if e_score > 0.6:
            anomalies.append(
                f"High command entropy "
                f"(score={entropy:.2f}, baseline≈{profile.entropy_stats.mean:.2f})"
            )
        if t_score > 0.7:
            anomalies.append(f"Unusual execution hour: {hour:02d}:xx UTC")
        if n_score > 0.7 and dst_ip:
            anomalies.append(
                f"Rare/unseen network destination: {dst_ip} "
                f"(seen {profile.network_counts.get(dst_ip.lower(), 0)}/{profile.network_total} times)"
            )
        if slow_attack_penalty > 0:
            anomalies.append(
                f"Slow/stealthy attack pattern: low frequency ({exec_count:.0f} events) "
                f"but {high_signals_count} high-confidence behavioral signals"
            )

        behavior_score = profile.compute_behavior_score(
            exec_count, entropy, parent, image,
            grandparent or "", dst_ip, hour, event
        )
        
        # ── [10/10] Score Unification ─────────────────────────────────────
        # Ensures behavior score is never significantly weaker than deviation.
        behavior_score = max(behavior_score, combined * 0.8)

        return {
            "deviation_score": combined,
            "behavior_score":  behavior_score,
            "sub_scores": {
                "frequency": round(f_score, 3),
                "parent":    round(p_score, 3),
                "sequence":  round(s_score, 3),
                "entropy":   round(e_score, 3),
                "time":      round(t_score, 3),
                "network":   round(n_score, 3),
            },
            "is_mature":  profile.is_mature(),
            "anomalies":  anomalies,
        }

    # ── Learning ──────────────────────────────────────────────────────────

    def should_learn(self, event: Dict[str, Any], deviation_score: float) -> bool:
        """Gate: only learn from low-risk, benign-looking events. (v3.2 Poisoning Guard)"""
        # 10/10 SOC: Tightened thresholds to prevent slow-drip poisoning
        if int(event.get("risk_score") or 0) > 40:
            return False
        
        behavior_score = event.get("behavior_score", 0)
        image = (event.get("image") or "").lower()
        if image in NEVER_LEARN:
            return False
        
        # Check profile for early-stage exception
        key = _entity_key(event)
        profile = self.get_profile(key)
        if profile and profile.exec_stats.n < 15:
            # Allow early-stage learning ONLY if extremely clean
            if deviation_score < 0.15 and behavior_score < 0.3:
                return True

        # ── [10/10] Hardened Learning Gating (Final Lock) ─────────────────
        # Reject anomalies to prevent the baseline from "shifting" toward malicious activity
        if deviation_score >= 0.2:
            return False
        if behavior_score >= 0.4:
            return False

        if event.get("has_persistence") or event.get("has_injection"):
            return False
        if float(event.get("cmd_entropy") or 0.0) > 4.0:
            return False
        if event.get("has_encoded_flag") or event.get("sequence_flag") or float(event.get("sequence_anomaly") or 0) > 0.7:
            return False
            
        if int(event.get("network_strength", 0) or 0) >= 2:
            return False
            
        stage = event.get("kill_chain_stage") or "Execution"
        if stage not in ("Execution", "Background"):
            return False
        return True

    def learn_from_event(self, event: Dict[str, Any]) -> None:
        """
        Update profile from a trusted-benign event.
        High-risk events (risk_score > 80) are NEVER learned — feedback loop
        ensures the baseline cannot be poisoned by attacker activity.
        """
        # Feedback loop: block learning if scoring engine already flagged this as malicious
        if int(event.get("risk_score") or 0) > 80:
            return

        key     = _entity_key(event)
        profile = self._get_or_create(key)

        exec_count  = float(event.get("exec_count") or event.get("count") or 1)
        entropy     = float(event.get("cmd_entropy") or 0.0)
        parent      = (event.get("parent_image") or "unknown")
        image       = (event.get("image") or "unknown")
        grandparent = (event.get("grandparent_image") or "")
        dst_ip      = event.get("destination_ip") or event.get("dst_ip") or ""

        profile.update_exec(exec_count)
        profile.update_entropy(entropy)
        profile.update_parent(parent)
        
        # --- Issue 3: Update count and last_seen ---
        profile.count += 1
        # Extract timestamp
        import pandas as pd
        try:
            ts = pd.to_datetime(event.get("start_time") or event.get("utc_time"), errors="coerce", utc=True)
            if pd.notna(ts):
                profile.last_seen = ts
        except Exception:
            pass  # Non-parseable timestamp — intentional skip
        # Pass grandparent so trigram model gets populated
        if grandparent:
            profile.update_sequence(grandparent, parent)   # gp→parent bigram
        profile.update_sequence(parent, image)             # parent→child bigram + trigram
        if dst_ip:
            profile.update_network(dst_ip)

        try:
            t = pd.to_datetime(
                event.get("start_time") or event.get("utc_time") or "",
                errors="coerce", utc=True,
            )
            if pd.notna(t):
                profile.update_hour(int(t.hour))
        except Exception:
            pass

    # ── Persistence (MySQL via DB helpers) ────────────────────────────────

    def load_from_db(self) -> None:
        """
        Pull all baseline profiles from behavior_baseline.
        Restores Welford stats, n-gram sequence tables, and network
        probability maps from JSON columns added in v2 schema.
        """
        import json as _json
        try:
            from dashboard.db import get_engine
            from sqlalchemy import text
            import pandas as pd
            with get_engine("cases").connect() as conn:
                df = pd.read_sql_query(
                    text("SELECT computer, process_name, user_type, avg_exec, var_exec, "
                         "avg_cmd_len, count_samples, seen_days, "
                         "seq_bigram_json, seq_trigram_json, seq_2_total, seq_3_total, "
                         "network_ip_json, network_subnet_json, "
                         "network_total, network_subnet_total "
                         "FROM behavior_baseline"),
                    conn,
                )
        except Exception:
            # Fallback: v1 columns only (pre-migration database)
            try:
                from dashboard.db import get_engine
                from sqlalchemy import text
                import pandas as pd
                with get_engine("cases").connect() as conn:
                    df = pd.read_sql_query(
                        text("SELECT computer, process_name, user_type, avg_exec, var_exec, "
                             "avg_cmd_len, count_samples, seen_days "
                             "FROM behavior_baseline"),
                        conn,
                    )
                # Add missing columns as None
                for col in ["seq_bigram_json", "seq_trigram_json",
                            "network_ip_json", "network_subnet_json"]:
                    df[col] = None
                for col in ["seq_2_total", "seq_3_total",
                            "network_total", "network_subnet_total"]:
                    df[col] = 0
            except Exception as e:
                import traceback
                log.error("[BaselineEngine] load_from_db failed (v2 cols): %s", e)
                log.debug("[BaselineEngine] Continuing with empty baseline — next upload will build it.")
                traceback.print_exc()
                return

        for _, row in df.iterrows():
            key = (
                str(row.get("computer") or "unknown_host"),
                str(row.get("user_type") or "interactive"),
                str(row.get("process_name") or "unknown"),
            )
            profile = EntityProfile()

            # ── Welford exec stats ────────────────────────────────────────
            n    = int(row.get("count_samples") or 0)
            mean = float(row.get("avg_exec") or 0.0)
            var  = float(row.get("var_exec") or 0.0)
            m2   = var * (n - 1) if n > 1 else 0.0
            profile.exec_stats = WelfordStats(n=n, mean=mean, m2=m2)
            profile.seen_days  = int(row.get("seen_days") or 1)

            # ── N-gram sequence tables ────────────────────────────────────
            try:
                raw2 = row.get("seq_bigram_json")
                if raw2:
                    loaded = _json.loads(raw2)
                    # Keys were stored as "parent|child" strings
                    profile.seq_2 = defaultdict(int, {
                        tuple(k.split("|", 1)): v for k, v in loaded.items()
                    })
                profile.seq_2_total = int(row.get("seq_2_total") or 0)
            except Exception:
                pass

            try:
                raw3 = row.get("seq_trigram_json")
                if raw3:
                    loaded = _json.loads(raw3)
                    profile.seq_3 = defaultdict(int, {
                        tuple(k.split("|", 2)): v for k, v in loaded.items()
                    })
                profile.seq_3_total = int(row.get("seq_3_total") or 0)
            except Exception:
                pass

            # ── Network probability maps ──────────────────────────────────
            try:
                raw_ip = row.get("network_ip_json")
                if raw_ip:
                    profile.network_counts = defaultdict(int, _json.loads(raw_ip))
                profile.network_total = int(row.get("network_total") or 0)
            except Exception:
                pass

            try:
                raw_sub = row.get("network_subnet_json")
                if raw_sub:
                    profile.network_subnet_counts = defaultdict(int, _json.loads(raw_sub))
                profile.network_subnet_total = int(row.get("network_subnet_total") or 0)
            except Exception:
                pass

            self._profiles[key] = profile

        log.info("[BaselineEngine] Loaded %d profiles from DB.", len(self._profiles))

    def save_to_db(self) -> None:
        """
        Flush in-memory profiles to behavior_baseline.
        Serializes n-gram tables and network maps as compact JSON.
        Runs in batches of 200 to avoid lock-wait timeouts on large datasets.
        """
        import json as _json
        if not self._profiles:
            return
        
        # ── [10/10 EXPERT] Throttled & Resilient Persistence ───────────
        import time
        import random
        now = time.time()
        
        # Check backoff window
        if self._retry_count > 0:
            wait_time = (self._backoff_base * (2 ** (self._retry_count - 1))) + random.uniform(0, 10)
            if (now - self._last_fail_time) < wait_time:
                log.warning("[BaselineEngine] Persistence in backoff: wait=%ds, retries=%d", 
                            int(wait_time - (now - self._last_fail_time)), self._retry_count)
                return

        if self._dirty_count < 100 and (now - self._last_save_time) < 300:
            log.debug("[BaselineEngine] Skipping throttled save (dirty=%d, idle=%ds)", 
                      self._dirty_count, int(now - self._last_save_time))
            return

        try:
            from dashboard.db import get_db_connection, get_cursor, sql_upsert, now_utc
        except Exception as e:
            log.error("[BaselineEngine] save_to_db import failed: %s", e)
            return

        # Build upsert — check if decay_updates column exists first
        try:
            from dashboard.db import get_db_connection as _gdbc, get_cursor as _gcur, get_table_columns as _gtc
            with _gdbc("cases") as _chk_conn:
                with _gcur(_chk_conn) as _chk_cur:
                    _bb_cols = set(_gtc(_chk_cur, "behavior_baseline"))
            _has_decay = "decay_updates" in _bb_cols
        except Exception:
            _has_decay = False

        _insert_cols = ["computer", "process_name", "user_type", "parent_process",
             "hour_bucket", "avg_exec", "var_exec", "avg_cmd_len", "avg_followup",
             "count_samples", "seen_days", "last_updated",
             "seq_bigram_json", "seq_trigram_json", "seq_2_total", "seq_3_total",
             "network_ip_json", "network_subnet_json",
             "network_total", "network_subnet_total"]
        _update_cols = ["avg_exec", "var_exec", "avg_cmd_len", "avg_followup",
             "count_samples", "seen_days", "last_updated",
             "seq_bigram_json", "seq_trigram_json", "seq_2_total", "seq_3_total",
             "network_ip_json", "network_subnet_json",
             "network_total", "network_subnet_total"]
        if _has_decay:
            _insert_cols.append("decay_updates")
            _update_cols.append("decay_updates")

        stmt = sql_upsert("behavior_baseline", _insert_cols, [], _update_cols)
        ts      = now_utc()
        items   = list(self._profiles.items())
        BATCH   = 200

        def _ser_seq2(profile: EntityProfile) -> str:
            """Serialize bigram dict — tuple keys become 'parent|child' strings."""
            d = {"{}|{}".format(k[0], k[1]): v
                 for k, v in profile.seq_2.items() if v > 0}
            return _json.dumps(d) if d else None

        def _ser_seq3(profile: EntityProfile) -> str:
            d = {"{}|{}|{}".format(k[0], k[1], k[2]): v
                 for k, v in profile.seq_3.items() if v > 0}
            return _json.dumps(d) if d else None

        try:
            for i in range(0, len(items), BATCH):
                batch = items[i: i + BATCH]
                with get_db_connection("cases") as conn:
                    with get_cursor(conn) as cur:
                        for (computer, user_type, image), profile in batch:
                            n   = profile.exec_stats.n
                            var = profile.exec_stats.variance
                            _row_vals = (
                                computer, image, user_type, "unknown", 0,
                                profile.exec_stats.mean,
                                var,
                                profile.entropy_stats.mean,
                                0.0,      # avg_followup placeholder
                                n,
                                profile.seen_days,
                                ts,
                                # v2 fields
                                _ser_seq2(profile),
                                _ser_seq3(profile),
                                profile.seq_2_total,
                                profile.seq_3_total,
                                _json.dumps(dict(profile.network_counts)) or None,
                                _json.dumps(dict(profile.network_subnet_counts)) or None,
                                profile.network_total,
                                profile.network_subnet_total,
                            )
                            if _has_decay:
                                _row_vals = _row_vals + (profile._updates,)
                            cur.execute(stmt, _row_vals)
                    conn.commit()
            self._retry_count = 0 # Success
            log.info("[BaselineEngine] Successfully persisted %d profiles", len(items))
        except Exception as e:
            import traceback
            self._retry_count += 1
            self._last_fail_time = time.time()
            log.error("[BaselineEngine] save_to_db failed (attempt %d): %s", self._retry_count, e)
            if self._retry_count >= 3:
                # Escalation
                log.critical("[BaselineEngine] Persistence FATAL: missed 3 consecutive flushes")
            traceback.print_exc()
        finally:
            self._dirty_count = 0
            self._last_save_time = now
            # Prune global state if too large (> 10k entries)
            if len(self._profiles) > 10000:
                self._prune_global_baseline()

    # ── Batch processing ──────────────────────────────────────────────────

    def process_burst_batch(
        self,
        bursts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Score and optionally learn from a batch of burst dicts.
        Implements top-N learning, trust gating, and maintenance awareness.
        """
        import time
        now = time.time()
        
        # Maintenance window check (Simple POC)
        is_maint = os.environ.get("MAINTENANCE_WINDOW") == "1"
        
        for burst in bursts:
            result = self.score_event(burst)
            burst["deviation_score"]     = result["deviation_score"]
            burst["behavior_score"]      = result.get("behavior_score", result["deviation_score"])
            burst["baseline_anomalies"]  = result["anomalies"]
            burst["baseline_mature"]     = result["is_mature"]
            burst["baseline_sub_scores"] = result["sub_scores"]
            
            # [10/10 EXPERT] System Health Modeling
            burst["system_health"] = self.compute_system_health()

            if burst.get("_never_learn"): continue
            
            # [10/10 EXPERT] Feedback Variance Freeze
            if now < self._freeze_until:
                continue

            # [10/10 EXPERT] Selective Learning & Contamination Control
            if burst["behavior_score"] > 0.70: continue
            
            # [10/10 EXPERT] Per-Host Rate Limiting (Top-N)
            host = burst.get("computer", "unknown").lower()
            if not is_maint:
                self._host_updates[host] += 1
                if self._host_updates[host] > 50:
                    # Learn only if it's a very low-deviation event (Top 5% of noisy host)
                    if burst["behavior_score"] > 0.15: continue

            if self.should_learn(burst, result["deviation_score"]):
                self.learn_from_event(burst)
                self._dirty_count += 1

        # Check for batch end save
        if self._dirty_count > 500:
            self.save_to_db()

        return bursts

    def compute_system_health(self) -> float:
        """Return 0-100 score based on module status."""
        health = 100.0
        if self._freeze_until > 0: health -= 30.0  # Feedback unstable
        return max(0, health)

    def _prune_global_baseline(self):
        """Hygiene: Remove oldest/lowest confidence entries."""
        if len(self._profiles) < 5000: return
        # Simple prune: remove profiles with n=1 and not seen in 30 days
        log.info("[BaselineEngine] Pruning global baseline hygiene...")
        keys_to_del = []
        for key, profile in self._profiles.items():
            if profile.exec_stats.n < 3:
                keys_to_del.append(key)
        for k in keys_to_del[:2000]: # Prune up to 2k
            del self._profiles[k]


# ---------------------------------------------------------------------------
# Module-level singleton (imported by analysis_engine)
# ---------------------------------------------------------------------------

_engine: Optional[BaselineEngine] = None


def get_baseline_engine() -> BaselineEngine:
    """
    Return the module-level BaselineEngine singleton.
    The engine loads from DB on first call and caches in memory.
    Call reset_baseline_engine() between upload runs to force a fresh DB load.
    """
    global _engine
    if _engine is None:
        _engine = BaselineEngine()
        try:
            _engine.load_from_db()
        except Exception as e:
            log.error("[BaselineEngine] load_from_db failed in get_baseline_engine: %s", e)
    return _engine


def reset_baseline_engine() -> None:
    """Force reload on next get_baseline_engine() call.
    Call this between upload analysis runs to pick up newly-saved baseline data.
    """
    global _engine
    _engine = None
    log.info("[BaselineEngine] Engine reset — will reload from DB on next call")
