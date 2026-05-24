import math
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
import datetime


log = logging.getLogger(__name__)

# --- SOC-Grade Configuration (v2.8) ---
# Absolute hierarchy: Burst -> Campaign -> Global NO FEEDBACK
TRUSTED_PARENTS = {
    "explorer.exe",
    "services.exe",
    "svchost.exe",
    "wininit.exe",
    "lsass.exe",
    "smss.exe",
    "csrss.exe",
    "winlogon.exe"
}

@dataclass
class LedgerEntry:
    label: str
    delta: float
    explanation: str
    category: str = "general"

    def to_dict(self):
        return {
            "label": self.label,
            "delta": round(self.delta, 2),
            "reason": self.explanation,
            "category": self.category
        }

@dataclass
class ScoreResult:
    score: float
    ledger: List[LedgerEntry] = field(default_factory=list)
    confidence_modifier: float = 1.0
    primary_driver: str = "rule"
    severity: str = "low"
    # Added for compatibility with pipeline expectations
    stage_cap: float = 100.0
    chain_multiplier: float = 1.0
    
    def __post_init__(self):
        # SOC-Grade Severity Mapping (relaxed thresholds for real-world attack elevation)
        if self.score >= 70.0: self.severity = "high"
        elif self.score >= 40.0: self.severity = "medium"
        elif self.score > 0: self.severity = "low"
        else: self.severity = "informational"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "primary_driver": self.primary_driver,
            "confidence_modifier": self.confidence_modifier,
            "ledger": [e.to_dict() for e in self.ledger],
            "why": [f"• {e.label}: {e.explanation}" for e in self.ledger if abs(e.delta) > 0.1]
        }

class ScoringEngine:
    """
    Production-grade Unified Risk Engine (v2.8).
    Implements contribution-based labeling, stability-locking, and adversarial resilience.
    """
    def __init__(self):
        # Local state-based tracking for accumulation (ephemeral per session)
        self.history = {} # host -> {image: [timestamps]}
        self.last_seen = {} # host -> {image: last_time}
        self.global_user_history = {} # user -> {computers}

    def score_burst(self, burst: Dict[str, Any], detections: List[Dict[str, Any]], 
                    sequence_detections: List[Dict[str, Any]] = None,
                    behavior_score: float = None,
                    chain_depth: int = 1,
                    now: datetime.datetime = None) -> ScoreResult:
        """
        Calculates a SOC-grade risk score (0-100) using multi-signal fusion.
        """
        if now is None:
            now = datetime.datetime.now(datetime.timezone.utc)
            
        ledger = []
        image = str(burst.get("image") or "unknown").lower()
        computer = str(burst.get("computer") or "unknown").lower()
        user = str(burst.get("user") or "unknown").lower()
        parent_image = str(burst.get("parent_image") or "").lower()
        prior_hosts = self.global_user_history.setdefault(user, set())
        prior_images = self.history.setdefault(computer, {})
        image_history = prior_images.setdefault(image, [])
        unique_rule_ids: Set[str] = set()
        unique_tactics: Set[str] = set()
        
        # ── 1. BASE SIGNALS (Static Rule Weights) ──
        rule_score = 0.0
        for det in (detections or []):
            # Avoid inflating scores with an arbitrary default — treat missing
            # confidence as 0 and use a nonlinear mapping to amplify high-confidence
            # signals while suppressing noisy low-confidence hits.
            conf = float(det.get("confidence") or det.get("confidence_score") or 0.0)
            sev = str(det.get("severity") or "medium").lower()
            rule_id = str(det.get("rule_id") or det.get("rule_name") or "").strip().lower()
            tactic = str(det.get("mitre_tactic") or det.get("kill_chain_stage") or "").strip().lower()
            if rule_id:
                unique_rule_ids.add(rule_id)
            if tactic:
                unique_tactics.add(tactic)
            
            # Graded severity weight
            sev_weight = 1.0
            if sev == "critical": sev_weight = 1.8
            elif sev == "high": sev_weight = 1.5
            elif sev == "medium": sev_weight = 1.0
            elif sev == "low": sev_weight = 0.6
            
            # Nonlinear confidence mapping: emphasize high-confidence hits
            # Tuned: slightly soften exponent and base multiplier to reduce score flattening
            conf_norm = max(0.0, min(100.0, conf)) / 100.0
            # Lowered base multiplier from 35.0 -> 22.0 to reduce systemic score inflation
            delta = (conf_norm ** 1.2) * 22.0 * sev_weight
            rule_score += delta
            ledger.append(LedgerEntry(f"Rule: {det.get('rule_name')}", delta, f"Static detection {det.get('rule_id', 'N/A')}", "rule"))

        # ── 2. SEQUENCE SIGNALS (DOMINANT — strongest SOC signal) ──
        sequence_score = 0.0
        for seq in (sequence_detections or []):
            s_conf = float(seq.get("confidence", 0))
            s_norm = max(0.0, min(100.0, s_conf)) / 100.0
            # Sequence hits are significant; tuned to avoid override inflation
            # Reduced multiplier from 45.0 -> 28.0
            delta = (s_norm ** 1.2) * 28.0
            sequence_score += delta
            ledger.append(LedgerEntry(f"Sequence: {seq.get('sequence_type')}", delta, "Attack pattern match", "sequence"))

            if s_conf >= 80:
                # Smaller high-confidence bump to limit single-source dominance
                ledger.append(LedgerEntry(
                    "High-confidence attack chain",
                    12.0,
                    "Strong sequence detection override",
                    "sequence"
                ))
                sequence_score += 12.0

        # ── 3. BEHAVIORAL INTELLIGENCE (BASELINE ENGINE) ──
        if behavior_score is None:
            behavior_score = float(burst.get("behavior_score", 0.0))
        
        samples = int(burst.get("baseline_maturity", 0))
        
        # Direct behavior boost (no stability dependency — consistent across environments)
        behavior_boost = (behavior_score * 30.0) + ((behavior_score ** 2) * 18.0)
        if behavior_score > 0.8:
            behavior_boost += 5.0
            
        if behavior_boost > 0.1:
            label = "Behavioral anomaly"
            if behavior_score > 0.7: label += " (HIGH)"
            ledger.append(LedgerEntry(label, behavior_boost, f"Anomalous execution profile (deviance {behavior_score:.2f})", "behavior"))

        # ── [9.6/10 Locked] Zero-Signal Integrity ───────────────────────────
        if rule_score == 0 and sequence_score == 0 and behavior_score == 0:
            return ScoreResult(
                score=0.0,
                ledger=[LedgerEntry("No detection signals", 0.0, "Baseline activity", "fallback")],
                primary_driver="benign"
            )

        # ── 4. RARITY & FIRST-SEEN (CONTEXTUAL) ──
        baseline_stats = burst.get("baseline_stats", {})
        host_stats = baseline_stats.get(computer, {})
        image_freq = int(host_stats.get(image, {}).get("count", 1))
        
        # Smooth Logarithmic Rarity Weight
        rarity_weight = 1.5 - (math.log10(max(1, image_freq) + 1) * 0.3)
        rarity_weight = max(0.6, min(1.5, rarity_weight))
        
        rarity_boost = 0.0
        if image_freq <= 3:
            rarity_boost = 10.0 * (1.5 - (image_freq * 0.1))
            ledger.append(LedgerEntry("Rare process context", rarity_boost, f"{image} seen {image_freq} times on host", "rarity"))
        elif image_freq > 100:
            ledger.append(LedgerEntry("Common process dampener", -5.0, f"{image} very common ({image_freq} executions)", "rarity"))

        # Conditional First-Seen execution (v2.8)
        first_seen_boost = 0.0
        if image_freq == 1 and behavior_score > 0.4:
            first_seen_boost = 10.0
            ledger.append(LedgerEntry("First-seen execution", 10.0, f"{image} executed for first time on host in suspicious context", "rarity"))

        # Diversity bonuses prevent one-dimensional scores from collapsing to the same value.
        detection_diversity = len(unique_rule_ids)
        tactic_diversity = len(unique_tactics)
        diversity_boost = 0.0
        if detection_diversity:
            diversity_boost += min(8.0, detection_diversity * 1.25)
        if tactic_diversity > 1:
            diversity_boost += min(8.0, (tactic_diversity - 1) * 2.5)
        if diversity_boost > 0.0:
            ledger.append(LedgerEntry(
                "Signal diversity",
                diversity_boost,
                f"{detection_diversity} unique rule(s) across {tactic_diversity} tactic bucket(s)",
                "correlation",
            ))

        # ── 5. CORRELATION AMPLIFICATION (CAMPAIGNS) ──
        corr_strength = max(0, float(burst.get("correlation_strength", 0.0)))
        corr_size = max(1, int(burst.get("correlation_size", 1)))
        
        # Nonlinear Capped Correlation (v3.0 — moderated weight for campaign visibility)
        corr_boost = (math.sqrt(max(0.0, corr_strength)) * 3.0) * min(1.5, math.log2(corr_size + 1))
        corr_boost = min(35.0, corr_boost)
        
        if corr_boost > 5.0:
            ledger.append(LedgerEntry("Campaign correlation", corr_boost, f"Linked to {corr_size} events (strength {corr_strength:.0f})", "correlation"))

        # ── 6. ADVERSARIAL RESILIENCE (STEALTH RULE) ──
        parent_trust = 0.9 if parent_image in TRUSTED_PARENTS else 0.1
        stealth_boost = 0.0
        
        # Micro-Lock: Gated by behavior + count + entropy + maturity + trust
        if (behavior_score > 0.75 and 
            int(burst.get("event_count", 0)) <= 5 and 
            (float(burst.get("cmd_entropy", 0)) > 4.0 or burst.get("has_encoded_flag") or float(burst.get("sequence_anomaly", 0)) > 0.7) and
            samples > 5 and 
            parent_trust < 0.5):
            
            stealth_boost = 15.0
            ledger.append(LedgerEntry("Stealth (Slow-Drip) Detection", 15.0, "Multi-dimensional stealth pattern match", "stealth"))

        # ── 7. ENVIRONMENT DRIFT ──
        drift = float(burst.get("host_baseline_drift", 0.0))
        drift_boost = 0.0
        if drift > 0.3:
            drift_boost = 10.0
            ledger.append(LedgerEntry("Environment drift", 10.0, "Host baseline behavior significantly changed recently", "behavior"))

        # ── 8. COMPOSITE INTEGRATION (Non-multiplicative Rarity v3.0) ──

        # Early LOLBin suspicious-context boost (MUST be before base_signals)
        image_name = image.split("\\")[-1]
        if image_name in ["powershell.exe", "cmd.exe", "wscript.exe"]:
            if burst.get("has_encoded_flag") or chain_depth >= 2 or sequence_score > 0:
                # Lower LOLBIN boost to reduce generic admin-tool inflation
                lolbin_boost = 8.0 if image_name in ["powershell.exe", "pwsh.exe"] else 5.0
                sequence_score += lolbin_boost
                ledger.append(LedgerEntry(
                    "Suspicious LOLBin usage",
                    lolbin_boost,
                    f"{image_name} used in suspicious context",
                    "rule"
                ))

        host_spread = max(1, int(burst.get("host_spread") or burst.get("campaign_host_count") or burst.get("host_count") or 1))
        temporal_span = float(burst.get("campaign_age_minutes") or burst.get("temporal_span_minutes") or 0.0)
        host_spread_boost = 0.0
        if host_spread > 1:
            host_spread_boost = min(12.0, math.log2(host_spread + 1) * 3.5)
            ledger.append(LedgerEntry(
                "Host spread",
                host_spread_boost,
                f"Activity spans {host_spread} host(s)",
                "correlation",
            ))

        temporal_density_boost = 0.0
        if temporal_span > 0:
            temporal_density_boost = min(10.0, 12.0 / max(1.0, math.log1p(temporal_span)))
            if temporal_density_boost > 1.0:
                ledger.append(LedgerEntry(
                    "Temporal density",
                    temporal_density_boost,
                    f"Campaign compressed into {temporal_span:.1f} minute(s)",
                    "sequence",
                ))

        context_bonus = 0.0
        if burst.get("has_persistence"):
            context_bonus += 10.0
        if burst.get("has_injection"):
            context_bonus += 16.0
        if burst.get("has_credential_access"):
            context_bonus += 14.0
        if burst.get("has_lateral_movement"):
            context_bonus += 12.0
        if burst.get("has_net"):
            context_bonus += 6.0
        if burst.get("has_encoded_flag"):
            context_bonus += 6.0
        if parent_trust < 0.5 and image_name in ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"]:
            context_bonus += 4.0

        campaign_memory_boost = 0.0
        if prior_hosts and computer not in prior_hosts:
            campaign_memory_boost = min(10.0, 2.5 + (len(prior_hosts) * 2.0))
            ledger.append(LedgerEntry(
                "Cross-host spread",
                campaign_memory_boost,
                f"User {user} now observed on {len(prior_hosts) + 1} host(s)",
                "correlation",
            ))
        prior_hosts.add(computer)

        repeat_context_boost = 0.0
        if image_history:
            repeat_context_boost = min(4.0, 0.5 * len(image_history))
            if repeat_context_boost > 0:
                ledger.append(LedgerEntry(
                    "Repeated context",
                    repeat_context_boost,
                    f"{image} has prior activity on {computer}",
                    "rarity",
                ))
        image_history.append(now.isoformat())

        base_signals = (
            rule_score
            + sequence_score
            + behavior_boost
            + corr_boost
            + stealth_boost
            + drift_boost
            + diversity_boost
            + host_spread_boost
            + temporal_density_boost
            + context_bonus
            + campaign_memory_boost
            + repeat_context_boost
        )
        
        event_count = int(burst.get("event_count") or 1)
        chain_factor = 1.0 + min(0.35, max(1, chain_depth) * 0.1)
        
        core_score = base_signals * chain_factor + (event_count * 0.5)
        rarity_component = (rarity_boost + first_seen_boost) * rarity_weight
        
        final = core_score + rarity_component

        # ── CHAIN DEPTH BOOST (multi-stage attack amplifier) ──
        if chain_depth >= 3:
            # Moderated multi-stage boost to prevent runaway amplification for synthetic chains
            final += 10.0
            ledger.append(LedgerEntry(
                "Multi-stage attack",
                10.0,
                f"Attack chain depth = {chain_depth}",
                "sequence"
            ))
        
        # ── 9. MATURITY & SOFT-START (v2.8) ──
        conf_mod = 1.0
        if samples < 5:
            penalty = 0.85
            conf_mod = 0.8  # Uncertainty flag for new hosts
            ledger.append(LedgerEntry("Confidence Dampener", 0.0, "Low host maturity (<5 samples) — reducing detection confidence", "baseline"))
        else:
            penalty = 1.0 - (0.015 * max(0, 20 - samples))
            
        final *= max(0.75, penalty)

        # ── 10. OVERRIDES & FLOORS (LOLBIN GUARD) ──
        final = min(99.0, final)

        # Reduce aggressive LOLBIN flooring to avoid widespread score flattening.
        # Tuned: lower floor values to reduce false-positive inflation for common admin tools
        lolbin_floor = 0.0
        if image_name in ["powershell.exe", "pwsh.exe"]: lolbin_floor = 20.0
        elif image_name in ["cmd.exe", "wscript.exe", "cscript.exe"]: lolbin_floor = 18.0
        
        if lolbin_floor > 0 and final < lolbin_floor:
            # Only floor when there is corroborating context beyond an image name
            if (burst.get("has_encoded_flag") or behavior_score > 0.6 or chain_depth >= 2 or sequence_score > 20):
                final = max(final, lolbin_floor)
                burst["floor_applied"] = True
                ledger.append(LedgerEntry("LOLBin floor", 0.0, f"Baseline visibility floor for suspicious {image}", "rule"))

        # ── CRITICAL: ATTACK OVERRIDE ──
        # Trigger on strong sequence OR multiple partial chains
        # Tuned: raise the sequence threshold to reduce accidental overrides from noisy signals
        if sequence_score >= 65 or len(sequence_detections or []) >= 2:
            final = max(final, 75.0)
            ledger.append(LedgerEntry(
                "Attack override",
                0.0,
                "Sequence detection indicates confirmed attack",
                "sequence"
            ))

        # ── 11. CONTRIBUTION-BASED PRIMARY DRIVER (v2.8) ──
        driver_scores = {
            "rule": max(0, rule_score),
            "sequence": max(0, sequence_score),
            "behavior": max(0, behavior_boost + stealth_boost + drift_boost),
            "rarity": max(0, rarity_boost + first_seen_boost),
            "correlation": max(0, corr_boost)
        }
        
        total_delta = sum(driver_scores.values()) or 1.0
        normalized = {k: v / total_delta for k, v in driver_scores.items()}
        primary_driver = max(normalized, key=normalized.get)
        
        # Mixed signal fallback
        if normalized.get(primary_driver, 0) < 0.4:
            primary_driver = "mixed"

        # \ud83d\udd12 Hard clamp: score MUST be in [0, 100] — no exceptions
        final = max(0.0, min(100.0, final))

        # Chain multiplier derived from chain_depth for downstream consumers
        chain_multiplier = 1.0 + min(3.0, max(0.0, (chain_depth - 1) * 0.75))

        return ScoreResult(
            score=round(float(final), 1),
            ledger=ledger,
            confidence_modifier=conf_mod,
            primary_driver=primary_driver,
            stage_cap=100.0,
            chain_multiplier=chain_multiplier,
        )

    def classify(self, score: float, kill_chain_stage: str = "Execution") -> str:
        """Compatibility method for legacy pipeline."""
        if score >= 70: return "attack_candidate"
        if score >= 30: return "suspicious"
        if kill_chain_stage not in ("Execution", "Background"): return "suspicious"
        return "benign"

    def validate_context(self, burst: Dict[str, Any]) -> bool:
        """
        Syntactic and causal validation of context records.
        """
        try:
            mandatory = ["image", "computer", "user"]
            for m in mandatory:
                if m not in burst: return False
                
            if "start_time" in burst:
                import pandas as pd
                pd.to_datetime(burst["start_time"])
                
            return True
        except Exception:
            return False

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_scoring_engine: Optional[ScoringEngine] = None

def get_scoring_engine() -> ScoringEngine:
    global _scoring_engine
    if _scoring_engine is None:
        _scoring_engine = ScoringEngine()
    return _scoring_engine

def validate_context(burst: Dict[str, Any]) -> bool:
    """Module-level wrapper for context validation."""
    return get_scoring_engine().validate_context(burst)
