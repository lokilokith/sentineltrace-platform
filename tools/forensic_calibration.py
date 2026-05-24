"""
forensic_calibration.py
Lightweight forensic-grade calibration harness.
Generates synthetic bursts from rules.yaml, scores them with ScoringEngine,
and emits the metrics/reports requested by the final calibration task.

Run: python -m tools.forensic_calibration
"""
import yaml
import statistics
import json
from collections import Counter, defaultdict
from pathlib import Path

import sys
# Ensure project root on path for imports
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard.scoring_engine import get_scoring_engine
from dashboard.analysis_engine import build_attack_story

RULES_PATH = ROOT / "rules.yaml"

def load_rules(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data.get("rules", []) if data else []

def synthesize_detection(rule, override_conf=None):
    return {
        "rule_id": rule.get("rule_id"),
        "rule_name": rule.get("name"),
        "mitre_tactic": rule.get("mitre_tactic"),
        "kill_chain_stage": rule.get("kill_chain_stage"),
        "confidence": float(override_conf if override_conf is not None else rule.get("confidence", 50)),
        "severity": rule.get("severity", "medium"),
        "image": (rule.get("image_any") or rule.get("image_contains") or "unknown"),
        "command_line": "",
    }

def make_burst_from_detection(det, image_override=None, extra=None):
    b = {
        "image": image_override or det.get("image") or "unknown.exe",
        "computer": extra.get("computer") if extra and extra.get("computer") else "host-1",
        "user": extra.get("user") if extra and extra.get("user") else "user-1",
        "parent_image": extra.get("parent_image") if extra and extra.get("parent_image") else "explorer.exe",
        "event_count": extra.get("event_count", 1) if extra else 1,
        "behavior_score": extra.get("behavior_score", 0.0) if extra else 0.0,
        "baseline_maturity": extra.get("baseline_maturity", 20) if extra else 20,
        "correlation_strength": extra.get("correlation_strength", 0.0) if extra else 0.0,
        "correlation_size": extra.get("correlation_size", 1) if extra else 1,
        "host_spread": extra.get("host_spread", 1) if extra else 1,
        "has_encoded_flag": 1 if ("-enc" in (det.get("rule_name") or "") or "PowerShell" in (det.get("rule_name") or "")) else 0,
        "event_ids": [],
    }
    return b

def percentile(sorted_list, p):
    if not sorted_list:
        return None
    k = (len(sorted_list)-1) * (p/100.0)
    f = int(k)
    c = min(f+1, len(sorted_list)-1)
    if f == c:
        return sorted_list[int(k)]
    d0 = sorted_list[f] * (c-k)
    d1 = sorted_list[c] * (k-f)
    return d0 + d1

def main():
    rules = load_rules(RULES_PATH)
    se = get_scoring_engine()

    samples = []
    tactic_counter = Counter()
    image_counter = Counter()
    scores = []
    ledger_reasons = Counter()
    p1 = p2 = p3 = 0

    # Create multiple scenarios per rule to exercise floors/boosts
    for rule in rules:
        for conf in (rule.get("confidence",50), max(5, rule.get("confidence",50)-20), min(95, rule.get("confidence",50)+20)):
            det = synthesize_detection(rule, override_conf=conf)
            # variations
            for behavior in (0.0, 0.45, 0.8):
                for chain_depth in (1,2,3):
                    burst = make_burst_from_detection(det, image_override=(rule.get("image_any") if rule.get("image_any") else rule.get("image_contains") or "unknown.exe"), extra={"behavior_score":behavior, "chain_depth":chain_depth, "baseline_maturity":20, "correlation_strength":0.0, "correlation_size":1, "host_spread":1})
                    # score
                    res = se.score_burst(burst, detections=[det], sequence_detections=[], behavior_score=behavior, chain_depth=chain_depth)
                    scores.append(res.score)
                    tactic_counter[det.get("mitre_tactic") or "Unmapped"] += 1
                    img = burst.get("image")
                    if isinstance(img, (list, tuple)):
                        img = img[0] if img else "unknown"
                    image_counter[str(img) if img else "unknown"] += 1
                    for e in res.ledger:
                        ledger_reasons[e.label] += 1
                    # priority mapping similar to pipeline thresholds
                    if res.score >= 75:
                        p1 += 1
                    elif res.score >= 50:
                        p2 += 1
                    elif res.score >= 25:
                        p3 += 1

    # Metrics
    scores_sorted = sorted(scores)
    hist_bins = Counter()
    for s in scores:
        bin_label = f"{int(s//10)*10}-{int(s//10)*10+9}"
        hist_bins[bin_label] += 1

    report = {
        "confidence_histogram": dict(hist_bins),
        "confidence_percentiles": {
            "p0": percentile(scores_sorted, 0),
            "p10": percentile(scores_sorted, 10),
            "p25": percentile(scores_sorted, 25),
            "p50": percentile(scores_sorted, 50),
            "p75": percentile(scores_sorted, 75),
            "p90": percentile(scores_sorted, 90),
            "p99": percentile(scores_sorted, 99),
        },
        "p_distribution": {"P1": p1, "P2": p2, "P3": p3},
        "tactic_distribution": dict(tactic_counter.most_common()),
        "top_noisy_binaries": image_counter.most_common(20),
        "top_ledger_reasons": ledger_reasons.most_common(20),
        "samples_count": len(scores),
        "score_mean": statistics.mean(scores) if scores else 0,
        "score_stdev": statistics.pstdev(scores) if scores else 0,
    }

    out = Path.cwd() / "engineering_outputs" / "forensic_calibration_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote report: {out}")

if __name__ == "__main__":
    main()
