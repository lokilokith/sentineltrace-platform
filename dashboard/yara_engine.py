"""
yara_engine.py — SentinelTrace v2.2
=====================================
Upgraded from binary match/no-match to weighted scoring.

Changes:
  - yara_score = number_of_matches × 20, bonus +20 for ≥3 matches, capped at 100.
  - Removed unused sqlite3 import.
  - load_yara_rules() returns None gracefully if yara not installed.
  - run_yara_on_events() returns enriched dicts with yara_score, yara_hits,
    and yara_rule_names — downstream engines use these.
  - scan_text() helper exposed for scanning arbitrary strings.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("yara_engine")

try:
    import yara as _yara_lib
    _YARA_AVAILABLE = True
except ImportError:
    _yara_lib = None  # type: ignore
    _YARA_AVAILABLE = False


def yara_available() -> bool:
    return _YARA_AVAILABLE


def load_yara_rules(rules_path) -> Optional[Any]:
    """
    Compile YARA rules from a file path.
    Returns compiled rules object or None if yara not installed / path invalid.
    """
    if not _YARA_AVAILABLE:
        log.debug("yara-python not installed — YARA scanning disabled")
        return None
    if rules_path is None:
        return None
    path = Path(rules_path)
    if not path.exists():
        log.warning("YARA rules file not found: %s", path)
        return None
    if path.suffix.lower() not in (".yar", ".yara"):
        log.warning("Unsupported YARA extension: %s", path.suffix)
        return None
    try:
        rules = _yara_lib.compile(filepath=str(path))
        log.info("Compiled YARA rules from %s", path.name)
        return rules
    except _yara_lib.SyntaxError as exc:
        raise RuntimeError(f"Invalid YARA rule syntax in {path.name}: {exc}") from exc


def _build_scan_data(ev: Dict[str, Any]) -> bytes:
    """Build a single string to scan from an event's key fields."""
    parts = [
        str(ev.get("image") or ""),
        str(ev.get("command_line") or ""),
        str(ev.get("parent_image") or ""),
        str(ev.get("dst_ip") or ev.get("destination_ip") or ""),
        str(ev.get("file_path") or ev.get("target_filename") or ""),
        str(ev.get("reg_key") or ""),
        str(ev.get("dns_query") or ""),
    ]
    return " ".join(parts).encode("utf-8", "replace")


def compute_yara_score(match_count: int) -> int:
    """
    Convert a raw match count into a 0–100 risk score.

      1 match  →  20
      2 matches → 40
      3+ matches → 60 + bonus 20 = 80, capped at 100.
    """
    if match_count <= 0:
        return 0
    score = match_count * 20
    if match_count >= 3:
        score += 20    # multi-rule bonus
    return min(score, 100)


def scan_text(rules: Any, text: str) -> Dict[str, Any]:
    """
    Scan an arbitrary string with compiled YARA rules.
    Returns {"yara_score": int, "yara_hits": int, "yara_rule_names": list}.
    """
    if rules is None or not text:
        return {"yara_score": 0, "yara_hits": 0, "yara_rule_names": []}
    try:
        matches = rules.match(data=text.encode("utf-8", "replace"))
        hit_count  = len(matches)
        rule_names = [m.rule for m in matches]
        return {
            "yara_score":      compute_yara_score(hit_count),
            "yara_hits":       hit_count,
            "yara_rule_names": rule_names,
        }
    except Exception as exc:
        log.debug("YARA scan error: %s", exc)
        return {"yara_score": 0, "yara_hits": 0, "yara_rule_names": []}


def run_yara_on_events(
    rules: Any,
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Scan each event dict against compiled YARA rules.

    Returns the same list with three new fields added to each event:
      yara_score      int    0–100 weighted score (not binary)
      yara_hits       int    number of rule matches
      yara_rule_names list   names of matched rules

    Non-matching events get these fields set to 0 / empty so
    downstream code can always read them safely.
    """
    if rules is None:
        for ev in events:
            ev.setdefault("yara_score", 0)
            ev.setdefault("yara_hits",  0)
            ev.setdefault("yara_rule_names", [])
        return events

    for ev in events:
        data = _build_scan_data(ev)
        try:
            matches    = rules.match(data=data)
            hit_count  = len(matches)
            rule_names = [m.rule for m in matches]
        except Exception as exc:
            log.debug("YARA scan error on event %s: %s", ev.get("event_uid", "?"), exc)
            hit_count  = 0
            rule_names = []

        ev["yara_score"]      = compute_yara_score(hit_count)
        ev["yara_hits"]       = hit_count
        ev["yara_rule_names"] = rule_names

    return events
