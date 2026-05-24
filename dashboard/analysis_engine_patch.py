# dashboard/analysis_engine_patch.py
"""
analysis_engine_patch.py — SentinelTrace v2 Pipeline Bridge
============================================================
Bridges the original run_full_analysis with the new unified pipeline
(baseline, sequence engine, decision layer, etc.).

FIXES vs root-level analysis_engine_patch.py:
  1. Loads events directly from sentinel_cases with correct column names.
  2. Extracts actual_run_id from context to handle upload vs analysis run_id mismatch.
  3. Passes both events_df and detections_df to the pipeline rather than None.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Dict

import pandas as pd

log = logging.getLogger("analysis_engine_patch")


def _run_pipeline_enrichment(actual_run_id: str, context: Dict[str, Any]) -> None:
    """Best-effort dashboard enrichment that must never block terminal completion."""
    try:
        from dashboard.pipeline import run_full_pipeline
        events_df = _load_events_for_pipeline(actual_run_id)
        detections_df = _load_detections_for_pipeline(actual_run_id)

        log.info(
            "[Patch] Background pipeline input: %d events, %d detections for run_id=%s",
            len(events_df), len(detections_df), actual_run_id[:16],
        )

        enriched = run_full_pipeline(
            events_df=events_df,
            detections_df=detections_df,
            run_id=actual_run_id,
            context=context,
        )

        if isinstance(enriched, dict):
            from dashboard.analysis_cache import set_analysis_snapshot

            set_analysis_snapshot(actual_run_id, enriched, authoritative=True)
            log.info("[Patch] Background pipeline snapshot updated for run_id=%s", actual_run_id[:16])
    except Exception as exc:
        log.warning("[Patch] Background pipeline enrichment failed for run_id=%s: %s", actual_run_id[:16], exc, exc_info=True)


def _load_events_for_pipeline(run_id: str) -> pd.DataFrame:
    """
    Load events from sentinel_cases for the given run_id.
    Bypasses app.load_events() which renames/drops columns needed by the pipeline.
    """
    try:
        from dashboard.db import get_engine
        from sqlalchemy import text
        sql = text(
            "SELECT event_uid, event_time, event_id, image, parent_image,"
            " command_line, `user`, pid, ppid,"
            " src_ip AS source_ip, dst_ip AS destination_ip,"
            " dst_port AS destination_port, severity, computer,"
            " file_path AS target_filename, run_id,"
            " cmd_entropy, cmd_has_encoded_flag AS has_encoded_flag"
            " FROM events WHERE run_id = :run_id ORDER BY event_time ASC"
        )
        with get_engine("cases").connect() as conn:
            df = pd.read_sql_query(sql, conn, params={"run_id": run_id})
        if df.empty:
            log.warning("[Patch] No events found for run_id=%s", run_id)
            return pd.DataFrame()

        # Preserve native MySQL datetime values; downstream code can use them directly.
        df["event_time"] = df["event_time"]
        df["utc_time"] = df["event_time"]
        df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce").fillna(0).astype(int)
        log.info("[Patch] Loaded %d events for run_id=%s", len(df), run_id)
        return df
    except Exception as exc:
        log.error("[Patch] _load_events_for_pipeline failed: %s", exc, exc_info=True)
        return pd.DataFrame()


def _load_detections_for_pipeline(run_id: str) -> pd.DataFrame:
    """Load detections from sentinel_cases."""
    try:
        from dashboard.db import get_engine
        from sqlalchemy import text
        with get_engine("cases").connect() as conn:
            df = pd.read_sql_query(
                text("SELECT * FROM detections WHERE run_id = :run_id ORDER BY utc_time DESC"),
                conn,
                params={"run_id": run_id},
            )
        if df.empty:
            log.warning("[Patch] No detections for run_id=%s", run_id)
        return df
    except Exception as exc:
        log.warning("[Patch] _load_detections_for_pipeline failed: %s", exc)
        return pd.DataFrame()


def patched_run_full_analysis(run_id: str, run_correlation: bool = True) -> Dict[str, Any]:
    """
    Wraps the original analysis and then enriches the result with the
    unified pipeline (baseline, sequence, decision layer, etc.).
    """
    from dashboard.analysis_engine import run_full_analysis as _original_run

    # 1. Run original analysis (builds initial context & snapshot)
    log.info("[Patch] Running original analysis for run_id=%s", run_id)
    context = _original_run(run_id, run_correlation)
    if not context:
        log.warning("[Patch] run_full_analysis returned empty context for run_id=%s", run_id)
        return context

    # CRITICAL: use the actual run_id that was written to the DB
    # (may differ from upload tracking id)
    actual_run_id = context.get("analysis_run_id") or run_id
    context["analysis_run_id"] = actual_run_id
    context["run_id"] = actual_run_id

    # 2. Apply the full pipeline augmentation out of band so completion is not blocked.
    threading.Thread(
        target=_run_pipeline_enrichment,
        args=(actual_run_id, context),
        daemon=True,
        name=f"pipeline-enrichment-{actual_run_id[:8]}",
    ).start()

    return context
