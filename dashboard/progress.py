# dashboard/progress.py
from typing import Any, Dict, Optional

import threading

_state = {}
_lock = threading.Lock()

def set_run_progress(
    run_id: str,
    state: str,
    progress: int = 0,
    message: str = "",
    actual_run_id: str = None,
    error: str = None,
    active_stage: Optional[str] = None,
    stage_elapsed_seconds: float = 0.0,
    processed_events: int = 0,
    total_events: int = 0,
    operation_label: Optional[str] = None,
    metrics: Optional[Dict[str, Any]] = None,
    heartbeat_reset: bool = True,
    **extra_fields: Any,
):
    with _lock:
        existing = dict(_state.get(run_id, {}))
        now = __import__('time').time()
        progress_changed = existing.get("progress") != progress
        active_stage_changed = active_stage is not None and active_stage != existing.get("active_stage")
        existing.update({
            "state": state,
            "progress": progress,
            "message": message,
            "updated_at": now,
            "last_progress_at": now,
            "progress_sequence": int(existing.get("progress_sequence", 0)) + (1 if progress_changed else 0),
            "stage_sequence": int(existing.get("stage_sequence", 0)) + 1,
        })
        if actual_run_id is not None:
            existing["run_id"] = actual_run_id
        if error is not None:
            existing["error"] = error
        if active_stage is not None:
            existing["active_stage"] = active_stage
        if stage_elapsed_seconds or "stage_elapsed_seconds" not in existing:
            existing["stage_elapsed_seconds"] = stage_elapsed_seconds
        if processed_events or "processed_events" not in existing:
            existing["processed_events"] = processed_events
        if total_events or "total_events" not in existing:
            existing["total_events"] = total_events
        if operation_label is not None:
            existing["operation_label"] = operation_label
        if metrics is not None:
            existing["metrics"] = metrics
        if heartbeat_reset:
            existing["heartbeat_reset_at"] = now
        existing["last_progress_timestamp"] = now
        if active_stage_changed:
            existing["active_stage_transition_at"] = now
        existing.update(extra_fields)
        _state[run_id] = existing

def get_run_progress(run_id: str):
    with _lock:
        status = dict(_state.get(run_id, {"state": "unknown"}))
        if "updated_at" in status and "last_progress_timestamp" not in status:
            status["last_progress_timestamp"] = status["updated_at"]
        return status
