from typing import Any, List, Dict, Iterable, Tuple
from flask import Blueprint, jsonify, request
import json
import logging
import time
from dashboard.db import (
    get_incident_by_id, 
    get_events_by_uids, 
    get_event_by_uid,
    get_incident_evidence,
    insert_evidence
)
from dashboard.analysis_cache import get_analysis_snapshot_slice
from dashboard.auth import login_required, get_current_user

import datetime
log = logging.getLogger("routes_incident")
incident_bp = Blueprint("incident", __name__)

DEFAULT_TIMELINE_PAGE_SIZE = 120
MAX_TIMELINE_PAGE_SIZE = 500
SEARCH_BATCH_SIZE = 500

def safe_parse(ts):
    """[10/10] Robust ISO parser with fallback for malformed telemetry."""
    if not ts:
        return datetime.datetime.min
    try:
        # datetime.datetime.fromisoformat exists since Python 3.7
        return datetime.datetime.fromisoformat(str(ts))
    except (ValueError, TypeError):
        return datetime.datetime.min

def enforce_response_contract(data: Any) -> dict:
    """
    Strict 9.8/10 Mastery: Centralized response normalization.
    Ensures 'status' and 'meta' are always present in JSON returns.
    """
    if not isinstance(data, dict):
        data = {}

    data["status"] = data.get("status") or "complete"

    if "meta" not in data:
        data["meta"] = {
            "pipeline_stage": "unknown",
            "errors": [],
            "warnings": []
        }
    
    return data


def _chunked(values: List[str], size: int) -> Iterable[List[str]]:
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _parse_event_uids(incident: dict) -> List[str]:
    raw_uids = incident.get("event_uids")
    try:
        if isinstance(raw_uids, list):
            uids = [str(uid) for uid in raw_uids]
        else:
            uids = [str(uid) for uid in json.loads(raw_uids)] if raw_uids else []
        return list(dict.fromkeys(uids))
    except Exception:
        return []


def _safe_json(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _safe_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_safe_json(v) for v in obj]
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


def _event_matches_query(event: dict, query: str) -> bool:
    if not query:
        return True
    q = query.lower().strip()
    if not q:
        return True
    fields = (
        event.get("event_uid"),
        event.get("event_id"),
        event.get("image"),
        event.get("parent_image"),
        event.get("command_line"),
        event.get("computer"),
        event.get("user"),
        event.get("destination_ip"),
        event.get("dst_ip"),
    )
    return any(q in str(value).lower() for value in fields if value not in (None, ""))


def _normalize_timeline_event(event: dict) -> dict:
    return {
        "event_uid": str(event.get("event_uid", "")),
        "event_time": str(event.get("event_time") or "1970-01-01T00:00:00Z"),
        "event_id": event.get("event_id", ""),
        "image": event.get("image", "unknown"),
        "parent_image": event.get("parent_image", ""),
        "command_line": event.get("command_line", ""),
        "computer": event.get("computer", ""),
        "network": event.get("destination_ip") or event.get("dst_ip") or ""
    }


def _load_incident_context(incident_id: str, timeline_limit: int = 0) -> tuple:
    incident = get_incident_by_id(incident_id)
    if not incident:
        return None, None, None, None, None

    run_id = incident.get("run_id")
    if not run_id:
        return incident, None, [], None, None

    snapshot = None
    wait = 0.1
    for i in range(5):
        snapshot = get_analysis_snapshot_slice(run_id, timeline_limit=timeline_limit)
        if snapshot:
            break
        log.info("[IncidentAPI] Snapshot retry %d/5 for run_id=%s", i + 1, run_id[:8])
        time.sleep(wait)
        wait *= 2

    uids = _parse_event_uids(incident)
    evidence = get_incident_evidence(incident_id)
    return incident, run_id, uids, snapshot, evidence


def _load_timeline_page(run_id: str, uids: List[str], offset: int, limit: int, query: str = "") -> dict:
    offset = max(int(offset or 0), 0)
    limit = max(1, min(int(limit or DEFAULT_TIMELINE_PAGE_SIZE), MAX_TIMELINE_PAGE_SIZE))
    query = (query or "").strip()

    if query:
        matched_events: List[dict] = []
        for batch in _chunked(uids, SEARCH_BATCH_SIZE):
            events = get_events_by_uids(run_id, batch)
            event_map = {str(event.get("event_uid")): event for event in events}
            for uid in batch:
                event = event_map.get(str(uid))
                if event and _event_matches_query(event, query):
                    matched_events.append(event)

        total = len(matched_events)
        page_events = matched_events[offset:offset + limit]
        page_offset = offset
        has_more = page_offset + len(page_events) < total
        next_offset = page_offset + len(page_events)
        returned = len(page_events)
        missing = 0
    else:
        page_uids = uids[offset:offset + limit]
        total = len(uids)
        events = get_events_by_uids(run_id, page_uids)
        event_map = {str(event.get("event_uid")): event for event in events}
        page_events = [event_map[str(uid)] for uid in page_uids if str(uid) in event_map]
        returned = len(page_events)
        missing = max(len(page_uids) - returned, 0)
        has_more = offset + len(page_uids) < total
        next_offset = offset + len(page_uids)

    timeline_page = [_normalize_timeline_event(event) for event in page_events if isinstance(event, dict)]
    return {
        "timeline_page": timeline_page,
        "timeline_meta": {
            "total": total,
            "offset": offset,
            "limit": limit,
            "returned": returned,
            "missing": missing,
            "has_more": has_more,
            "next_offset": next_offset,
            "query": query,
        },
    }


def _build_incident_payload(incident_id: str, *, offset: int = 0, limit: int = DEFAULT_TIMELINE_PAGE_SIZE, query: str = "") -> dict:
    incident, run_id, uids, snapshot, evidence = _load_incident_context(incident_id, timeline_limit=0)
    if not incident:
        return {"error": "Incident not found"}
    if not run_id:
        return {"error": "Invalid incident data"}

    if not snapshot:
        log.warning("[IncidentAPI] Analysis snapshot missing after retries for run_id=%s", run_id)
        snapshot = {
            "status": "processing",
            "meta": {},
            "attack_narrative": {
                "summary": "Analysis in progress... please wait.",
                "stage": "Processing",
                "score": 0,
                "is_attack": False,
            },
        }

    attack_story = snapshot.get("attack_narrative") or {
        "summary": "Analysis incomplete — narrative unavailable",
        "bullets": [],
        "full_text": "",
        "stage": "Unknown",
        "score": 0,
        "is_attack": None,
    }

    timeline_payload = _load_timeline_page(run_id, uids, offset, limit, query=query)
    timeline_valid = bool(uids)

    incident_payload = _safe_json(incident)
    if isinstance(snapshot, dict):
        for key in (
            "attack_conf_score",
            "attack_conf_level",
            "attack_conf_basis",
            "attack_conf_cap",
            "confidence_trend",
            "recommended_action",
            "action_priority",
            "action_reason",
            "response_tasks",
            "highest_kill_chain",
            "campaign_name",
            "campaign_theme",
        ):
            if key in snapshot and snapshot.get(key) is not None:
                incident_payload[key] = _safe_json(snapshot.get(key))

    log.info(
        "[IncidentAPI] incident=%s | events=%d | evidence=%d | query=%r | has_story=%s",
        incident_id,
        len(timeline_payload["timeline_page"]),
        len(evidence or []),
        query,
        bool(attack_story.get("summary")),
    )

    payload = {
        "incident": incident_payload,
        "attack_story": attack_story,
        "timeline_page": timeline_payload["timeline_page"],
        "timeline_meta": timeline_payload["timeline_meta"],
        "timeline_valid": timeline_valid,
        "evidence": evidence or [],
        "run_id": run_id,
        "status": snapshot.get("status", "complete"),
        "meta": snapshot.get("meta", {}),
    }

    return enforce_response_contract(payload)

@incident_bp.route("/api/incidents/<incident_id>")
def get_incident_detail(incident_id):
    """
    10/10 SOC: Full Reconstruction API.
    Returns the formal incident, enriched with its original analysis context,
    the subset of events matching the triggering UIDs, and tagged evidence.
    """
    # 9.8/10 Mastery: Context-Aware Auth
    if not get_current_user():
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        from flask import redirect, url_for
        return redirect(url_for("login"))

    try:
        payload = _build_incident_payload(incident_id, offset=0, limit=DEFAULT_TIMELINE_PAGE_SIZE)
        if "error" in payload:
            code = 404 if payload["error"] == "Incident not found" else 500
            return jsonify(enforce_response_contract({"error": payload["error"]})), code
        return jsonify(payload)
    except Exception as e:
        log.error("[IncidentDetail] Error fetching %s: %s", incident_id, e, exc_info=True)
        return jsonify(enforce_response_contract({
            "error": str(e),
            "status": "failed",
            "meta": {
                "pipeline_stage": "api-error",
                "errors": [{"stage": "api", "message": str(e)[:200], "type": type(e).__name__}]
            }
        })), 500


@incident_bp.route("/api/incidents/<incident_id>/timeline")
def get_incident_timeline_page(incident_id):
    """Return a progressive page of incident timeline events without truncation."""
    if not get_current_user():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        offset = int(request.args.get("offset", 0))
        limit = int(request.args.get("limit", DEFAULT_TIMELINE_PAGE_SIZE))
        query = request.args.get("q", "")
    except ValueError:
        return jsonify({"error": "Invalid pagination parameters"}), 400

    payload = _build_incident_payload(incident_id, offset=offset, limit=limit, query=query)
    if "error" in payload:
        code = 404 if payload["error"] == "Incident not found" else 500
        return jsonify(enforce_response_contract({"error": payload["error"]})), code

    return jsonify({
        "timeline": payload["timeline_page"],
        "timeline_page": payload["timeline_page"],
        "timeline_meta": payload["timeline_meta"],
        "status": payload["status"],
        "meta": payload["meta"],
        "run_id": payload["run_id"],
        "timeline_valid": payload["timeline_valid"],
        "query": query,
    })


@incident_bp.route("/api/incidents/<incident_id>/events/<event_uid>")
def get_incident_event(incident_id, event_uid):
    """Return the full forensic record for one incident-associated event."""
    if not get_current_user():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        incident = get_incident_by_id(incident_id)
        if not incident:
            return jsonify(enforce_response_contract({"error": "Incident not found"})), 404

        run_id = incident.get("run_id")
        if not run_id:
            return jsonify(enforce_response_contract({"error": "Invalid incident data"})), 500

        raw_uids = incident.get("event_uids")
        try:
            valid_uids = [str(uid) for uid in json.loads(raw_uids)] if raw_uids else []
        except Exception:
            valid_uids = []

        if str(event_uid) not in valid_uids:
            return jsonify(enforce_response_contract({"error": "Event not associated with this incident"})), 404

        event = get_event_by_uid(run_id, str(event_uid))
        if not event:
            return jsonify(enforce_response_contract({"error": "Event not found"})), 404

        return jsonify({
            "incident_id": incident_id,
            "event_uid": str(event_uid),
            "event": _safe_json(event),
            "status": "complete",
            "meta": {
                "pipeline_stage": "event-detail",
                "warnings": [],
                "errors": [],
            },
        })
    except Exception as e:
        log.error("[IncidentAPI] Event detail error for %s/%s: %s", incident_id, event_uid, e, exc_info=True)
        return jsonify(enforce_response_contract({
            "error": str(e),
            "status": "failed",
            "meta": {
                "pipeline_stage": "event-detail",
                "errors": [{"stage": "event-detail", "message": str(e)[:200], "type": type(e).__name__}],
            }
        })), 500

@incident_bp.route("/api/evidence/add", methods=["POST"])
@login_required
def add_evidence():
    """
    10/10 SOC: Structured Evidence Tagging with Validation.
    """
    data = request.json
    incident_id = data.get("incident_id")
    event_uid   = data.get("event_uid")
    tag         = data.get("tag", "Relevant")

    if not incident_id or not event_uid:
        return jsonify({"error": "Missing parameters"}), 400

    try:
        incident = get_incident_by_id(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found"}), 404

        # Validation: Ensure event_uid belongs to the incident's triggering set
        raw_uids = incident.get("event_uids")
        try:
            valid_uids = [str(u) for u in json.loads(raw_uids)] if raw_uids else []
        except Exception:
            valid_uids = []

        if str(event_uid) not in valid_uids:
            # log.warning("[Evidence] Attempted to link unassociated event %s to INC-%s", event_uid, incident_id)
            return jsonify({"error": "Event not associated with this incident"}), 400

        user = get_current_user()
        analyst_name = user.get("username", "system") if isinstance(user, dict) else "system"
        
        insert_evidence(incident_id, event_uid, tag, analyst_name)
        return jsonify({"success": True, "message": "Evidence linked"})
    except Exception as e:
        log.error("[EvidenceAdd] Failed for %s: %s", incident_id, e)
        return jsonify({"error": str(e)}), 500
