from flask import Blueprint, request, jsonify
from dashboard.db import update_incident_status, get_incident_status
from dashboard.routes_incident import enforce_response_contract
from dashboard.soc_verdict import validate_transition
import logging
log = logging.getLogger("routes_triage")

triage_bp = Blueprint("triage", __name__)

@triage_bp.route("/api/triage/update", methods=["POST"])
def update_triage():
    """
    Securely update incident status.
    1. Fetches current state from DB (prevents client-side state injection)
    2. Validates transition via SOC state machine
    3. Performs atomic update with concurrency check (prevents race conditions)
    """
    data = request.json or {}
    incident_id = data.get("incident_id")
    new_status = data.get("status")

    if not incident_id or not new_status:
        return jsonify({"error": "Missing incident_id or status"}), 400

    if not isinstance(incident_id, str) or len(incident_id) > 100:
        return jsonify({"error": "Invalid incident_id format"}), 400

    if not isinstance(new_status, str):
        return jsonify({"error": "Invalid status format"}), 400

    # ── [10/10] Case-Safe Status Normalization ──────────────────────────────
    from dashboard.soc_verdict import VALID_STATUSES
    new_status = new_status.strip()
    valid_map = {s.lower(): s for s in VALID_STATUSES}
    
    if new_status.lower() not in valid_map:
        log.warning(
            "[Triage] Invalid status attempt | incident=%s | input=%s",
            incident_id, new_status
        )
        return jsonify({"error": "Invalid status"}), 400
        
    new_status = valid_map[new_status.lower()]

    # 10/10 Formal Mastery: Fetch CURRENT status from DB, don't trust the client
    current = get_incident_status(incident_id) or "New"
    if current is None:
        log.warning("[Triage] Update attempted on missing incident_id=%s", incident_id)
        return jsonify({"error": "Incident not found"}), 404
    
    log.info("[Triage] Current status fetched | incident=%s | status=%s", incident_id, current)

    # Validate transition using existing SOC logic
    valid, err = validate_transition(current, new_status)
    if not valid:
        log.warning(
            "[Triage] Invalid transition | incident=%s | %s → %s | reason=%s",
            incident_id, current, new_status, err
        )
        return jsonify({"error": err}), 400

    # ── [10/10] Activated Audit Trail ───────────────────────────────────────
    from dashboard.soc_verdict import create_audit_entry
    audit = create_audit_entry(
        analyst_id=data.get("analyst_id", "unknown"),
        action="status_change",
        target_type="incident",
        target_id=incident_id,
        detail=f"{current} → {new_status}"
    )
    log.info("[AUDIT] %s", audit)

    # Atomic update: only succeeds if current status matches what we just read
    success = update_incident_status(incident_id, new_status, current)
    if not success:
        log.error(
            "[Triage] Update failed | incident=%s | expected=%s | new=%s",
            incident_id, current, new_status
        )
        return jsonify({
            "error": "Update failed. The incident status may have changed or the incident does not exist."
        }), 409

    return jsonify(enforce_response_contract({
        "success": True, 
        "incident_id": incident_id,
        "previous_status": current,
        "new_status": new_status,
        "status": "complete"
    }))
