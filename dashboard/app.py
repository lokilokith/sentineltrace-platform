from __future__ import annotations
"""
app.py — SentinelTrace Flask Application  (MySQL edition)
==========================================================
All PostgreSQL / psycopg2 references removed.
Uses the MySQL-compatible db.py layer throughout.

FIXES IN THIS VERSION:
  FIX-1: load_events() — expanded column set to include parent_image,
          command_line, file_path, pid, ppid so hunt console can filter
          on all standard fields. Previously these were missing, causing
          hunt queries to always return 0 results.

  FIX-2: burst_view() — added field aliases (dst_ip -> destination_ip,
          file_path -> target_filename) in safe_events so burst.html
          template can access them. Previously burst detail page showed
          empty event tables even when events existed in the DB.

  FIX-3: burst_view() — `user` column aliased explicitly in SQL to avoid
          reserved-word issues on MySQL 8+.
"""

import datetime
import io
import json
import logging
import os
import numbers
import re
import threading
import time
import traceback
import uuid
from collections import defaultdict
from ipaddress import ip_address, AddressValueError
from pathlib import Path

import xml.etree.ElementTree as ET
from itertools import islice
import pandas as pd
from sqlalchemy import text
from flask import (
    Flask,
    Response,
    flash,
    get_flashed_messages,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from dashboard.db import (
    get_db_connection,
    get_cursor,
    get_engine,
    health_check,
    now_utc,
    quote_identifier,
    sanitize_datetime,
    sql_now_minus,
)

from dashboard.auth import (
    get_current_user
)
from dashboard.soc_verdict import sla_status

from dashboard.analysis_cache import (
    clear_analysis_snapshot,
    get_analysis_snapshot,
    get_analysis_snapshot_slice,
    set_analysis_snapshot,
)
# Defer heavy imports: analysis_engine, soc_verdict — loaded in function scopes
# 'hunt' is the actual function name in threat_hunter; alias it as hunt_query
# so the /api/hunt route can call hunt_query(df, query) without changes.
from dashboard.threat_hunter import hunt as hunt_query  # noqa: E402

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("app")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR      = Path(__file__).resolve().parent
DATA_DIR      = BASE_DIR / "data"
TEMPLATES_DIR = BASE_DIR / "templates"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder=str(TEMPLATES_DIR))

_secret = os.environ.get("SECRET_KEY", "")
if not _secret:
    raise EnvironmentError(
        "SECRET_KEY environment variable is not set.\n"
        "Set it before starting:\n"
        "  Windows:  set SECRET_KEY=your_random_string\n"
        "  Linux:    export SECRET_KEY=$(python -c \"import secrets; print(secrets.token_hex(32))\")"
    )
app.secret_key = _secret
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB

# ---------------------------------------------------------------------------
# CSRF shim — templates reference {{ csrf_token() }} but Flask-WTF is not
# installed. Inject a no-op callable so Jinja2 doesn't raise UndefinedError.
# ---------------------------------------------------------------------------
app.jinja_env.globals["csrf_token"] = lambda: ""

SNAPSHOT_LOCK = threading.Lock()


def _preview_items(values, limit: int):
    if values is None:
        return []
    try:
        if isinstance(values, list):
            return values[:limit]
        if hasattr(values, "__getitem__"):
            return list(values[:limit])
    except Exception:
        pass
    return list(islice(values, limit))


def _template_safe_value(value):
    if isinstance(value, dict):
        return {str(key): _template_safe_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_template_safe_value(item) for item in value]
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    try:
        if pd.isna(value):
            return None
    except Exception:
        pass
    if isinstance(value, (str, numbers.Number, bool)):
        return value
    return str(value)


def _template_safe_records(values, *, string_keys: set[str] | None = None):
    if not values:
        return []
    if isinstance(values, pd.DataFrame):
        values = values.to_dict(orient="records")
    else:
        values = list(values)
    string_keys = set(string_keys or set())
    safe_records = []
    for record in values:
        if isinstance(record, dict):
            safe_record = {}
            for key, item in record.items():
                if key in string_keys and item is not None:
                    safe_record[key] = str(item)
                else:
                    safe_record[key] = _template_safe_value(item)
            safe_records.append(safe_record)
        else:
            safe_records.append(_template_safe_value(record))
    return safe_records

# ---------------------------------------------------------------------------
# Blueprint registration — incident and triage routes
# ---------------------------------------------------------------------------
from dashboard.routes_incident import incident_bp  # noqa: E402
from dashboard.routes_triage import triage_bp        # noqa: E402

app.register_blueprint(incident_bp)
app.register_blueprint(triage_bp)

# ---------------------------------------------------------------------------
# 10/10 Formal Mastery: Environment Auditing
# ---------------------------------------------------------------------------
def check_environment():
    """Audits the execution environment for production-grade readiness."""
    try:
        import watchdog
        log.info("[ENV] watchdog detected: High-performance filesystem polling ACTIVE.")
    except ImportError:
        log.warning("[ENV] watchdog MISSING: Falling back to slow 'stat' polling. Reloads will be sluggish.")
    
    if os.environ.get("SECRET_KEY") == "SentinelTrace2026_ChangeThis":
        log.warning("[ENV] DEFAULT SECRET_KEY DETECTED: UNSAFE FOR PRODUCTION DEPLOYMENT.")

# ---------------------------------------------------------------------------
# Global Warmup State
# ---------------------------------------------------------------------------
_WARMUP_DONE = False
_WARMUP_STARTED = False
_WARMUP_LOCK = threading.Lock()

def is_system_ready():
    return _WARMUP_DONE


def _start_warmup_once() -> bool:
    """Start warmup thread once per process; returns True if started now."""
    global _WARMUP_STARTED
    with _WARMUP_LOCK:
        if _WARMUP_STARTED:
            return False
        _WARMUP_STARTED = True
    threading.Thread(target=warmup_dashboard_ultimate, daemon=True, name="warmup").start()
    return True

def warmup_dashboard_ultimate():
    """
    [10/10 Mastery] Escalated Background Warmup with infinite self-healing.
    Performs 5 fast retries, then a CRITICAL alert, then infinite 5m heartbeat.
    Ensures the dashboard eventually reaches 'Hot' state even after DB restarts.
    """
    global _WARMUP_DONE
    import time
    
    log.info("[WARMUP] Starting background structural warmup (V9.0)...")
    
    # --- STAGE 1: Aggressive Retry (5 attempts, 10s backoff) ---
    for i in range(5):
        try:
            from dashboard.analysis_engine import load_detection_rules
            from dashboard.db import initialize_db_schema
            
            # 1. DB Integrity
            initialize_db_schema()
                
            # 2. Rule Engine Warming
            rules = load_detection_rules()
            log.info("[WARMUP] Detection engine warmed with %d rules.", len(rules))
            
            # 3. Import Chain Warming (Force Pandas/SQLAlchemy load in bg)
            import pandas as pd
            pd.DataFrame()
            
            _WARMUP_DONE = True
            log.info("[WARMUP] SYSTEM READY. All structures warmed and responsive.")
            return
        except Exception as e:
            log.warning("[WARMUP] Attempt %d failed: %s. Retrying in 10s...", i+1, e)
            time.sleep(10)

    # --- STAGE 2: Escalated Failure ---
    log.critical("[WARMUP] PERSISTENT WARMUP FAILURE. Dashboard operating in 'COLD' mode (Limited UI).")
    
    # --- STAGE 3: Infinite Heartbeat ---
    while True:
        try:
            from dashboard.analysis_engine import load_detection_rules
            from dashboard.db import is_schema_valid

            if is_schema_valid():
                log.info("[WARMUP] Infrastructure RECOVERED. Performing structural warming...")
                _WARMUP_DONE = False # Reset for re-attempt
                load_detection_rules()
                _WARMUP_DONE = True
                log.info("[WARMUP] RECOVERY SUCCESS. Dashboard back to 'HOT' state.")
                return
        except Exception as _wup_exc:
            log.debug("[WARMUP] Recovery probe failed: %s", _wup_exc)
        time.sleep(300) # Check every 5 minutes

# ---------------------------------------------------------------------------
# Global status + backpressure
# ---------------------------------------------------------------------------
from dashboard.progress import set_run_progress as _set_run_status, get_run_progress as _get_run_status

# 9.8: Backpressure semaphore — max 3 concurrent analyses
# Beyond this, new uploads get an immediate error instead of hanging.
_ANALYSIS_SEMAPHORE = threading.Semaphore(3)
_ANALYSIS_SEMAPHORE_MAX = 3

def _run_analysis_async(run_id: str, xml_path, rules_dest) -> None:
    """Background worker — runs full pipeline with backpressure guard."""
    worker_tid = threading.get_ident()
    log.info("[FINALIZE] enter worker run_id=%s thread_id=%s", run_id[:16], worker_tid)
    # 9.8: Acquire backpressure slot (non-blocking check)
    if not _ANALYSIS_SEMAPHORE.acquire(blocking=False):
        log.warning(
            "[BACKPRESSURE] Analysis queue full (%d max). Rejecting run_id=%s",
            _ANALYSIS_SEMAPHORE_MAX, run_id[:16]
        )
        _set_run_status(
            run_id, "error",
            message="System overloaded. Too many concurrent analyses. Try again in a few minutes.",
            error="QUEUE_FULL"
        )
        return

    try:
        _set_run_status(run_id, "running", progress=5, message="Starting ingestion...")
        log.info("[ASYNC] Starting analysis for run_id=%s", run_id)
        
        from dashboard.analysis_engine import ingest_upload, persist_case
        from dashboard.analysis_engine_patch import patched_run_full_analysis as run_full_analysis
        from dashboard.analysis_cache import set_analysis_snapshot
        
        t0 = time.perf_counter()
        events_df, detections_df, behaviors_df, content_hash = ingest_upload(
            xml_path=xml_path, rules_path=rules_dest, run_id=run_id,
        )
        log.info(
            "[INGEST_PROBE] stage=async_ingest_upload elapsed_sec=%.3f run_id=%s events=%d detections=%d behaviors=%d",
            time.perf_counter() - t0,
            run_id[:16],
            len(events_df),
            len(detections_df),
            len(behaviors_df),
        )
        _set_run_status(run_id, "running", progress=30, message="Persisting case data...")
        t0 = time.perf_counter()
        actual_run_id = persist_case(events_df, detections_df, behaviors_df, content_hash)
        log.info(
            "[INGEST_PROBE] stage=async_persist_case elapsed_sec=%.3f run_id=%s actual_run_id=%s",
            time.perf_counter() - t0,
            run_id[:16],
            str(actual_run_id)[:16],
        )

        try:
            from dashboard.db import ANALYZING as _DB_ANALYZING, set_run_state as _set_case_state
            _set_case_state(actual_run_id, _DB_ANALYZING, "Async analysis started")
        except Exception as _state_exc:
            log.warning("[STATE] Failed to mark run_id=%s as ANALYZING: %s", str(actual_run_id)[:16], _state_exc)

        try:
            from dashboard.db import dispose_engine as _dispose
            _dispose("cases")
            _dispose("live")
            log.info("[ASYNC] SQLAlchemy pools disposed — fresh connections will be used")
        except Exception as _de:
            log.warning("[ASYNC] dispose_engine failed: %s", _de)

        _set_run_status(run_id, "running", progress=60, message="Executing full analysis pipeline...")
        t_final = time.perf_counter()
        log.info("[FINALIZE] enter terminal-analysis run_id=%s thread_id=%s", actual_run_id[:16], worker_tid)
        context = run_full_analysis(actual_run_id)
        log.info("[FINALIZE] exit terminal-analysis run_id=%s thread_id=%s elapsed_ms=%d context_type=%s", actual_run_id[:16], worker_tid, int((time.perf_counter() - t_final) * 1000), type(context).__name__)
        if isinstance(context, dict):
            # Always write snapshot — even failed/partial contexts must be persisted
            # so the dashboard can show an error instead of spinning forever
            t_final = time.perf_counter()
            log.info("[FINALIZE] enter snapshot-write run_id=%s thread_id=%s payload_keys=%d", actual_run_id[:16], worker_tid, len(context))
            set_analysis_snapshot(actual_run_id, context, authoritative=True)
            log.info("[FINALIZE] exit snapshot-write run_id=%s thread_id=%s elapsed_ms=%d", actual_run_id[:16], worker_tid, int((time.perf_counter() - t_final) * 1000))
        else:
            log.error("[ASYNC] Analysis returned non-dict context for %s: %s", actual_run_id, type(context))
        
        t_final = time.perf_counter()
        log.info("[FINALIZE] enter completion-emit run_id=%s thread_id=%s", run_id[:16], worker_tid)
        if isinstance(context, dict) and str(context.get("status", "")).lower() != "complete":
            errors = context.get("meta", {}).get("errors", []) if isinstance(context.get("meta"), dict) else []
            first_error = errors[0] if errors else {}
            failure_message = first_error.get("traceback_summary") or first_error.get("message") or context.get("error") or context.get("attack_narrative", {}).get("summary") or "Analysis failed."
            failure_stage = first_error.get("stage") or context.get("meta", {}).get("pipeline_stage") or "analysis_failure"
            _set_run_status(
                run_id,
                "error",
                progress=100,
                message=failure_message,
                error=failure_stage,
                actual_run_id=actual_run_id,
            )
        else:
            _set_run_status(run_id, "complete", progress=100, message="Analysis complete.", actual_run_id=actual_run_id)
        log.info("[FINALIZE] exit completion-emit run_id=%s thread_id=%s elapsed_ms=%d", run_id[:16], worker_tid, int((time.perf_counter() - t_final) * 1000))
        log.info("[ASYNC] Analysis complete for run_id=%s -> %s", run_id, actual_run_id)
    except Exception as exc:
        log.error("[ASYNC] Analysis failed for run_id=%s: %s", run_id, exc, exc_info=True)
        _set_run_status(run_id, "error", message=f"Pipeline Failure: {str(exc)}", error=str(exc))
    finally:
        # 9.8: Always release the backpressure slot
        _ANALYSIS_SEMAPHORE.release()
        log.debug("[BACKPRESSURE] Released slot for run_id=%s", run_id[:16])
        log.info("[FINALIZE] exit worker run_id=%s thread_id=%s", run_id[:16], worker_tid)

# ---------------------------------------------------------------------------
# DB init
# ---------------------------------------------------------------------------
def init_db() -> None:
    results = health_check()
    for mode, ok in results.items():
        log.info("DB health check [%s]: %s", mode, "OK" if ok else "FAILED")

# ---------------------------------------------------------------------------
# SIEM background maintenance
# ---------------------------------------------------------------------------
def maintenance_loop() -> None:
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    log.info("[SIEM] Maintenance thread started")
    cutoff_expr = sql_now_minus(24, "HOUR")

    while True:
        try:
            with get_db_connection("live") as conn:
                with get_cursor(conn) as cur:
                    cur.execute(
                        f"DELETE FROM live_events "
                        f"WHERE inserted_at < {cutoff_expr} LIMIT 5000"
                    )
                    deleted = cur.rowcount
                conn.commit()
            if deleted > 0:
                log.info("[SIEM-MAINT] Purged %d stale live_events rows.", deleted)
        except Exception as exc:
            log.error("[SIEM-MAINT] Error during cleanup: %s", exc)

        threading.Event().wait(600)


def start_maintenance() -> None:
    thread = threading.Thread(
        target=maintenance_loop, daemon=True, name="siem-maintenance"
    )
    thread.start()

# ---------------------------------------------------------------------------
# Helpers — data loaders
# ---------------------------------------------------------------------------
_user_col = quote_identifier("user")   # `user` on MySQL


def load_events(run_id: str | None = None, *, limit: int | None = None, offset: int = 0) -> pd.DataFrame:
    """
    FIX-1: Expanded column set to include parent_image, command_line,
    file_path, pid, ppid. Previously these were missing, causing hunt
    console field filters (parent:, cmd:, dst:) to always return 0 results.
    """
    if not run_id:
        return pd.DataFrame()

    mode   = "live" if run_id == "live" else "cases"
    engine = get_engine(mode)
    import pandas as pd
    try:
        query = (
            f"SELECT event_uid, event_time, event_id, image, parent_image, "
            f"command_line, {_user_col}, src_ip, dst_ip, dst_port, "
            f"severity, computer, file_path, run_id, pid, ppid "
            f"FROM events WHERE run_id = :run_id ORDER BY event_time DESC"
        )
        params = {"run_id": run_id}
        if limit is not None:
            query += " LIMIT :limit OFFSET :offset"
            params["limit"] = int(limit)
            params["offset"] = max(int(offset), 0)
        with engine.connect().execution_options(stream_results=True) as conn:
            chunks = pd.read_sql_query(
                text(query),
                conn,
                params=params,
                chunksize=5000,
            )
            frames = [chunk for chunk in chunks if not chunk.empty]
        if not frames:
            return pd.DataFrame()
        df = frames[0].reset_index(drop=True) if len(frames) == 1 else pd.concat(frames, ignore_index=True)
    except Exception as exc:
        log.error("load_events error: %s", exc)
        return pd.DataFrame()

    if df.empty:
        return df

    df = df.rename(columns={
        "src_ip":    "source_ip",
        "dst_ip":    "destination_ip",
        "pid":       "process_id",
        "ppid":      "parent_process_id",
        "file_path": "target_filename",
    })
    if "event_time" in df.columns:
        df["utc_time"] = df["event_time"]
    return df


def load_detections(run_id: str | None = None) -> pd.DataFrame:
    if not run_id:
        return pd.DataFrame()

    mode   = "live" if run_id == "live" else "cases"
    engine = get_engine(mode)
    import pandas as pd
    try:
        df = pd.read_sql_query(
            text("SELECT * FROM detections WHERE run_id = :run_id "
                 "ORDER BY event_time DESC LIMIT 10000"),
            engine,
            params={"run_id": run_id},
        )
    except Exception:
        df = pd.DataFrame()
    return df


def load_correlations(run_id: str | None = None) -> pd.DataFrame:
    if not run_id:
        return pd.DataFrame()

    mode   = "live" if run_id == "live" else "cases"
    engine = get_engine(mode)
    import pandas as pd
    try:
        df = pd.read_sql_query(
            text("SELECT * FROM correlations WHERE run_id = :run_id"),
            engine,
            params={"run_id": run_id},
        )
    except Exception:
        df = pd.DataFrame()
    return df


def load_incident_row(incident_id: str, run_id: str) -> dict | None:
    if not run_id:
        return None
    try:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "SELECT incident_id, status, severity, confidence, escalation, "
                    "analyst, notes, created_at, updated_at "
                    "FROM incidents WHERE incident_id = %s AND run_id = %s",
                    (incident_id, run_id),
                )
                row = cur.fetchone()
                return dict(row) if row else None
    except Exception:
        return None


def load_behaviors(run_id: str | None = None) -> pd.DataFrame:
    if not run_id:
        return pd.DataFrame()

    mode   = "live" if run_id == "live" else "cases"
    engine = get_engine(mode)
    import pandas as pd
    try:
        df = pd.read_sql_query(
            text("SELECT * FROM behaviors WHERE run_id = :run_id ORDER BY event_time DESC"),
            engine,
            params={"run_id": run_id},
        )
    except Exception:
        df = pd.DataFrame()
    return df


# ---------------------------------------------------------------------------
# Internal IP check
# ---------------------------------------------------------------------------
def _is_internal_ip(ip_str: str) -> bool:
    try:
        return ip_address(ip_str).is_private
    except (AddressValueError, ValueError):
        return True


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET","POST"])
def login_page():
    if get_current_user():
        return redirect(url_for("welcome_page"))
    error = None
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        analyst  = authenticate(username, password)
        if analyst:
            login_user(analyst)
            log.info("[AUTH] Login: %s (%s)", username, analyst.get("role"))
            next_url = request.form.get("next") or url_for("welcome_page")
            return redirect(next_url)
        else:
            log.warning("[AUTH] Failed login attempt: %s", username)
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    user = get_current_user()
    if user:
        log.info("[AUTH] Logout: %s", user.get("username"))
    logout_user()
    return redirect(url_for("login_page"))


@app.route("/")
@app.route("/welcome")
def welcome_page():
    if "analysis_run_id" in session:
        old_id = session.pop("analysis_run_id")
        clear_analysis_snapshot(old_id)
    _ = get_flashed_messages()
    return render_template("welcome_upload.html", current_user=get_current_user())


@app.route("/setup-page")
def setup_page():
    return redirect(url_for("welcome_page"))


@app.route("/setup", methods=["POST"], endpoint="setup_upload")
def setup_upload():
    xml_file   = request.files.get("sysmon_xml")
    rules_file = request.files.get("rules_file")

    if not xml_file or xml_file.filename == "":
        flash("Please upload a Sysmon XML file.")
        return redirect(url_for("welcome_page"))

    if not xml_file.filename.lower().endswith(".xml"):
        flash("Invalid file type. Only .xml Sysmon exports are accepted.")
        return redirect(url_for("welcome_page"))

    run_id  = re.sub(r"[^a-zA-Z0-9_-]", "", uuid.uuid4().hex)[:64]
    run_dir = DATA_DIR / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    xml_path = run_dir / "sysmon.xml"
    xml_file.save(str(xml_path))

    try:
        with open(xml_path, "rb") as f:
            parser = ET.iterparse(f, events=("start",))
            _, elem = next(parser)
            if "Events" not in elem.tag:
                flash("Invalid XML: root tag must be <Events>.")
                return redirect(url_for("welcome_page"))
    except Exception as exc:
        log.error("[UPLOAD] Ingestion failed: %s", exc, exc_info=True)
        flash(f"Upload failed: {exc}", "error")
        return redirect(url_for("welcome_page"))

    rules_dest = None
    if rules_file and rules_file.filename:
        rules_ext = Path(rules_file.filename).suffix.lower()
        if rules_ext not in (".yar", ".yara"):
            flash("Only .yar or .yara rule files are supported.")
            return redirect(url_for("welcome_page"))
        rules_dest = run_dir / f"rules{rules_ext}"
        rules_file.save(str(rules_dest))

    _set_run_status(run_id, "processing")
    session["analysis_run_id"] = run_id
    clear_analysis_snapshot(run_id)

    threading.Thread(
        target=_run_analysis_async,
        args=(run_id, xml_path, rules_dest),
        daemon=True,
        name=f"analysis-{run_id[:8]}",
    ).start()
    log.info("[UPLOAD] Kicked off async analysis thread for run_id=%s", run_id)

    flash("Sysmon logs uploaded successfully. Threat analysis and timeline reconstruction are in progress.")
    return redirect(url_for("dashboard_status", run_id=run_id))


# ---------------------------------------------------------------------------
# Async status routes
# ---------------------------------------------------------------------------

@app.route("/dashboard/status/<run_id>")
def dashboard_status(run_id: str):
    safe = re.sub(r"[^a-zA-Z0-9_-]", "", run_id)[:64]
    status = _get_run_status(safe)
    messages = get_flashed_messages(with_categories=True)
    
    state = status.get("state")
    if state == "complete" or state.startswith("done:"):
        actual = status.get("run_id") or (state.split(":", 1)[1] if ":" in state else safe)
        session["analysis_run_id"] = actual
        resp = redirect(url_for("dashboard", run_id=actual))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return resp
    if state == "error" or state.startswith("error:"):
        msg = status.get("message") or status.get("error") or "Unknown error"
        flash(f"Analysis failed: {msg}", "error")
        return redirect(url_for("welcome_page"))

    api_url = url_for("api_run_status", run_id=safe)
    from html import escape as _escape
    flash_html = ""
    if messages:
        flash_html = "<div class='flash-stack'>" + "".join(
            f"<div class='flash {'error' if category == 'error' else 'info'}'>{_escape(str(message))}</div>"
            for category, message in messages
        ) + "</div>"
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelTrace — Analysing…</title>
<style>
  :root{{--bg:#0f172a;--card:rgba(30,41,59,.9);--blue:#60a5fa;--muted:#94a3b8;--dim:#475569}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:#f1f5f9;
       display:flex;align-items:center;justify-content:center;min-height:100vh}}
  .card{{background:var(--card);border:1px solid rgba(148,163,184,.15);border-radius:16px;
         padding:40px 40px;width:100%;max-width:520px;text-align:center}}
  .flash-stack{{display:grid;gap:10px;margin-bottom:20px;text-align:left}}
  .flash{{padding:12px 14px;border-radius:10px;font-size:13px;line-height:1.5;border:1px solid transparent}}
  .flash.info{{background:rgba(96,165,250,.12);border-color:rgba(96,165,250,.25);color:#bfdbfe}}
  .flash.error{{background:rgba(248,113,113,.12);border-color:rgba(248,113,113,.25);color:#fecaca}}
  .spinner{{width:56px;height:56px;border:4px solid #1e293b;border-top-color:var(--blue);
            border-radius:50%;animation:spin 0.9s linear infinite;margin:0 auto 28px}}
  @keyframes spin{{to{{transform:rotate(360deg)}}}}
  h2{{font-size:20px;font-weight:700;margin-bottom:10px;color:#f1f5f9}}
  .sub{{font-size:13px;color:var(--muted);margin-bottom:28px;line-height:1.6}}
  .bar-wrap{{background:#1e293b;border-radius:6px;height:8px;overflow:hidden;margin-bottom:8px}}
  .bar{{height:100%;background:var(--blue);border-radius:6px;transition:width 1s ease;width:5%}}
  .pct{{font-size:11px;color:var(--dim);margin-bottom:20px;font-family:monospace}}
  .stage{{background:#0f172a;border:1px solid rgba(148,163,184,.12);border-radius:8px;
          padding:14px;font-size:12px;color:var(--muted);text-align:left;line-height:1.8}}
  .stage .active{{color:var(--blue);font-weight:600}}
  .stage .done{{color:#34d399}}
  .stage .pending{{color:var(--dim)}}
  .elapsed{{font-size:10px;color:var(--dim);margin-top:16px;font-family:monospace}}
  .stage-detail{{margin-top:10px;font-size:11px;color:#cbd5e1;font-family:monospace;line-height:1.5;min-height:18px}}
</style>
</head>
<body>
<div class="card">
    {flash_html}
  <div class="spinner"></div>
  <h2>Analysing Sysmon Data</h2>
  <p class="sub">Processing your endpoint telemetry through the<br>
  detection &amp; correlation pipeline…</p>
  <div class="bar-wrap"><div class="bar" id="bar"></div></div>
  <div class="pct" id="pct">0% — Starting…</div>
  <div class="stage">
    <div id="s1" class="active">① Parsing XML events</div>
    <div id="s2" class="pending">② Enriching signals</div>
    <div id="s3" class="pending">③ Running detection rules</div>
    <div id="s4" class="pending">④ Persisting to database</div>
    <div id="s5" class="pending">⑤ Building behavior baseline</div>
    <div id="s6" class="pending">⑥ Correlation &amp; scoring</div>
  </div>
  <div class="elapsed" id="elapsed">Elapsed: 0s</div>
    <div class="stage-detail" id="stage-detail">Waiting for progress...</div>
</div>
<script>
const API = "{api_url}";
const start = Date.now();
let tick = 0;
let stopped = false;
const stages = [
  [0,  5,  's1', '① Parsing XML events'],
  [5,  20, 's2', '② Enriching signals'],
  [20, 40, 's3', '③ Running detection rules'],
  [40, 60, 's4', '④ Persisting to database'],
  [60, 80, 's5', '⑤ Building behavior baseline'],
  [80, 99, 's6', '⑥ Correlation & scoring'],
];
const stageIds = ['s1','s2','s3','s4','s5','s6'];
function setProgress(pct, label) {{
  document.getElementById('bar').style.width = pct + '%';
  document.getElementById('pct').textContent = pct + '% — ' + label;
  let activeIdx = stages.length - 1;
  for (let i = 0; i < stages.length; i++) {{
    const [low, high] = stages[i];
    if (pct >= low && pct < high) {{ activeIdx = i; break; }}
  }}
  stageIds.forEach((id, i) => {{
    const el = document.getElementById(id);
    if (i < activeIdx) {{
      el.className = 'done';
      el.textContent = '✓ ' + stages[i][3].slice(2);
    }} else if (i === activeIdx) {{
      el.className = 'active';
    }} else {{
      el.className = 'pending';
    }}
  }});
}}
function updateElapsed() {{
  const s = Math.floor((Date.now() - start) / 1000);
  document.getElementById('elapsed').textContent = 'Elapsed: ' + s + 's';
}}
function updateStageDetail(data) {{
    const el = document.getElementById('stage-detail');
    if (!el) return;
    if (!data) {{
        el.textContent = 'Waiting for progress...';
        return;
    }}
    const parts = [];
    if (data.active_stage) parts.push('Stage: ' + data.active_stage);
    if (data.operation_label) parts.push('Operation: ' + data.operation_label);
    if (typeof data.stage_elapsed_seconds === 'number' && data.stage_elapsed_seconds >= 0) {{
        parts.push('Stage time: ' + data.stage_elapsed_seconds.toFixed(1) + 's');
    }}
    if (Number.isFinite(data.processed_events) && Number.isFinite(data.total_events) && data.total_events > 0) {{
        parts.push('Events: ' + data.processed_events + '/' + data.total_events);
    }}
    if (data.metrics && typeof data.metrics === 'object') {{
        const metrics = [];
        if (Number.isFinite(data.metrics.parent_lookup_count)) metrics.push('parent lookups ' + data.metrics.parent_lookup_count);
        if (Number.isFinite(data.metrics.grandparent_lookup_count)) metrics.push('grandparent lookups ' + data.metrics.grandparent_lookup_count);
        if (Number.isFinite(data.metrics.resolved_grandparent_count)) metrics.push('resolved ' + data.metrics.resolved_grandparent_count);
        if (metrics.length) parts.push(metrics.join(' · '));
    }}
    if (data.watchdog_warning && typeof data.watchdog_warning === 'object') {{
        const warning = data.watchdog_warning;
        const note = warning.active_stage || warning.operation_label || 'watchdog';
        parts.push('Watchdog: ' + note + ' idle ' + (warning.idle_seconds ?? '?') + 's');
    }}
    el.textContent = parts.length ? parts.join(' · ') : (data.message || 'Processing...');
}}
async function poll() {{
  if (stopped) return;
  tick++;
  // 9.8 UI TIMEOUT: 600 polls × 2s = 20-minute hard limit
  if (tick > 600) {{
    stopped = true;
    document.querySelector('h2').textContent = 'Analysis Timed Out';
    document.querySelector('.sub').textContent = 'Exceeded 20 minutes. The system may be overloaded. Please re-upload your file.';
    document.getElementById('bar').style.background = '#f97316';
    document.getElementById('pct').textContent = 'Timed out after 20 minutes';
    return;
  }}
  updateElapsed();
  try {{
    const resp = await fetch(API, {{cache: 'no-store'}});
    const data = await resp.json();
    if (data.status === 'done') {{
      stopped = true;
      setProgress(100, 'Complete!');
        updateStageDetail(data);
      document.getElementById('elapsed').textContent += ' — Redirecting…';
      setTimeout(() => {{ window.location.href = data.redirect; }}, 800);
      return;
    }}
    if (data.status === 'error') {{
      stopped = true;
      document.querySelector('h2').textContent = 'Analysis Failed';
      document.querySelector('.sub').textContent = data.message || data.error || 'Unknown pipeline error';
      document.getElementById('bar').style.background = '#f87171';
      document.getElementById('pct').textContent = 'Analysis failed';
    updateStageDetail(data);
      return;
    }}
    if (data.progress) {{
      const sp = Math.min(97, data.progress);
      const sl = stages.find(s => sp >= s[0] && sp < s[1]);
      setProgress(sp, sl ? sl[3] : (data.message || 'Processing…'));
    updateStageDetail(data);
      updateElapsed();
      setTimeout(poll, 2000);
      return;
    }}
  }} catch(e) {{}}
  const elapsed = (Date.now() - start) / 1000;
  let pct;
  if (elapsed < 5)       pct = Math.min(15, tick * 2);
  else if (elapsed < 20) pct = Math.min(35, 15 + (elapsed-5)*1.5);
  else if (elapsed < 50) pct = Math.min(60, 35 + (elapsed-20)*0.8);
  else if (elapsed < 90) pct = Math.min(85, 60 + (elapsed-50)*0.6);
  else                   pct = Math.min(97, 85 + (elapsed-90)*0.1);
  const stageLabel = stages.find(s => pct >= s[0] && pct < s[1]);
  setProgress(Math.floor(pct), stageLabel ? stageLabel[3] : 'Finalising…');
    updateStageDetail({{message: stageLabel ? stageLabel[3] : 'Finalising…'}});
  updateElapsed();
  setTimeout(poll, 2000);
}}
poll();
setInterval(updateElapsed, 1000);
</script>
</body>
</html>"""
    return body, 200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }


@app.route("/api/run/status/<run_id>")
def api_run_status(run_id: str):
    safe   = re.sub(r"[^a-zA-Z0-9_-]", "", run_id)[:64]
    status = _get_run_status(safe)
    now_ts = time.time()
    
    state = status.get("state", "unknown")
    last_progress_ts = status.get("last_progress_timestamp") or status.get("updated_at")
    watchdog_warning = None
    if state in ("running", "processing") and isinstance(last_progress_ts, (int, float)):
        idle_seconds = max(0.0, now_ts - float(last_progress_ts))
        if idle_seconds >= 120:
            watchdog_warning = {
                "type": "stalled_progress",
                "idle_seconds": round(idle_seconds, 3),
                "active_stage": status.get("active_stage", ""),
                "operation_label": status.get("operation_label", ""),
                "last_progress_timestamp": last_progress_ts,
            }
    if state == "complete" or state.startswith("done:"):
        actual = status.get("run_id") or (state.split(":", 1)[1] if ":" in state else safe)
        return jsonify({
            "status": "done",
            "run_id": actual,
            "redirect": url_for("dashboard", run_id=actual),
            "last_progress_timestamp": last_progress_ts,
            "watchdog_warning": watchdog_warning,
        })
    if state == "error" or state.startswith("error:"):
        msg = status.get("message") or "Pipeline Failure"
        return jsonify({"status": "error", "message": msg, "last_progress_timestamp": last_progress_ts, "watchdog_warning": watchdog_warning})
    
    return jsonify({
        "status": state,
        "progress": status.get("progress", 0),
        "message": status.get("message", "Processing..."),
        "active_stage": status.get("active_stage", ""),
        "stage_elapsed_seconds": status.get("stage_elapsed_seconds", 0.0),
        "processed_events": status.get("processed_events", 0),
        "total_events": status.get("total_events", 0),
        "operation_label": status.get("operation_label", ""),
        "metrics": status.get("metrics", {}),
        "last_progress_timestamp": last_progress_ts,
        "watchdog_warning": watchdog_warning,
    })


# ---------------------------------------------------------------------------
# SOC Live APIs (disabled — upload-only mode)
# ---------------------------------------------------------------------------
@app.route("/api/live/events")
def api_live_events():
    return jsonify({"events": [], "last_row_id": 0, "info": "Live mode removed"})

@app.route("/api/live/status")
def api_live_status():
    return jsonify({"status": "DISABLED", "latency": -1, "info": "Live mode removed"})

@app.route("/api/live/metrics")
def api_live_metrics():
    return jsonify({"eps_sma": 0, "beaconing": [], "process_bursts": [], "info": "Live mode removed"})

@app.route("/api/collector/metrics")
def api_collector_metrics():
    return jsonify({"collector_available": False, "info": "Live collector removed"}), 503


# ---------------------------------------------------------------------------
# Core UI
# ---------------------------------------------------------------------------
@app.route("/live")
def live_dashboard():
    flash("Live monitoring has been removed. Please upload a Sysmon XML file.")
    return redirect(url_for("welcome_page"))


@app.route("/dashboard/<run_id>")
def dashboard(run_id):
    safe_run_id = re.sub(r"[^a-zA-Z0-9_-]", "", run_id)[:64]
    if not safe_run_id:
        flash("Invalid run ID.", "error")
        return redirect(url_for("welcome_page"))
    log.debug("Dashboard requested for run_id=%s", safe_run_id)
    session["analysis_run_id"] = safe_run_id

    status = _get_run_status(safe_run_id)
    state = status.get("state", "unknown") if isinstance(status, dict) else str(status)
    if state in ("processing", "running"):
        return redirect(url_for("dashboard_status", run_id=safe_run_id))
    if state == "error" or (isinstance(state, str) and state.startswith("error:")):
        err_msg = status.get("message") or status.get("error") or state
        flash(f"Analysis failed: {err_msg}", "error")
        return redirect(url_for("welcome_page"))

    from dashboard.analysis_engine_patch import patched_run_full_analysis as run_full_analysis
    from dashboard.analysis_engine import _PerfTimer, _emit_analysis_profile_summary
    import cProfile

    context = None
    _dashboard_perf = _PerfTimer(safe_run_id)
    _dashboard_profiler = cProfile.Profile()
    _dashboard_profiler.enable()
    try:
        t0 = time.perf_counter()
        context = get_analysis_snapshot_slice(safe_run_id, timeline_limit=50)
        log.info(
            "[INGEST_PROBE] stage=dashboard_snapshot_read elapsed_sec=%.3f run_id=%s cache_hit=%s",
            time.perf_counter() - t0,
            safe_run_id[:16],
            bool(context),
        )
        _dashboard_perf.lap("dashboard_snapshot_read")
        if context:
            log.debug("[DASHBOARD] cache hit for %s", safe_run_id)
            # Propagate failed snapshots to the user immediately
            if context.get("status") == "failed":
                err = context.get("error") or context.get("attack_narrative", {}).get("summary", "Pipeline error")
                log.warning("[DASHBOARD] cached snapshot has status=failed for %s: %s", safe_run_id, err)
                flash(f"Analysis failed: {err}", "error")
                return redirect(url_for("welcome_page"))
        else:
            log.info("[DASHBOARD] running fresh analysis for %s", safe_run_id)
            context = run_full_analysis(safe_run_id)
            if context:
                set_analysis_snapshot(safe_run_id, context, authoritative=True)

        if not context:
            flash("Analysis failed or expired. Please re-upload.", "error")
            return redirect(url_for("welcome_page"))

        if isinstance(status, dict):
            context["active_stage"] = status.get("active_stage") or context.get("active_stage") or context.get("meta", {}).get("pipeline_stage", "")
            context["operation_label"] = status.get("operation_label") or context.get("operation_label") or ""
            context["progress"] = status.get("progress", context.get("progress", 0))
            context["watchdog_warning"] = status.get("watchdog_warning")

        context["run_id"] = safe_run_id
        context.setdefault("baseline_execution_context", [])
        context.setdefault("baseline_noise_count", len(context["baseline_execution_context"]))

        correlation_campaigns = _template_safe_records(
            context.get("correlation_campaigns", []),
            string_keys={"corr_id", "corrid"},
        )

        t0 = time.perf_counter()
        response = render_template(
            "index.html",
            run_id=safe_run_id,
            current_user=get_current_user(),
            severity_counts=context.get("events_by_severity", {}),
            correlation_campaigns=correlation_campaigns,
            correlations_detail=context.get("correlations_detail", []),
            lolbins_summary=context.get("lolbins_summary", []),
            forensic_metadata=context.get("forensic_metadata", {}),
            time_range=context.get("time_range", "all"),
            q=context.get("q", ""),
            attack_conf_score=context.get("attack_conf_score"),
            attack_conf_level=context.get("attack_conf_level"),
            attack_conf_basis=context.get("attack_conf_basis"),
            attack_conf_cap=context.get("attack_conf_cap"),
            is_alertable=context.get("is_alertable", False),
            correlation_score=context.get("correlation_score", 0),
            effective_urgency=context.get("effective_urgency"),
            next_expected_stage=context.get("next_expected_stage"),
            missing_evidence=context.get("missing_evidence", []),
            dominant_burst=context.get("dominant_burst"),
            confidence_trend=context.get("confidence_trend", []),
            analyst_verdict=context.get("analyst_verdict"),
            analyst_action=context.get("analyst_action"),
            action_priority=context.get("action_priority"),
            action_reason=context.get("action_reason"),
            response_tasks=context.get("response_tasks", []),
            incident=context.get("incident"),
            source_file_hash=context.get("source_file_hash"),
            kill_chain_summary=context.get("kill_chain_summary", []),
            kc_severity=context.get("kc_severity", {}),
            evidence_state=context.get("evidence_state", {}),
            correlation_hunts=context.get("correlation_hunts", []),
            highest_kill_chain=context.get("highest_kill_chain"),
            total_events=context.get("total_events", 0),
            high_count=context.get("high_count", 0),
            medium_count=context.get("medium_count", 0),
            low_count=context.get("low_count", 0),
            detections_count=context.get("detections_count", 0),
            events_by_severity=context.get("events_by_severity", {"high": 0, "medium": 0, "low": 0}),
            events_per_hour=context.get("events_per_hour", []),
            top_events=context.get("top_events", []),
            mitre_summary=context.get("mitre_summary", []),
            burst_aggregates=_preview_items(context.get("burst_aggregates", []), 15),
            interesting=_preview_items(context.get("interesting", []), 30),
            recent=_preview_items(context.get("recent", []), 30),
            detections=_preview_items(context.get("detections", []), 30),
            correlations=context.get("correlations", []),
            timeline=_preview_items(context.get("timeline", []), 50),
            baseline_noise_count=context.get("baseline_noise_count", 0),
            baseline_execution_context=_preview_items(context.get("baseline_execution_context", []), 20),
            baseline_stats=_preview_items(context.get("baseline_execution_context", []), 20),
            top_dangerous_bursts=context.get("top_dangerous_bursts", []),
            sequence_detections=context.get("sequence_detections", []),
            attack_narrative=context.get("attack_narrative", {}),
            recommended_action=context.get("recommended_action", "BASELINE"),
            # [FIX] These keys are required by index.html but were missing from render_template
            incidents=context.get("incidents", []),
            pipeline_error=context.get("pipeline_error"),
        )
        response_bytes = len(response.encode("utf-8"))
        log.info(
            "[INGEST_PROBE] stage=dashboard_render elapsed_sec=%.3f response_bytes=%d run_id=%s timeline=%d detections=%d bursts=%d incidents=%d",
            time.perf_counter() - t0,
            response_bytes,
            safe_run_id[:16],
            len(context.get("timeline", [])),
            len(context.get("detections", [])),
            len(context.get("burst_aggregates", [])),
            len(context.get("incidents", [])),
        )
        meta = context.setdefault("meta", {})
        profiling_inputs = meta.setdefault("profiling_inputs", {})
        profiling_inputs["dashboard_serialization"] = {
            "response_bytes": response_bytes,
            "timeline_entries": len(context.get("timeline", [])),
            "burst_aggregate_entries": len(context.get("burst_aggregates", [])),
            "detections_entries": len(context.get("detections", [])),
            "serialization_elapsed_seconds": round(time.perf_counter() - t0, 6),
            "preview_materializations": 6,
        }
        _dashboard_perf.lap("dashboard_render")
        return response
    finally:
        try:
            _emit_analysis_profile_summary(
                safe_run_id,
                _dashboard_profiler,
                _dashboard_perf,
                context if isinstance(context, dict) else None,
                "dashboard",
                attach_to_context=False,
            )
        except Exception as _profile_exc:
            log.warning("[PROFILE] dashboard profiling summary failed for %s: %s", safe_run_id[:16], _profile_exc)


# ---------------------------------------------------------------------------
# Incident lifecycle actions
# ---------------------------------------------------------------------------
@app.route("/details")
def details():
    run_id = session.get("analysis_run_id")
    if not run_id:
        return redirect(url_for("welcome_page"))

    context = get_analysis_snapshot_slice(run_id, timeline_limit=100)
    if not context:
        flash("Please open dashboard first to initialize analysis.")
        return redirect(url_for("dashboard", run_id=run_id))

    safe_dets = _template_safe_records(
        _preview_items(context.get("detections", []), 100),
        string_keys={"mitre_id", "rule_id"},
    )
    safe_corrs = _template_safe_records(
        context.get("correlations", []),
        string_keys={"corr_id", "corrid"},
    )
    safe_timeline = _template_safe_records(_preview_items(context.get("timeline", []), 100))

    return render_template(
        "details.html",
        analysis_run_id=context.get("analysis_run_id", run_id),
        incident=context.get("incident"),
        timeline=safe_timeline,
        detections=safe_dets,
        correlations=safe_corrs,
        current_user=get_current_user(),
    )


@app.route("/incident/update", methods=["POST"])
def update_incident():
    run_id      = session.get("analysis_run_id")
    incident_id = request.form.get("incident_id")
    if not incident_id or not run_id:
        return redirect(url_for("dashboard", run_id=run_id))

    action  = request.form.get("action", "save")
    analyst = request.form.get("analyst", "").strip() or None
    now     = now_utc().isoformat(timespec="seconds") + "Z"

    status_map = {
        "false_positive": ("Closed - False Positive", "False Positive"),
        "escalate":       ("Escalated",               "Incident"),
        "close_benign":   ("Closed - Benign",          "Benign"),
    }

    try:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                if action in status_map:
                    status, escalation = status_map[action]
                    cur.execute(
                        "UPDATE incidents SET status = %s, "
                        "escalation = COALESCE(%s, escalation), "
                        "analyst = COALESCE(%s, analyst), updated_at = %s "
                        "WHERE incident_id = %s AND run_id = %s",
                        (status, escalation, analyst, now, incident_id, run_id),
                    )
                else:
                    status = request.form.get("status") or None
                    if status:
                        cur.execute(
                            "UPDATE incidents SET status = %s, "
                            "analyst = COALESCE(%s, analyst), updated_at = %s "
                            "WHERE incident_id = %s AND run_id = %s",
                            (status, analyst, now, incident_id, run_id),
                        )
                    else:
                        cur.execute(
                            "UPDATE incidents SET "
                            "analyst = COALESCE(%s, analyst), updated_at = %s "
                            "WHERE incident_id = %s AND run_id = %s",
                            (analyst, now, incident_id, run_id),
                        )
            conn.commit()
    except Exception as exc:
        flash(f"Error updating incident: {exc}", "error")

    return redirect(url_for("dashboard", run_id=run_id))


@app.route("/incident/note", methods=["POST"])
def add_incident_note():
    run_id      = session.get("analysis_run_id")
    incident_id = request.form.get("incident_id")
    note        = (request.form.get("note") or "").strip()

    if not incident_id or not note or not run_id:
        return redirect(url_for("dashboard", run_id=run_id))

    now = now_utc().isoformat(timespec="seconds") + "Z"
    try:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "SELECT notes FROM incidents "
                    "WHERE incident_id = %s AND run_id = %s",
                    (incident_id, run_id),
                )
                row      = cur.fetchone()
                existing = (row["notes"] if row and row["notes"] else "")
                combined = (existing + "\n" + f"[{now}] {note}").strip()
                cur.execute(
                    "UPDATE incidents SET notes = %s, updated_at = %s "
                    "WHERE incident_id = %s AND run_id = %s",
                    (combined, now, incident_id, run_id),
                )
            conn.commit()
    except Exception as exc:
        flash(f"Error adding note: {exc}", "error")

    return redirect(url_for("dashboard", run_id=run_id))


# ---------------------------------------------------------------------------
# Process detail view
# ---------------------------------------------------------------------------
@app.route("/process/<path:image>")
def process_view(image):
    image = image.strip()
    if not image:
        return "Missing image parameter", 400

    run_id = session.get("analysis_run_id")
    df     = load_events(run_id)

    if df.empty:
        proc_df        = df.iloc[0:0]
        parent_summary = child_summary = []
        total          = 0
    else:
        proc_df = df[df["image"] == image]
        total   = len(proc_df)

        parent_summary = (
            proc_df.groupby("parent_image").size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .to_dict(orient="records")
        ) if "parent_image" in proc_df.columns else []

        child_summary = (
            df[df["parent_image"] == image]
            .groupby("image").size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .to_dict(orient="records")
        ) if "parent_image" in df.columns else []

    return render_template(
        "process.html",
        image=image,
        events=proc_df.to_dict(orient="records"),
        total=total,
        parent_summary=parent_summary,
        child_summary=child_summary,
    )


# ---------------------------------------------------------------------------
# Burst view
# ---------------------------------------------------------------------------
_RISK_CRITICAL_IDS   = {"1", "8", "9", "12", "13", "14", "19", "25"}
_RISK_MEDIUM_IDS     = {"3", "11", "17", "18", "22"}
_RISK_CRITICAL_BONUS = 60
_RISK_MEDIUM_BONUS   = 20
_RISK_HIGH_VOL_BONUS = 15
_RISK_MED_VOL_BONUS  = 5
_RISK_EXTERNAL_BONUS = 10
_RISK_MAX            = 100


@app.route("/burst/")
@app.route("/burst")
def burst_missing_redirect():
    run_id = session.get("analysis_run_id")
    if run_id:
        return redirect(url_for("dashboard", run_id=run_id))
    return redirect(url_for("welcome_page"))


@app.route("/burst/<burst_id>")
def burst_view(burst_id):
    run_id = session.get("analysis_run_id")
    if not run_id:
        return redirect(url_for("welcome_page"))

    context = get_analysis_snapshot_slice(run_id, timeline_limit=20)
    if not context or "burst_aggregates" not in context:
        flash("Burst data not found. Please refresh the Dashboard.")
        return redirect(url_for("dashboard", run_id=run_id))

    all_bursts = (
        context.get("burst_aggregates", [])
        + context.get("top_dangerous_bursts", [])
        + context.get("timeline", [])
    )
    burst = next(
        (b for b in all_bursts if str(b.get("burst_id")) == str(burst_id)), None
    )
    if not burst:
        return f"Burst not found: {burst_id}", 404

    image = burst.get("image")
    start = burst.get("start_time")
    end   = burst.get("end_time")

    _burst_mode = "live" if run_id == "live" else "cases"
    try:
        with get_db_connection(_burst_mode) as conn:
            with get_cursor(conn) as cur:
                # FIX-3: `user` quoted, explicit column list avoids reserved-word errors
                _cols = (
                    f"event_time, event_id, image, parent_image, command_line, "
                    f"{_user_col}, pid, ppid, src_ip, dst_ip, dst_port, file_path, computer"
                )
                if image and start and end:
                    _start_s = sanitize_datetime(start) or start
                    _end_s   = sanitize_datetime(end)   or end
                    cur.execute(
                        f"SELECT {_cols} FROM events "
                        f"WHERE image = %s AND event_time >= %s AND event_time <= %s "
                        f"AND run_id = %s ORDER BY event_time LIMIT 500",
                        (image, _start_s, _end_s, run_id),
                    )
                elif image:
                    cur.execute(
                        f"SELECT {_cols} FROM events "
                        f"WHERE image = %s AND run_id = %s "
                        f"ORDER BY event_time LIMIT 500",
                        (image, run_id),
                    )
                else:
                    return "Invalid burst: missing image", 400

                events = [dict(r) for r in cur.fetchall()]

                cur.execute(
                    "SELECT DISTINCT image FROM events "
                    "WHERE parent_image = %s AND run_id = %s LIMIT 50",
                    (image, run_id),
                )
                child_images = sorted(
                    r["image"] for r in cur.fetchall() if r.get("image")
                )
    except Exception as exc:
        log.error("burst_view error for burst_id=%s: %s", burst_id, exc, exc_info=True)
        flash(f"Error loading burst details: {exc}", "error")
        return redirect(url_for("dashboard", run_id=run_id))

    risk_score = 0
    unique_ids = {str(e.get("event_id")) for e in events}
    if unique_ids & _RISK_CRITICAL_IDS:
        risk_score += _RISK_CRITICAL_BONUS
    if unique_ids & _RISK_MEDIUM_IDS:
        risk_score += _RISK_MEDIUM_BONUS
    if len(events) > 50:
        risk_score += _RISK_HIGH_VOL_BONUS
    elif len(events) > 10:
        risk_score += _RISK_MED_VOL_BONUS
    if any(not _is_internal_ip(e["dst_ip"]) for e in events if e.get("dst_ip")):
        risk_score += _RISK_EXTERNAL_BONUS
    risk_score = min(risk_score, _RISK_MAX)

    burst_meta = {
        "burst_id":    burst_id,
        "image":       image,
        "start_time":  start,
        "end_time":    end,
        "event_count": len(events),
        "risk_score":  burst.get("peak_score") or risk_score,
        "stage_cap":   burst.get("stage_cap", 100),
        "kill_chain_stage": burst.get("kill_chain_stage", "Execution"),
        "has_correlation":  burst.get("has_correlation", False),
        "score_ledger":     burst.get("score_ledger", []),
        "baseline_sub_scores": burst.get("baseline_sub_scores", {}),
        "baseline_anomalies":  burst.get("baseline_anomalies", []),
        "confidence_reasons":  burst.get("confidence_reasons", []),
        "event_ids":   [e.get("event_id") for e in events if e.get("event_id") is not None],
    }
    process_summary = {
        "parents":   sorted({e["parent_image"] for e in events if e.get("parent_image")}),
        "children":  child_images,
        "processes": sorted({e.get("image") for e in events if e.get("image")}),
    }

    from dashboard.analysis_engine import build_attack_story

    # FIX-2: Sanitise timestamps AND add field aliases so burst.html template
    # can access both column name variants (dst_ip + destination_ip, etc.)
    safe_events = []
    for ev in events:
        clean = {}
        for k, v in ev.items():
            clean[k] = v.isoformat() if hasattr(v, 'isoformat') else v
        # Add aliases so template works regardless of DB column naming
        clean.setdefault("destination_ip",   clean.get("dst_ip"))
        clean.setdefault("destination_port", clean.get("dst_port"))
        clean.setdefault("target_filename",  clean.get("file_path"))
        safe_events.append(clean)

    # ── Burst Storyline & Explainability ──
    burst_detections = []
    if context.get("detections"):
        for d in context["detections"]:
            # Match detection to this burst by image and time
            if d.get("image") == image:
                d_time = d.get("event_time") or d.get("utc_time")
                if d_time and start and end and start <= str(d_time) <= end:
                    burst_detections.append(d)

    attack_story = build_attack_story(safe_events, burst_detections)
    burst_meta["attack_story"] = attack_story
    
    # Grab the match_reason for explainability
    if burst_detections:
        top_det = max(burst_detections, key=lambda x: x.get("confidence_score", 0), default=None)
        burst_meta["top_detection_reasons"] = top_det.get("match_reason", []) if top_det else []
    else:
        burst_meta["top_detection_reasons"] = []

    return render_template(
        "burst.html",
        burst=burst_meta,
        process_summary=process_summary,
        events=safe_events,
        current_user=get_current_user(),
    )


# ---------------------------------------------------------------------------
# CSV exports
# ---------------------------------------------------------------------------
@app.route("/api/events.csv")
def export_events_csv():
    run_id = session.get("analysis_run_id")
    df = load_events(run_id)
    if df.empty:
        return "No events available", 404

    out    = io.StringIO()
    df_out = df.copy()
    if "tags" in df_out.columns:
        df_out["tags"] = df_out["tags"].apply(
            lambda lst: ",".join(lst) if isinstance(lst, list) else (lst or "")
        )
    df_out.to_csv(out, index=False)
    out.seek(0)
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )


@app.route("/api/detections.csv")
def export_detections_csv():
    run_id = session.get("analysis_run_id")
    det = load_detections(run_id)
    if det.empty:
        return "No detections available", 404

    out = io.StringIO()
    det.to_csv(out, index=False)
    out.seek(0)
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=detections.csv"},
    )


# ---------------------------------------------------------------------------
# Raw events (paginated)
# ---------------------------------------------------------------------------
@app.route("/raw-events")
def raw_events():
    run_id = session.get("analysis_run_id")
    if not run_id:
        return redirect(url_for("welcome_page"))

    page      = max(1, int(request.args.get("page", 1)))
    page_size = 50
    offset    = (page - 1) * page_size

    try:
        _raw_mode = "live" if run_id == "live" else "cases"
        with get_db_connection(_raw_mode) as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    f"SELECT event_time, event_id, image, {_user_col}, "
                    f"src_ip, dst_ip, command_line "
                    f"FROM events WHERE run_id = %s "
                    f"ORDER BY event_time DESC LIMIT %s OFFSET %s",
                    (run_id, page_size, offset),
                )
                events = [dict(r) for r in cur.fetchall()]
    except Exception as exc:
        flash(f"Error loading raw events: {exc}", "error")
        events = []

    return render_template(
        "raw_events.html",
        analysis_run_id=run_id,
        events=events,
        page=page,
        has_next=(len(events) == page_size),
    )


# ---------------------------------------------------------------------------
# Threat Hunting APIs
# ---------------------------------------------------------------------------

@app.route("/api/hunt")
def api_hunt():
    """
    Ad-hoc threat hunt query against current run's events.
    FIX-1 ensures load_events() now returns parent_image, command_line,
    destination_ip etc. so hunt field filters actually work.
    """
    run_id = session.get("analysis_run_id") or request.args.get("run_id")
    query  = request.args.get("q", "").strip()
    try:
        limit = request.args.get("limit")
        offset = max(int(request.args.get("offset", 0)), 0)
        limit = int(limit) if limit not in (None, "") else None
    except ValueError:
        return jsonify({"error": "Invalid pagination parameters", "results": []}), 400
    if not run_id:
        return jsonify({"error": "No active run", "results": []})
    df = load_events(run_id)
    if df.empty:
        return jsonify({"results": [], "count": 0, "query": query, "offset": offset, "limit": limit, "has_more": False})
    try:
        result_df = hunt_query(df, query) if query else df
        total = len(result_df)
        if limit is not None:
            result_df = result_df.iloc[offset:offset + max(limit, 0)]
        else:
            result_df = result_df.iloc[offset:]
        for col in result_df.columns:
            if result_df[col].dtype.name.startswith("datetime"):
                result_df[col] = result_df[col].astype(str)
        records = result_df.fillna("").to_dict(orient="records")
        next_offset = offset + len(records)
        has_more = next_offset < total
        return jsonify({
            "results": records,
            "count": len(records),
            "total": total,
            "query": query,
            "offset": offset,
            "limit": limit,
            "next_offset": next_offset,
            "has_more": has_more,
        })
    except Exception as exc:
        return jsonify({"error": str(exc), "results": [], "query": query})


@app.route("/api/process-tree/<run_id>")
def api_process_tree(run_id):
    df = load_events(run_id)
    if df.empty:
        return jsonify({"tree": [], "flat": []})
    try:
        if "parent_image" not in df.columns and "parent_process_id" in df.columns:
            df["parent_image"] = None
        roots = build_process_tree(df)
        flat  = flatten_process_tree(roots)
        return jsonify({"tree": roots[:200], "flat": flat[:500], "run_id": run_id})
    except Exception as exc:
        return jsonify({"error": str(exc), "tree": [], "flat": []})


@app.route("/api/beaconing/<run_id>")
def api_beaconing(run_id):
    df = load_events(run_id)
    if df.empty:
        return jsonify({"beacons": [], "run_id": run_id})
    try:
        if "destination_ip" not in df.columns and "dst_ip" in df.columns:
            df["destination_ip"] = df["dst_ip"]
        beacons = detect_beaconing(df)
        return jsonify({"beacons": beacons, "run_id": run_id, "count": len(beacons)})
    except Exception as exc:
        return jsonify({"error": str(exc), "beacons": []})


@app.route("/api/iocs/<run_id>")
def api_iocs(run_id):
    df = load_events(run_id)
    if df.empty:
        return jsonify({"iocs": [], "run_id": run_id})
    try:
        # Use the flat IOC extractor from soc_verdict (returns ioc_type/ioc_value dicts)
        # NOT the old extract_iocs from analysis_engine (returns {"ips":[], "files":[]})
        from dashboard.soc_verdict import extract_iocs as extract_iocs_flat
        events = df.fillna("").to_dict(orient="records")
        iocs = extract_iocs_flat(events, run_id=run_id)
        return jsonify({"iocs": iocs, "run_id": run_id, "count": len(iocs)})
    except Exception as exc:
        return jsonify({"error": str(exc), "iocs": []})


@app.route("/api/iocs/<run_id>/export.csv")
def api_iocs_csv(run_id):
    df = load_events(run_id)
    if df.empty:
        return "No events", 404
    import csv
    from dashboard.soc_verdict import extract_iocs as extract_iocs_flat
    events = df.fillna("").to_dict(orient="records")
    iocs = extract_iocs_flat(events, run_id=run_id)
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=["ioc_type","ioc_value","confidence","source_field","first_seen","run_id"])
    w.writeheader()
    for ioc in iocs:
        w.writerow({k: ioc.get(k,"") for k in w.fieldnames})
    out.seek(0)
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=iocs_{run_id[:8]}.csv"})


# ---------------------------------------------------------------------------
# SOC Verdict APIs
# ---------------------------------------------------------------------------

@app.route("/api/verdict", methods=["POST"])
def api_verdict():
    run_id = session.get("analysis_run_id")
    data   = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id") or (f"INC-{run_id[:8]}" if run_id else None)
    analyst_id  = data.get("analyst_id", "analyst")
    verdict_str = data.get("verdict", "")
    reason      = data.get("reason", "")
    evidence    = data.get("evidence_uids", [])
    notes       = data.get("notes", "")

    if not incident_id:
        return jsonify({"error": "No active incident"}), 400

    try:
        verdict = create_verdict(incident_id, analyst_id, verdict_str, reason, evidence, notes)

        new_status = "Closed - True Positive" if verdict["is_true_positive"] else "Closed - False Positive"
        try:
            with get_db_connection("live") as conn:
                with get_cursor(conn) as cur:
                    cur.execute(
                        "UPDATE incidents SET status=%s, verdict=%s, verdict_reason=%s, "
                        "analyst=%s, updated_at=%s WHERE incident_id=%s",
                        (new_status, verdict_str, reason, analyst_id, now_utc(), incident_id)
                    )
                    cur.execute(
                        "INSERT INTO audit_log (analyst_id, action, target_type, target_id, detail) "
                        "VALUES (%s, %s, %s, %s, %s)",
                        (analyst_id, "verdict_submitted", "incident", incident_id,
                         f"Verdict: {verdict_str}")
                    )
                conn.commit()
        except Exception as db_exc:
            log.warning("Verdict DB persist failed: %s", db_exc)

        if run_id:
            clear_analysis_snapshot(run_id)

        return jsonify({"success": True, "verdict": verdict})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/verdict/options")
def api_verdict_options():
    return jsonify({
        "verdicts":    VERDICT_OPTIONS,
        "transitions": {k: sorted(v) for k, v in {
            "New":          {"Triage", "Closed - False Positive"},
            "Triage":       {"Investigating", "Closed - False Positive", "Closed - Benign"},
            "Investigating":{"Escalated","Closed - True Positive","Closed - False Positive","Closed - Benign"},
            "Escalated":    {"Closed - True Positive", "Closed - False Positive"},
        }.items()},
    })


@app.route("/api/incident/<incident_id>/transition", methods=["POST"])
def api_incident_transition(incident_id):
    run_id     = session.get("analysis_run_id")
    data       = request.get_json(silent=True) or {}
    new_status = data.get("status", "")
    analyst_id = data.get("analyst_id", "analyst")

    try:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "SELECT status FROM incidents WHERE incident_id=%s",
                    (incident_id,)
                )
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "Incident not found"}), 404
                current = row["status"]

        ok, msg = validate_transition(current, new_status)
        if not ok:
            return jsonify({"error": msg, "current": current}), 400

        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "UPDATE incidents SET status=%s, analyst=%s, updated_at=%s "
                    "WHERE incident_id=%s",
                    (new_status, analyst_id, now_utc(), incident_id)
                )
                cur.execute(
                    "INSERT INTO audit_log (analyst_id, action, target_type, target_id, detail) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (analyst_id, "status_transition", "incident", incident_id,
                     f"{current} -> {new_status}")
                )
            conn.commit()

        if run_id:
            clear_analysis_snapshot(run_id)

        return jsonify({"success": True, "from": current, "to": new_status})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/score-breakdown/<run_id>")
def api_score_breakdown(run_id):
    context = get_analysis_snapshot_slice(run_id, timeline_limit=20)
    if not context:
        return jsonify({"error": "No analysis context — load dashboard first"}), 404
    bursts = context.get("burst_aggregates", []) + context.get("timeline", [])
    breakdowns = [explain_risk_score(b) for b in bursts[:20]]
    return jsonify({"breakdowns": breakdowns, "run_id": run_id})


@app.route("/api/health")
def api_health():
    from dashboard.db import health_check as db_health
    db_results = db_health()
    return jsonify({
        "status":    "ok" if all(db_results.values()) else "degraded",
        "db":        db_results,
        "timestamp": now_utc().isoformat(),
        "version":   "2.0.0",
    })


@app.route("/api/alerts/latest")
def api_alerts_latest():
    run_id = request.args.get("run_id") or session.get("analysis_run_id")
    try:
        mode = "live" if (not run_id or run_id == "live") else "cases"
        engine = get_engine(mode)
        df = pd.read_sql_query(
            text("""
SELECT 
    event_time,
    image,
    computer,
    rule_name,
    severity,
    mitre_id
FROM detections
WHERE run_id = :run_id
ORDER BY event_time DESC
LIMIT 20
"""),
            engine, params={"run_id": run_id or "live"}
        )
        if df.empty:
            return jsonify({"alerts": []})
            
        if "utc_time" not in df.columns and "event_time" in df.columns:
            df["utc_time"] = df["event_time"]
        for col in df.columns:
            if df[col].dtype.name.startswith("datetime"):
                df[col] = df[col].astype(str)
        return jsonify({"alerts": df.fillna("").to_dict(orient="records")})
    except Exception as exc:
        log.error("[ASYNC] Analysis failed for run_id=%s: %s", run_id, exc, exc_info=True)
        _set_run_status(run_id, "failed")
        return jsonify({"alerts": [], "error": str(exc)})


@app.route("/api/events/latest")
def api_events_latest():
    run_id = request.args.get("run_id") or session.get("analysis_run_id")
    SHELL_IMAGES = ("powershell", "cmd", "wscript", "cscript", "mshta",
                    "rundll32", "regsvr32", "certutil", "bitsadmin")
    try:
        mode = "live" if (not run_id or run_id == "live") else "cases"
        engine = get_engine(mode)
        df = pd.read_sql_query(
            text(f"SELECT event_time, image, command_line, "
                 f"COALESCE({_user_col}, '') AS user, computer "
                 f"FROM events WHERE run_id = :run_id ORDER BY event_time DESC LIMIT 100"),
            engine, params={"run_id": run_id or "live"}
        )
        if not df.empty and "image" in df.columns:
            mask = df["image"].str.lower().str.contains("|".join(SHELL_IMAGES), na=False)
            df   = df[mask].head(20)
            
        if "utc_time" not in df.columns and "event_time" in df.columns:
            df["utc_time"] = df["event_time"]
        for col in df.columns:
            if df[col].dtype.name.startswith("datetime"):
                df[col] = df[col].astype(str)
        return jsonify({"events": df.fillna("").to_dict(orient="records") if not df.empty else []})
    except Exception as exc:
        return jsonify({"events": [], "error": str(exc)})


@app.route("/triage")
def triage_queue():
    try:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "SELECT incident_id, run_id, status, severity, confidence, "
                    "analyst, priority, sla_deadline, created_at, updated_at "
                    "FROM incidents WHERE status NOT IN "
                    "('Closed - True Positive','Closed - False Positive','Closed - Benign') "
                    "ORDER BY confidence DESC, created_at ASC LIMIT 100"
                )
                incidents = [dict(r) for r in cur.fetchall()]
    except Exception as exc:
        flash(f"Error loading triage queue: {exc}", "error")
        incidents = []

    def _triage_text(value, default=""):
        if value is None:
            return default
        try:
            if pd.isna(value):
                return default
        except Exception:
            pass
        if isinstance(value, (datetime.datetime, datetime.date, pd.Timestamp)):
            return value.isoformat()
        return str(value)

    def _triage_incident(inc: dict) -> dict:
        clean = {}
        for key, value in inc.items():
            if key in {"incident_id", "run_id", "status", "severity", "analyst", "priority"}:
                clean[key] = _triage_text(value, "Unknown" if key == "incident_id" else ("unknown" if key == "run_id" else ""))
            elif key in {"created_at", "updated_at", "sla_deadline"}:
                clean[key] = _triage_text(value, "") if value is not None else None
            elif key in {"attack_story", "top_detection_reasons", "sla"}:
                clean[key] = _template_safe_value(value)
            else:
                clean[key] = _template_safe_value(value)

        clean.setdefault("incident_id", "Unknown")
        clean.setdefault("run_id", "unknown")
        clean.setdefault("status", "New")
        clean.setdefault("severity", "Medium")
        clean.setdefault("analyst", "")
        clean.setdefault("priority", "")
        clean.setdefault("attack_story", None)
        clean.setdefault("top_detection_reasons", [])
        clean.setdefault("sla", {"breached": False, "label": "No SLA set", "color": "gray"})
        return clean

    incidents = [_triage_incident(inc) for inc in incidents]

    for inc in incidents:
        dl = inc.get("sla_deadline")
        if dl:
            if isinstance(dl, str):
                try:
                    dl = datetime.datetime.fromisoformat(dl.replace("Z","+00:00"))
                except Exception:
                    dl = None
            if dl:
                inc["sla"] = sla_status(dl)
        if "sla" not in inc:
            inc["sla"] = {"breached": False, "label": "No SLA set", "color": "gray"}

    # ── Enrich incidents with attack storyline + explainability ─────────────
    for inc in incidents:
        run_id_key = inc.get("run_id")
        if run_id_key:
            try:
                snap = get_analysis_snapshot_slice(run_id_key, timeline_limit=0)
                if snap:
                    inc["attack_story"]          = snap.get("attack_story")
                    inc["kill_chain_depth"]       = snap.get("kill_chain_depth", 0)
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
                    ):
                        if snap.get(key) is not None:
                            inc[key] = snap.get(key)
                    kill_chain_depth = int(snap.get("kill_chain_depth", 0) or 0)
                    burst_candidates = snap.get("burst_aggregates", []) or []
                    top_burst = None
                    if isinstance(burst_candidates, list) and burst_candidates:
                        top_burst = max(
                            (b for b in burst_candidates if isinstance(b, dict)),
                            key=lambda b: float(b.get("deviation_score", 0) or 0),
                            default=None,
                        )
                    if top_burst:
                        try:
                            deviation_score = float(top_burst.get("deviation_score", 0) or 0)
                        except Exception:
                            deviation_score = 0.0
                    else:
                        deviation_score = 0.0
                    if kill_chain_depth > 0:
                        inc["chain_depth"] = kill_chain_depth
                    if deviation_score > 0:
                        inc["deviation_score"] = deviation_score
                    inc["engine"] = "v2" if (kill_chain_depth > 0 or deviation_score > 0) else "v1"
                    # Gather top match_reason list from the most severe detection
                    all_dets = snap.get("detections", [])
                    if all_dets:
                        top_det = max(
                            all_dets,
                            key=lambda d: d.get("confidence_score", 0) if isinstance(d, dict) else 0,
                            default=None,
                        )
                        inc["top_detection_reasons"] = (
                            top_det.get("match_reason", []) if isinstance(top_det, dict) else []
                        )
                    else:
                        inc["top_detection_reasons"] = []
            except Exception:
                inc["attack_story"]          = None
                inc["top_detection_reasons"] = []

    def _triage_datetime(value):
        if isinstance(value, datetime.datetime):
            return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
        if isinstance(value, str) and value:
            try:
                parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)
            except Exception:
                return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
        return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

    def _triage_sort_key(inc: dict):
        try:
            confidence = float(inc.get("confidence", 0) or 0)
        except Exception:
            confidence = -1.0
        return (
            -confidence,
            _triage_datetime(inc.get("created_at")),
            str(inc.get("incident_id") or ""),
        )

    status_filter = (request.args.get("status") or "").strip()
    severity_filter = (request.args.get("severity") or "").strip()
    engine_filter = (request.args.get("engine") or "").strip().lower()
    try:
        last_id = max(int(request.args.get("last_id", 0) or 0), 0)
    except ValueError:
        last_id = 0

    filtered_incidents = incidents
    if status_filter:
        filtered_incidents = [inc for inc in filtered_incidents if str(inc.get("status") or "") == status_filter]
    if severity_filter:
        filtered_incidents = [inc for inc in filtered_incidents if str(inc.get("severity") or "") == severity_filter]
    if engine_filter in {"v1", "v2"}:
        filtered_incidents = [inc for inc in filtered_incidents if str(inc.get("engine") or "v1") == engine_filter]

    filtered_incidents.sort(key=_triage_sort_key)

    page_size = 25
    page_start = min(last_id, len(filtered_incidents))
    page_end = page_start + page_size
    page_incidents = filtered_incidents[page_start:page_end]
    next_cursor = page_end if page_end < len(filtered_incidents) else None

    return render_template(
        "triage.html",
        incidents=page_incidents,
        total=len(filtered_incidents),
        unreviewed=sum(1 for i in filtered_incidents if i["status"] == "New"),
        last_id=page_start,
        next_cursor=next_cursor,
        current_user=get_current_user(),
    )


@app.route("/hunt")
def hunt_console():
    run_id = session.get("analysis_run_id")
    query  = request.args.get("q", "")
    return render_template(
        "hunt_console.html",
        run_id=run_id,
        query=query,
        current_user=get_current_user(),
    )


# ---------------------------------------------------------------------------
# Application startup
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    check_environment()

    import sys

    # Freeze-stage defaults for runtime validation:
    # - debug OFF unless explicitly enabled
    # - reloader OFF unless explicitly enabled
    debug_enabled = os.environ.get("FLASK_DEBUG", "0") == "1" or "--debug" in sys.argv
    use_reload = (
        os.environ.get("FLASK_USE_RELOADER", "0") == "1"
        and os.environ.get("NO_RELOAD") != "1"
        and "--no-reload" not in sys.argv
    )

    is_reloader_child = os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    execution_process = (not use_reload) or is_reloader_child

    if execution_process:
        if _start_warmup_once():
            log.info("[MAIN] Initializing SentinelTrace (Execution Process)...")
        else:
            log.info("[MAIN] Warmup already started in this process.")
    else:
        log.info("[MAIN] Reloader parent process: skipping warmup/bootstrap.")

    log.info(
        ">>> Starting Flask dashboard on http://127.0.0.1:5000 (debug=%s reload=%s)",
        debug_enabled,
        use_reload,
    )
    app.run(host="127.0.0.1", port=5000, debug=debug_enabled, use_reloader=use_reload)
