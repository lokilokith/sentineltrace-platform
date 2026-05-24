-- ============================================================
-- SentinelTrace v2 — Production MySQL Schema
-- Phase 1: Core SIEM Foundation
-- ============================================================
-- Run: mysql -u root -p < setup.sql

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
SET sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO';

-- ============================================================
-- Databases
-- ============================================================
CREATE DATABASE IF NOT EXISTS sentinel_live  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS sentinel_cases CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ============================================================
-- User
-- ============================================================
CREATE USER IF NOT EXISTS 'sentinel_user'@'localhost' IDENTIFIED WITH mysql_native_password BY 'StrongPass123';
GRANT ALL PRIVILEGES ON sentinel_live.*  TO 'sentinel_user'@'localhost';
GRANT ALL PRIVILEGES ON sentinel_cases.* TO 'sentinel_user'@'localhost';
FLUSH PRIVILEGES;

-- ============================================================
-- LIVE database — streaming telemetry + analyst state
-- ============================================================
USE sentinel_live;

-- Raw live events from Sysmon collector
CREATE TABLE IF NOT EXISTS live_events (
    row_id           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_uid        VARCHAR(128) NOT NULL UNIQUE,
    event_time       DATETIME(6),
    inserted_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    event_id         INT,
    image            VARCHAR(512),
    parent_image     VARCHAR(512),
    command_line     TEXT,
    `user`           VARCHAR(256),
    pid              VARCHAR(32),
    ppid             VARCHAR(32),
    source_ip        VARCHAR(64),
    destination_ip   VARCHAR(64),
    destination_port VARCHAR(16),
    severity         VARCHAR(16),
    computer         VARCHAR(256),
    target_filename  TEXT,
    run_id           VARCHAR(64)  NOT NULL DEFAULT 'live',
    INDEX idx_live_time    (inserted_at),
    INDEX idx_live_run     (run_id, inserted_at),
    INDEX idx_live_image   (image(64), inserted_at),
    INDEX idx_live_dst     (destination_ip, inserted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Collector heartbeat
CREATE TABLE IF NOT EXISTS collector_status (
    id        INT PRIMARY KEY,
    last_seen DATETIME(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO collector_status (id, last_seen) VALUES (1, NULL);

-- Incidents — SOC lifecycle (Phase 3 ready)
CREATE TABLE IF NOT EXISTS incidents (
    incident_id    VARCHAR(64)  NOT NULL,
    run_id         VARCHAR(64)  NOT NULL,
    status         VARCHAR(64)  NOT NULL DEFAULT 'New',
    severity       VARCHAR(32)  NOT NULL DEFAULT 'Medium',
    confidence     INT          NOT NULL DEFAULT 0,
    escalation     VARCHAR(64),
    analyst        VARCHAR(128),
    analyst_id     VARCHAR(64),
    notes          TEXT,
    verdict        VARCHAR(64),
    verdict_reason TEXT,
    priority       VARCHAR(16)  DEFAULT 'P3',
    sla_deadline   DATETIME(6),
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (incident_id, run_id),
    INDEX idx_inc_status  (status),
    INDEX idx_inc_analyst (analyst_id),
    INDEX idx_inc_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Analyst users (Phase 4)
CREATE TABLE IF NOT EXISTS analysts (
    analyst_id   VARCHAR(64)  NOT NULL PRIMARY KEY,
    username     VARCHAR(128) NOT NULL UNIQUE,
    email        VARCHAR(256),
    role         VARCHAR(32)  NOT NULL DEFAULT 'analyst',
    password_hash VARCHAR(256),
    created_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_login   DATETIME(6),
    is_active    TINYINT(1)   NOT NULL DEFAULT 1,
    INDEX idx_analyst_user (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Audit trail
CREATE TABLE IF NOT EXISTS audit_log (
    id           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    analyst_id   VARCHAR(64),
    action       VARCHAR(128) NOT NULL,
    target_type  VARCHAR(64),
    target_id    VARCHAR(128),
    detail       TEXT,
    ip_address   VARCHAR(64),
    ts           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_audit_ts       (ts),
    INDEX idx_audit_analyst  (analyst_id),
    INDEX idx_audit_target   (target_type, target_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Saved hunt queries
CREATE TABLE IF NOT EXISTS hunt_queries (
    hunt_id      VARCHAR(64)  NOT NULL PRIMARY KEY,
    name         VARCHAR(256) NOT NULL,
    query_text   TEXT         NOT NULL,
    description  TEXT,
    created_by   VARCHAR(64),
    created_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_run     DATETIME(6),
    run_count    INT          NOT NULL DEFAULT 0,
    INDEX idx_hunt_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- IOC (Indicators of Compromise)
CREATE TABLE IF NOT EXISTS ioc_list (
    ioc_id       VARCHAR(64)  NOT NULL PRIMARY KEY,
    ioc_type     VARCHAR(32)  NOT NULL,  -- ip, domain, hash, url, filename
    ioc_value    VARCHAR(512) NOT NULL,
    confidence   INT          NOT NULL DEFAULT 50,
    source       VARCHAR(128),
    tags         VARCHAR(512),
    first_seen   DATETIME(6),
    last_seen    DATETIME(6),
    run_id       VARCHAR(64),
    incident_id  VARCHAR(64),
    created_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uk_ioc (ioc_type, ioc_value(256)),
    INDEX idx_ioc_type (ioc_type),
    INDEX idx_ioc_run  (run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Behavior baseline (rolled up statistics per process/host/hour)
CREATE TABLE IF NOT EXISTS behavior_baseline (
    id             BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    computer       VARCHAR(256) NOT NULL DEFAULT 'unknown_host',
    process_name   VARCHAR(512) NOT NULL,
    user_type      VARCHAR(64)  NOT NULL DEFAULT 'unknown',
    parent_process VARCHAR(512) NOT NULL DEFAULT 'unknown',
    hour_bucket    INT          NOT NULL DEFAULT 0,
    avg_exec       DOUBLE       NOT NULL DEFAULT 0.0,
    var_exec       DOUBLE       NOT NULL DEFAULT 0.0,
    avg_cmd_len    DOUBLE       NOT NULL DEFAULT 0.0,
    avg_followup   DOUBLE       NOT NULL DEFAULT 0.0,
    count_samples  INT          NOT NULL DEFAULT 0,
    seen_days      INT          NOT NULL DEFAULT 1,
    last_updated   DATETIME(6),
    -- ── v2 engine additions ──────────────────────────────────────────────
    -- Sequence model: serialized n-gram transition tables (JSON)
    seq_bigram_json    MEDIUMTEXT   DEFAULT NULL,   -- {(parent,child):count, ...}
    seq_trigram_json   MEDIUMTEXT   DEFAULT NULL,   -- {(gp,parent,child):count, ...}
    seq_2_total        INT          NOT NULL DEFAULT 0,
    seq_3_total        INT          NOT NULL DEFAULT 0,
    -- Network probability model (JSON ip→count + subnet→count)
    network_ip_json     MEDIUMTEXT   DEFAULT NULL,
    network_subnet_json MEDIUMTEXT   DEFAULT NULL,
    network_total       INT          NOT NULL DEFAULT 0,
    network_subnet_total INT         NOT NULL DEFAULT 0,
    -- Decay tracking
    decay_updates  INT          NOT NULL DEFAULT 0,
    UNIQUE KEY uq_baseline (
        computer(100), process_name(100), user_type(64),
        parent_process(100), hour_bucket
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Correlation campaigns
CREATE TABLE IF NOT EXISTS correlation_campaigns (
    corr_id           VARCHAR(128) NOT NULL,
    run_id            VARCHAR(64)  NOT NULL,
    base_image        VARCHAR(512),
    computer          VARCHAR(256),
    first_seen        DATETIME(6),
    last_seen         DATETIME(6),
    burst_count       INT          NOT NULL DEFAULT 1,
    max_confidence    INT          NOT NULL DEFAULT 0,
    highest_kill_chain VARCHAR(64),
    status            VARCHAR(32)  NOT NULL DEFAULT 'active',
    description       TEXT,
    PRIMARY KEY (corr_id, run_id),
    INDEX idx_camp_run    (run_id),
    INDEX idx_camp_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Correlations detail
CREATE TABLE IF NOT EXISTS correlations (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    corr_id     VARCHAR(128) NOT NULL,
    run_id      VARCHAR(64)  NOT NULL,
    base_image  VARCHAR(512),
    start_time  DATETIME(6),
    end_time    DATETIME(6),
    description TEXT,
    event_ids   TEXT,
    computer    VARCHAR(256),
    kill_chain_stage VARCHAR(64),
    severity    VARCHAR(16),
    confidence  INT,
    INDEX idx_corr_run  (run_id),
    INDEX idx_corr_id   (corr_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
    alert_id   VARCHAR(64)  NOT NULL PRIMARY KEY,
    ts         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    rule_id    VARCHAR(64),
    rule_name  VARCHAR(256),
    severity   VARCHAR(16),
    image      VARCHAR(512),
    computer   VARCHAR(256),
    mitre_id   VARCHAR(32),
    run_id     VARCHAR(64)  NOT NULL DEFAULT 'live',
    INDEX idx_alert_ts  (ts),
    INDEX idx_alert_run (run_id, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Events (live run copies)
CREATE TABLE IF NOT EXISTS events (
    event_uid          VARCHAR(128) NOT NULL,
    run_id             VARCHAR(64)  NOT NULL,
    event_time         DATETIME(6),
    event_id           INT,
    image              VARCHAR(512),
    parent_image       VARCHAR(512),
    command_line       TEXT,
    `user`             VARCHAR(256),
    pid                VARCHAR(32),
    ppid               VARCHAR(32),
    src_ip             VARCHAR(64),
    dst_ip             VARCHAR(64),
    dst_port           VARCHAR(16),
    severity           VARCHAR(16),
    computer           VARCHAR(256),
    file_path          TEXT,
    description        TEXT,
    parser_version     VARCHAR(16),
    PRIMARY KEY (event_uid, run_id),
    INDEX idx_ev_run_time  (run_id, event_time),
    INDEX idx_ev_image     (image(64), run_id),
    INDEX idx_ev_computer  (computer(64), run_id),
    INDEX idx_ev_event_id  (event_id, run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Detections (live)
CREATE TABLE IF NOT EXISTS detections (
    id                 BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id             VARCHAR(64)  NOT NULL,
    rule_id            VARCHAR(64),
    rule_name          VARCHAR(256),
    mitre_id           VARCHAR(32),
    mitre_tactic       VARCHAR(128),
    kill_chain_stage   VARCHAR(64),
    utc_time           DATETIME(6),
    event_time         DATETIME(6),
    image              VARCHAR(512),
    event_id           INT,
    description        TEXT,
    severity           VARCHAR(16),
    computer           VARCHAR(256),
    process_id         VARCHAR(32),
    parent_process_id  VARCHAR(32),
    parent_image       VARCHAR(512),
    confidence_score   FLOAT,
    source_ip          VARCHAR(64),
    source_port        VARCHAR(16),
    destination_ip     VARCHAR(64),
    destination_port   VARCHAR(16),
    target_filename    TEXT,
    command_line       TEXT,
    INDEX idx_det_run      (run_id),
    INDEX idx_det_severity (severity, run_id),
    INDEX idx_det_mitre    (mitre_id),
    INDEX idx_det_time     (utc_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Behaviors
CREATE TABLE IF NOT EXISTS behaviors (
    id                 BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id             VARCHAR(64)  NOT NULL,
    behavior_id        VARCHAR(128),
    behavior_type      VARCHAR(64),
    event_time         DATETIME(6),
    image              VARCHAR(512),
    parent_image       VARCHAR(512),
    command_line       TEXT,
    `user`             VARCHAR(256),
    process_id         VARCHAR(32),
    parent_process_id  VARCHAR(32),
    computer           VARCHAR(256),
    source_ip          VARCHAR(64),
    destination_ip     VARCHAR(64),
    destination_port   VARCHAR(16),
    target_filename    TEXT,
    raw_event_id       VARCHAR(8),
    INDEX idx_beh_run   (run_id),
    INDEX idx_beh_image (image(64), run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ============================================================
-- CASES database — forensic analysis per run
-- ============================================================
USE sentinel_cases;

-- Main events store for uploaded XML cases
CREATE TABLE IF NOT EXISTS events (
    event_uid          VARCHAR(128) NOT NULL,
    run_id             VARCHAR(64)  NOT NULL,
    event_time         DATETIME(6),
    event_id           INT,
    image              VARCHAR(512),
    parent_image       VARCHAR(512),
    command_line       TEXT,
    `user`             VARCHAR(256),
    pid                VARCHAR(32),
    ppid               VARCHAR(32),
    src_ip             VARCHAR(64),
    dst_ip             VARCHAR(64),
    dst_port           VARCHAR(16),
    severity           VARCHAR(16),
    computer           VARCHAR(256),
    file_path          TEXT,
    description        TEXT,
    parser_version     VARCHAR(16),
    PRIMARY KEY (event_uid, run_id),
    INDEX idx_ev_run_time  (run_id, event_time),
    INDEX idx_ev_image     (image(64), run_id),
    INDEX idx_ev_computer  (computer(64), run_id),
    INDEX idx_ev_event_id  (event_id, run_id),
    INDEX idx_ev_parent    (parent_image(64), run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Detections for cases
CREATE TABLE IF NOT EXISTS detections (
    id                 BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id             VARCHAR(64)  NOT NULL,
    rule_id            VARCHAR(64),
    rule_name          VARCHAR(256),
    mitre_id           VARCHAR(32),
    mitre_tactic       VARCHAR(128),
    kill_chain_stage   VARCHAR(64),
    utc_time           DATETIME(6),
    event_time         DATETIME(6),
    image              VARCHAR(512),
    event_id           INT,
    description        TEXT,
    severity           VARCHAR(16),
    computer           VARCHAR(256),
    process_id         VARCHAR(32),
    parent_process_id  VARCHAR(32),
    parent_image       VARCHAR(512),
    confidence_score   FLOAT,
    source_ip          VARCHAR(64),
    source_port        VARCHAR(16),
    destination_ip     VARCHAR(64),
    destination_port   VARCHAR(16),
    target_filename    TEXT,
    command_line       TEXT,
    INDEX idx_det_run      (run_id),
    INDEX idx_det_severity (severity, run_id),
    INDEX idx_det_mitre    (mitre_id),
    INDEX idx_det_time     (utc_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Behaviors for cases
CREATE TABLE IF NOT EXISTS behaviors (
    id                 BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id             VARCHAR(64)  NOT NULL,
    behavior_id        VARCHAR(128),
    behavior_type      VARCHAR(64),
    event_time         DATETIME(6),
    image              VARCHAR(512),
    parent_image       VARCHAR(512),
    command_line       TEXT,
    `user`             VARCHAR(256),
    process_id         VARCHAR(32),
    parent_process_id  VARCHAR(32),
    computer           VARCHAR(256),
    source_ip          VARCHAR(64),
    destination_ip     VARCHAR(64),
    destination_port   VARCHAR(16),
    target_filename    TEXT,
    raw_event_id       VARCHAR(8),
    INDEX idx_beh_run   (run_id),
    INDEX idx_beh_image (image(64), run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Correlations for cases
CREATE TABLE IF NOT EXISTS correlations (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    corr_id     VARCHAR(128) NOT NULL,
    run_id      VARCHAR(64)  NOT NULL,
    base_image  VARCHAR(512),
    start_time  DATETIME(6),
    end_time    DATETIME(6),
    description TEXT,
    event_ids   TEXT,
    computer    VARCHAR(256),
    kill_chain_stage VARCHAR(64),
    severity    VARCHAR(16),
    confidence  INT,
    INDEX idx_corr_run (run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Correlation campaigns for cases
CREATE TABLE IF NOT EXISTS correlation_campaigns (
    corr_id            VARCHAR(128) NOT NULL,
    run_id             VARCHAR(64)  NOT NULL,
    base_image         VARCHAR(512),
    computer           VARCHAR(256),
    first_seen         DATETIME(6),
    last_seen          DATETIME(6),
    burst_count        INT          NOT NULL DEFAULT 1,
    max_confidence     INT          NOT NULL DEFAULT 0,
    highest_kill_chain VARCHAR(64),
    status             VARCHAR(32)  NOT NULL DEFAULT 'active',
    description        TEXT,
    PRIMARY KEY (corr_id, run_id),
    INDEX idx_camp_run (run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================
-- v2 Engine Migration — idempotent ALTER TABLE additions
-- Safe to re-run on existing databases (errors suppressed by IF NOT EXISTS
-- equivalents via stored procedure pattern or manual admin)
-- ============================================================

-- behavior_baseline v2 columns (run once on existing installs)
-- These are no-ops if columns already exist.
ALTER TABLE sentinel_live.behavior_baseline
    ADD COLUMN IF NOT EXISTS seq_bigram_json     MEDIUMTEXT   DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS seq_trigram_json    MEDIUMTEXT   DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS seq_2_total         INT          NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS seq_3_total         INT          NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS network_ip_json     MEDIUMTEXT   DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS network_subnet_json MEDIUMTEXT   DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS network_total       INT          NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS network_subnet_total INT         NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS decay_updates       INT          NOT NULL DEFAULT 0;

-- detections v2: score_ledger (JSON) and chain_depth
ALTER TABLE sentinel_live.detections
    ADD COLUMN IF NOT EXISTS score_ledger  MEDIUMTEXT  DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS chain_depth   TINYINT     NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS chain_multiplier FLOAT    NOT NULL DEFAULT 1.0,
    ADD COLUMN IF NOT EXISTS grandparent_image VARCHAR(512) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS classification VARCHAR(32) DEFAULT NULL;

ALTER TABLE sentinel_cases.detections
    ADD COLUMN IF NOT EXISTS score_ledger  MEDIUMTEXT  DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS chain_depth   TINYINT     NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS chain_multiplier FLOAT    NOT NULL DEFAULT 1.0,
    ADD COLUMN IF NOT EXISTS grandparent_image VARCHAR(512) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS classification VARCHAR(32) DEFAULT NULL;

-- events v2: grandparent_image for trigram baseline
ALTER TABLE sentinel_live.events
    ADD COLUMN IF NOT EXISTS grandparent_image VARCHAR(512) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS cmd_entropy       FLOAT        DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS cmd_has_encoded_flag TINYINT(1) DEFAULT 0;

ALTER TABLE sentinel_cases.events
    ADD COLUMN IF NOT EXISTS grandparent_image VARCHAR(512) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS cmd_entropy       FLOAT        DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS cmd_has_encoded_flag TINYINT(1) DEFAULT 0;

-- correlation_campaigns v2: direction_bonus, forward_edge_count
ALTER TABLE sentinel_live.correlation_campaigns
    ADD COLUMN IF NOT EXISTS forward_edge_count  INT  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS direction_bonus      INT  NOT NULL DEFAULT 0;

ALTER TABLE sentinel_cases.correlation_campaigns
    ADD COLUMN IF NOT EXISTS forward_edge_count  INT  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS direction_bonus      INT  NOT NULL DEFAULT 0;

SELECT 'SentinelTrace v2 schema installed successfully.' AS status;
