-- ============================================================
-- SentinelTrace v3 — Migration Script
-- Adds tables for: feedback loop, cross-run campaigns, peer baseline
-- Safe to run on existing v2 databases (IF NOT EXISTS throughout)
-- Run: cmd /c "mysql -u root -p < migrate_v3.sql"
-- ============================================================

USE sentinel_live;

-- ── Analyst feedback suppression rules ─────────────────────────────────────
-- Stores learned patterns from analyst verdicts to tune future scoring
CREATE TABLE IF NOT EXISTS `feedback_suppressions` (
    `id`               INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `image`            VARCHAR(512) DEFAULT NULL,
    `parent_image`     VARCHAR(512) DEFAULT NULL,
    `kill_chain_stage` VARCHAR(64)  DEFAULT NULL,
    `rule_id`          VARCHAR(64)  DEFAULT NULL,
    `computer`         VARCHAR(256) DEFAULT NULL,
    `verdict`          VARCHAR(64)  NOT NULL,
    `confidence_adj`   INT NOT NULL DEFAULT -20,
    `reason`           TEXT,
    `created_at`       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `hit_count`        INT NOT NULL DEFAULT 0,
    INDEX idx_fb_image  (`image`(64)),
    INDEX idx_fb_rule   (`rule_id`),
    INDEX idx_fb_stage  (`kill_chain_stage`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Cross-run campaign memory ───────────────────────────────────────────────
-- Tracks attacker behavior across multiple analysis runs
-- Solves Problem 6: No cross-run intelligence
CREATE TABLE IF NOT EXISTS `global_campaigns` (
    `campaign_id`      VARCHAR(128) NOT NULL PRIMARY KEY,
    `base_image`       VARCHAR(512),
    `base_computer`    VARCHAR(256),
    `first_seen`       DATETIME(6),
    `last_seen`        DATETIME(6),
    `run_ids`          TEXT,                        -- JSON array of run_ids
    `highest_stage`    VARCHAR(64),
    `max_confidence`   INT NOT NULL DEFAULT 0,
    `ioc_ips`          TEXT,                        -- JSON array of seen IPs
    `ioc_domains`      TEXT,                        -- JSON array of seen domains
    `verdict`          VARCHAR(64),
    `total_detections` INT NOT NULL DEFAULT 0,
    `status`           VARCHAR(32) NOT NULL DEFAULT 'active',
    `description`      TEXT,
    `created_at`       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at`       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX idx_gc_image  (`base_image`(64)),
    INDEX idx_gc_status (`status`),
    INDEX idx_gc_stage  (`highest_stage`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Sequence detection results ──────────────────────────────────────────────
-- Stores completed attack chain matches from sequence_engine
CREATE TABLE IF NOT EXISTS `sequence_detections` (
    `id`               BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `run_id`           VARCHAR(64) NOT NULL,
    `pattern_id`       VARCHAR(32) NOT NULL,
    `rule_name`        VARCHAR(256),
    `mitre_id`         VARCHAR(32),
    `mitre_tactic`     VARCHAR(128),
    `kill_chain_stage` VARCHAR(64),
    `chain_str`        VARCHAR(512),
    `chain_depth`      INT NOT NULL DEFAULT 2,
    `confidence_score` FLOAT,
    `severity`         VARCHAR(16),
    `image`            VARCHAR(512),
    `computer`         VARCHAR(256),
    `utc_time`         DATETIME(6),
    `end_time`         DATETIME(6),
    `description`      TEXT,
    INDEX idx_sd_run    (`run_id`),
    INDEX idx_sd_pat    (`pattern_id`),
    INDEX idx_sd_time   (`utc_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Peer baseline (cross-host process norms) ────────────────────────────────
-- Tracks how a process behaves across ALL hosts for peer comparison
-- Solves Problem 4: Baseline is local, not global
CREATE TABLE IF NOT EXISTS `peer_baseline` (
    `id`               BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `process_name`     VARCHAR(512) NOT NULL,
    `host_count`       INT NOT NULL DEFAULT 1,     -- how many hosts run this
    `avg_exec_rate`    DOUBLE NOT NULL DEFAULT 0.0, -- avg exec/min across hosts
    `std_exec_rate`    DOUBLE NOT NULL DEFAULT 0.0,
    `common_parents`   TEXT,                       -- JSON top-5 parents seen
    `last_updated`     DATETIME(6),
    UNIQUE KEY uq_peer_proc (`process_name`(100)),
    INDEX idx_peer_proc (`process_name`(64))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Hunt suggestions (proactive) ────────────────────────────────────────────
-- Automatically generated hunt suggestions from pattern analysis
-- Solves Problem 7: Threat hunting is passive
CREATE TABLE IF NOT EXISTS `hunt_suggestions` (
    `id`               INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `suggestion_type`  VARCHAR(64) NOT NULL,        -- rare_process, rare_parent, new_ip
    `title`            VARCHAR(256) NOT NULL,
    `description`      TEXT,
    `hunt_query`       VARCHAR(512),                -- pre-built query string
    `run_id`           VARCHAR(64),
    `confidence`       INT NOT NULL DEFAULT 50,
    `created_at`       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `dismissed`        TINYINT(1) NOT NULL DEFAULT 0,
    INDEX idx_hs_run    (`run_id`),
    INDEX idx_hs_type   (`suggestion_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SELECT 'SentinelTrace v3 migration complete.' AS status;
