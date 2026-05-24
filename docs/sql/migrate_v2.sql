-- Run this file only if your database already has the v1 schema.
-- If this is a fresh install, use setup.sql instead.

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
