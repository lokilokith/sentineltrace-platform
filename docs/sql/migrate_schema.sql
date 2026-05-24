-- ============================================================
-- SentinelTrace — Schema Migration
-- Adds priority + sla_deadline columns if they don't exist yet
-- Safe to run multiple times (uses IF NOT EXISTS equivalent via stored proc)
-- Run in PowerShell:  cmd /c "mysql -u root -p sentinel_live < migrate_schema.sql"
-- ============================================================

USE sentinel_live;

-- Add priority column if missing
SET @col_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'sentinel_live'
      AND TABLE_NAME   = 'incidents'
      AND COLUMN_NAME  = 'priority'
);
SET @sql = IF(@col_exists = 0,
    "ALTER TABLE incidents ADD COLUMN priority VARCHAR(16) DEFAULT 'P3'",
    "SELECT 'priority column already exists' AS info"
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add sla_deadline column if missing
SET @col_exists2 = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'sentinel_live'
      AND TABLE_NAME   = 'incidents'
      AND COLUMN_NAME  = 'sla_deadline'
);
SET @sql2 = IF(@col_exists2 = 0,
    "ALTER TABLE incidents ADD COLUMN sla_deadline DATETIME(6) NULL",
    "SELECT 'sla_deadline column already exists' AS info"
);
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;

-- Add analyst_id column if missing (also added in full_setup.sql)
SET @col_exists3 = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'sentinel_live'
      AND TABLE_NAME   = 'incidents'
      AND COLUMN_NAME  = 'analyst_id'
);
SET @sql3 = IF(@col_exists3 = 0,
    "ALTER TABLE incidents ADD COLUMN analyst_id VARCHAR(64) NULL",
    "SELECT 'analyst_id column already exists' AS info"
);
PREPARE stmt3 FROM @sql3; EXECUTE stmt3; DEALLOCATE PREPARE stmt3;

-- Verify final structure
SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'sentinel_live' AND TABLE_NAME = 'incidents'
ORDER BY ORDINAL_POSITION;

SELECT 'Migration complete.' AS status;

-- ============================================================
-- sentinel_cases — create missing tables if they don't exist
-- (These were skipped if the original setup.sql failed mid-run)
-- ============================================================

USE sentinel_cases;

CREATE TABLE IF NOT EXISTS behaviors (
    id                 BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id             VARCHAR(64)  NOT NULL,
    behavior_id        VARCHAR(128),
    behavior_type      VARCHAR(64),
    event_time         DATETIME(6),
    image              VARCHAR(512),
    parent_image       VARCHAR(512),
    command_line       TEXT,
    user_name          VARCHAR(256),
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

-- Also ensure sentinel_live has the behaviors table with user_name column
USE sentinel_live;

CREATE TABLE IF NOT EXISTS behaviors (
    id                 BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id             VARCHAR(64)  NOT NULL,
    behavior_id        VARCHAR(128),
    behavior_type      VARCHAR(64),
    event_time         DATETIME(6),
    image              VARCHAR(512),
    parent_image       VARCHAR(512),
    command_line       TEXT,
    user_name          VARCHAR(256),
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

-- If behaviors table existed with old 'user' column, add user_name as alias
SET @has_user = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'sentinel_cases' AND TABLE_NAME = 'behaviors'
    AND COLUMN_NAME = 'user' 
);
SET @no_user_name = (
    SELECT COUNT(*) = 0 FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'sentinel_cases' AND TABLE_NAME = 'behaviors'
    AND COLUMN_NAME = 'user_name'
);
SET @sql_beh = IF(@has_user > 0 AND @no_user_name,
    'ALTER TABLE sentinel_cases.behaviors CHANGE COLUMN `user` user_name VARCHAR(256)',
    'SELECT 1'
);
PREPARE stmt_beh FROM @sql_beh; EXECUTE stmt_beh; DEALLOCATE PREPARE stmt_beh;

SELECT 'Migration complete — all tables created/verified.' AS status;
