-- ============================================================
-- SentinelTrace v2 — Safe Migration (MySQL 5.7 + 8.0 compatible)
-- Uses stored procedure to safely add columns without IF NOT EXISTS
-- Run: Get-Content migrate_v2_safe.sql | mysql -u sentinel_user -pStrongPass123
-- ============================================================

USE sentinel_live;

DROP PROCEDURE IF EXISTS add_col;

DELIMITER $$
CREATE PROCEDURE add_col(
    IN db_name  VARCHAR(64),
    IN tbl_name VARCHAR(64),
    IN col_name VARCHAR(64),
    IN col_def  TEXT
)
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = db_name
          AND TABLE_NAME   = tbl_name
          AND COLUMN_NAME  = col_name
    ) THEN
        SET @sql = CONCAT(
            'ALTER TABLE `', db_name, '`.`', tbl_name,
            '` ADD COLUMN `', col_name, '` ', col_def
        );
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
        SELECT CONCAT('  ADDED  : ', db_name, '.', tbl_name, '.', col_name) AS result;
    ELSE
        SELECT CONCAT('  SKIPPED: ', db_name, '.', tbl_name, '.', col_name, ' (already exists)') AS result;
    END IF;
END$$
DELIMITER ;

-- ── sentinel_live.behavior_baseline ────────────────────────────────────────
CALL add_col('sentinel_live','behavior_baseline','seq_bigram_json',    'MEDIUMTEXT DEFAULT NULL');
CALL add_col('sentinel_live','behavior_baseline','seq_trigram_json',   'MEDIUMTEXT DEFAULT NULL');
CALL add_col('sentinel_live','behavior_baseline','seq_2_total',        'INT NOT NULL DEFAULT 0');
CALL add_col('sentinel_live','behavior_baseline','seq_3_total',        'INT NOT NULL DEFAULT 0');
CALL add_col('sentinel_live','behavior_baseline','network_ip_json',    'MEDIUMTEXT DEFAULT NULL');
CALL add_col('sentinel_live','behavior_baseline','network_subnet_json','MEDIUMTEXT DEFAULT NULL');
CALL add_col('sentinel_live','behavior_baseline','network_total',      'INT NOT NULL DEFAULT 0');
CALL add_col('sentinel_live','behavior_baseline','network_subnet_total','INT NOT NULL DEFAULT 0');
CALL add_col('sentinel_live','behavior_baseline','decay_updates',      'INT NOT NULL DEFAULT 0');

-- ── sentinel_live.detections ───────────────────────────────────────────────
CALL add_col('sentinel_live','detections','score_ledger',     'MEDIUMTEXT DEFAULT NULL');
CALL add_col('sentinel_live','detections','chain_depth',      'TINYINT NOT NULL DEFAULT 1');
CALL add_col('sentinel_live','detections','chain_multiplier', 'FLOAT NOT NULL DEFAULT 1.0');
CALL add_col('sentinel_live','detections','grandparent_image','VARCHAR(512) DEFAULT NULL');
CALL add_col('sentinel_live','detections','classification',   'VARCHAR(32) DEFAULT NULL');

-- ── sentinel_cases.detections ──────────────────────────────────────────────
CALL add_col('sentinel_cases','detections','score_ledger',     'MEDIUMTEXT DEFAULT NULL');
CALL add_col('sentinel_cases','detections','chain_depth',      'TINYINT NOT NULL DEFAULT 1');
CALL add_col('sentinel_cases','detections','chain_multiplier', 'FLOAT NOT NULL DEFAULT 1.0');
CALL add_col('sentinel_cases','detections','grandparent_image','VARCHAR(512) DEFAULT NULL');
CALL add_col('sentinel_cases','detections','classification',   'VARCHAR(32) DEFAULT NULL');

-- ── sentinel_live.events ───────────────────────────────────────────────────
CALL add_col('sentinel_live','events','grandparent_image',      'VARCHAR(512) DEFAULT NULL');
CALL add_col('sentinel_live','events','cmd_entropy',            'FLOAT DEFAULT NULL');
CALL add_col('sentinel_live','events','cmd_has_encoded_flag',   'TINYINT(1) DEFAULT 0');

-- ── sentinel_cases.events ──────────────────────────────────────────────────
CALL add_col('sentinel_cases','events','grandparent_image',     'VARCHAR(512) DEFAULT NULL');
CALL add_col('sentinel_cases','events','cmd_entropy',           'FLOAT DEFAULT NULL');
CALL add_col('sentinel_cases','events','cmd_has_encoded_flag',  'TINYINT(1) DEFAULT 0');

-- ── sentinel_live.correlation_campaigns ────────────────────────────────────
CALL add_col('sentinel_live','correlation_campaigns','forward_edge_count','INT NOT NULL DEFAULT 0');
CALL add_col('sentinel_live','correlation_campaigns','direction_bonus',   'INT NOT NULL DEFAULT 0');

-- ── sentinel_cases.correlation_campaigns ───────────────────────────────────
CALL add_col('sentinel_cases','correlation_campaigns','forward_edge_count','INT NOT NULL DEFAULT 0');
CALL add_col('sentinel_cases','correlation_campaigns','direction_bonus',   'INT NOT NULL DEFAULT 0');

-- Cleanup
DROP PROCEDURE IF EXISTS add_col;

SELECT 'SentinelTrace v2 migration completed successfully.' AS status;
