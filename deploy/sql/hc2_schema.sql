-- Healthchecks 2.0: Tabellen hc2_* in der EIGENEN Datenbank (von Dennis angelegt, Benutzer ipv64_hc).
-- MariaDB 10.5+, InnoDB, utf8mb4. Phase 1, Paket S2. Idempotent (IF NOT EXISTS), mehrfach ausfuehrbar.
-- Vorher: USE <name der neuen Datenbank>;  (oder im Client die Datenbank waehlen)
-- Alte Tabellen in der Hauptdatenbank bleiben unveraendert; die Aenderungen an users/user_class
-- und die Sicht hc2_users_v stehen in ipv64_main.sql (Hauptdatenbank).
-- Zeiten in den hc2_*-Tabellen sind UTC (DATETIME(3)); das Portal rechnet beim Anzeigen um.
-- Token ist VARCHAR(50) wie healthchecks.healthtoken, damit alte Tokens 1:1 uebernommen werden.

SET NAMES utf8mb4;

-- ---------------------------------------------------------------- Standorte / Knoten
CREATE TABLE IF NOT EXISTS `hc2_locations` (
  `code`     VARCHAR(16) NOT NULL,
  `name`     VARCHAR(64) NOT NULL,
  `endpoint` VARCHAR(100) NOT NULL DEFAULT '',   -- z. B. hub-nbg.ipv64.net
  `enabled`  TINYINT NOT NULL DEFAULT 1,
  PRIMARY KEY (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
INSERT IGNORE INTO `hc2_locations` (`code`,`name`,`endpoint`) VALUES ('nbg','Nürnberg','hc-srv02.ipv64.net'), ('fsn','Falkenstein','hc-srv01.ipv64.net');

CREATE TABLE IF NOT EXISTS `hc2_hubs` (                 -- lebende hub-Instanzen
  `name`        VARCHAR(64) NOT NULL,
  `location`    VARCHAR(16) NOT NULL,
  `roles`       VARCHAR(32) NOT NULL DEFAULT '',
  `version`     VARCHAR(32) NOT NULL DEFAULT '',
  `connections` INT NOT NULL DEFAULT 0,
  `started_at`  DATETIME(3) NULL,
  `heartbeat`   DATETIME(3) NULL,
  PRIMARY KEY (`name`), KEY `heartbeat` (`heartbeat`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_slot_leases` (           -- Sicherung gegen Doppelausfuehrung je Standort
  `location` VARCHAR(16) NOT NULL,
  `slot`     SMALLINT NOT NULL,
  `owner`    VARCHAR(64) NOT NULL,
  `until`    DATETIME(3) NOT NULL,
  PRIMARY KEY (`location`,`slot`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------------------------------------------------------------- Nodes
CREATE TABLE IF NOT EXISTS `hc2_nodes` (
  `id`           INT NOT NULL AUTO_INCREMENT,
  `userid`       INT NOT NULL,
  `node_id`     VARCHAR(32) NOT NULL,                     -- vom Node erzeugt, unveraenderlich
  `name`         VARCHAR(100) NOT NULL,
  `location`     VARCHAR(100) NOT NULL DEFAULT '',          -- Freitext des Nutzers ("Keller")
  `version`      VARCHAR(32) NOT NULL DEFAULT '',
  `timezone`     VARCHAR(64) NOT NULL DEFAULT 'UTC',
  `modules`      VARCHAR(255) NOT NULL DEFAULT '',          -- aktive Module, kommagetrennt
  `remote_mgmt`  ENUM('off','read','full') NOT NULL DEFAULT 'full',
  `last_seen`    DATETIME(3) NULL,
  `last_sync`    DATETIME(3) NULL,
  `last_ack_seq` BIGINT NOT NULL DEFAULT 0,                 -- hoechste bestaetigte Messpunkt-Nummer
  `outbox_size`  INT NOT NULL DEFAULT 0,
  `conflicts`    INT NOT NULL DEFAULT 0,
  `online`       TINYINT NOT NULL DEFAULT 0,
  `node`         VARCHAR(64) NOT NULL DEFAULT '',           -- hub-Instanz, die die Verbindung haelt
  `created_at`   DATETIME(3) NOT NULL,
  `revoked_at`   DATETIME(3) NULL,
  PRIMARY KEY (`id`), UNIQUE KEY `node_id` (`node_id`), KEY `userid` (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_node_tokens` (
  `id`         INT NOT NULL AUTO_INCREMENT,
  `node_id`   VARCHAR(32) NOT NULL,
  `token_hash` CHAR(64) NOT NULL,                           -- sha256(token); Token selbst nur einmal sichtbar
  `created_at` DATETIME(3) NOT NULL,
  `last_used`  DATETIME(3) NULL,
  `revoked_at` DATETIME(3) NULL,
  PRIMARY KEY (`id`), UNIQUE KEY `token_hash` (`token_hash`), KEY `node_id` (`node_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_link_codes` (             -- Device-Code fuer die Erstverknuepfung
  `code`          CHAR(8) NOT NULL,                         -- ohne Bindestrich, Alphabet ohne 0/O/1/I
  `node_id`      VARCHAR(32) NOT NULL,
  `node_name`    VARCHAR(100) NOT NULL,
  `node_version` VARCHAR(32) NOT NULL DEFAULT '',
  `poll_secret`   CHAR(32) NOT NULL,
  `created_at`    DATETIME(3) NOT NULL,
  `expires_at`    DATETIME(3) NOT NULL,
  `userid`        INT NULL,                                 -- gesetzt, sobald der Nutzer den Code im Portal eingibt
  `location`      VARCHAR(100) NULL,
  `remote_mgmt`   ENUM('off','read','full') NULL,
  `consumed_at`   DATETIME(3) NULL,
  PRIMARY KEY (`code`), KEY `expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------------------------------------------------------------- Checks
CREATE TABLE IF NOT EXISTS `hc2_checks` (
  `token`              VARCHAR(50) NOT NULL,                -- wie healthchecks.healthtoken
  `userid`             INT NOT NULL,
  `node_id`           VARCHAR(32) NULL,                    -- Besitzer-Node bei execution local/both, sonst Herkunft
  `nodes`              VARCHAR(600) NOT NULL DEFAULT '',  -- messende Nodes (Komma-Liste), node_id = Besitzer
  `execution`          ENUM('local','online','both') NOT NULL DEFAULT 'online',
  `locations`          SET('nbg','fsn') NOT NULL DEFAULT 'nbg,fsn',   -- Online-Standorte; Portal kuerzt auf user_class.hc_locations
  `policy`             ENUM('all','any','majority') NOT NULL DEFAULT 'all',
  `notify_degraded`    TINYINT NOT NULL DEFAULT 0,
  `slot`               SMALLINT NOT NULL DEFAULT 0,         -- crc32(token) % 1024
  `type`               ENUM('http','keyword','icmp','tcp','port','cert','push','docker') NOT NULL,
  `name`               VARCHAR(200) NOT NULL,
  `target`             VARCHAR(500) NOT NULL DEFAULT '',
  `params`             JSON NOT NULL,
  `interval_sec`       INT NOT NULL DEFAULT 60,
  `retry_interval_sec` INT NOT NULL DEFAULT 20,
  `retries`            TINYINT NOT NULL DEFAULT 1,
  `connect_timeout_ms` INT NOT NULL DEFAULT 5000,
  `total_timeout_ms`   INT NOT NULL DEFAULT 10000,
  `invert`             TINYINT NOT NULL DEFAULT 0,
  `stabilize`          TINYINT NOT NULL DEFAULT 3,
  `ip_mode`            ENUM('auto','ipv4','ipv6','both') NOT NULL DEFAULT 'auto',
  `tags`               VARCHAR(255) NOT NULL DEFAULT '',
  `group_name`         VARCHAR(100) NOT NULL DEFAULT '',          -- Gruppe (frei benannt, fuer die Anzeige)
  `description`        TEXT NULL,
  `paused`             TINYINT NOT NULL DEFAULT 0,
  `parent_token`       VARCHAR(50) NULL,
  `critical`           TINYINT NOT NULL DEFAULT 0,
  `notify_down`        TINYINT NOT NULL DEFAULT 1,
  `notify_up`          TINYINT NOT NULL DEFAULT 1,
  `channels`           VARCHAR(255) NOT NULL DEFAULT '',    -- hc2_channels.id kommagetrennt, leer = Standardkanaele
  `repeat_minutes`     INT NOT NULL DEFAULT 0,
  `revision`           BIGINT NOT NULL DEFAULT 1,
  `created_at`         DATETIME(3) NOT NULL,
  `updated_at`         DATETIME(3) NOT NULL,
  `updated_by`         VARCHAR(100) NOT NULL DEFAULT '',
  `deleted_at`         DATETIME(3) NULL,                    -- Tombstone, 90 Tage
  `legacy_id`          INT NULL,                            -- healthchecks.id bei Migration
  -- Gesamtzustand (aus hc2_check_states nach policy berechnet)
  `state`              ENUM('pending','up','degraded','down','stabilizing','flapping','dependent','paused') NOT NULL DEFAULT 'pending',
  `state_since`        DATETIME(3) NULL,
  `last_check_at`      DATETIME(3) NULL,
  `next_check_at`      DATETIME(3) NULL,
  `last_status`        ENUM('up','down') NULL,
  `last_latency_ms`    FLOAT NULL,
  `last_reason`        VARCHAR(64) NULL,
  `last_message`       VARCHAR(500) NULL,
  `last_push_at`       DATETIME(3) NULL,
  `down_since`         DATETIME(3) NULL,
  `incident_id`        BIGINT NULL,
  PRIMARY KEY (`token`),
  KEY `user_list` (`userid`,`deleted_at`),
  KEY `node` (`node_id`),
  KEY `idx_due` (`slot`,`execution`,`paused`,`next_check_at`),
  KEY `parent` (`parent_token`),
  KEY `legacy` (`legacy_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Zustand je Messstelle: source = 'node:<node_id>' | 'loc:nbg' | 'loc:fsn'
CREATE TABLE IF NOT EXISTS `hc2_check_states` (
  `token`            VARCHAR(50) NOT NULL,
  `source`           VARCHAR(40) NOT NULL,
  `state`            ENUM('pending','up','down','stabilizing','flapping','dependent','paused') NOT NULL DEFAULT 'pending',
  `since`            DATETIME(3) NULL,
  `last_check_at`    DATETIME(3) NULL,
  `next_check_at`    DATETIME(3) NULL,
  `last_status`      ENUM('up','down') NULL,
  `last_latency_ms`  FLOAT NULL,
  `last_reason`      VARCHAR(64) NULL,
  `last_message`     VARCHAR(500) NULL,
  `consecutive_fail` SMALLINT NOT NULL DEFAULT 0,
  `consecutive_ok`   SMALLINT NOT NULL DEFAULT 0,
  `down_since`       DATETIME(3) NULL,
  `updated_at`       DATETIME(3) NULL,
  PRIMARY KEY (`token`,`source`), KEY `updated` (`updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Messpunkte, 7 Tage roh, tagesweise partitioniert. Der hub legt taeglich die naechste
-- Partition an (REORGANIZE pMAX) und loescht die aelteste (DROP PARTITION).
CREATE TABLE IF NOT EXISTS `hc2_measurements` (
  `token`       VARCHAR(50) NOT NULL,
  `source`      VARCHAR(40) NOT NULL,
  `node_seq`   BIGINT NOT NULL DEFAULT 0,                  -- laufende Nummer des Nodes, 0 bei Online
  `time`        DATETIME(3) NOT NULL,
  `status`      TINYINT NOT NULL,                           -- 1 up, 0 down
  `latency_ms`  FLOAT NOT NULL DEFAULT 0,
  `reason`      VARCHAR(64) NOT NULL DEFAULT '',
  `message`     VARCHAR(500) NOT NULL DEFAULT '',
  `family`      CHAR(4) NOT NULL DEFAULT '',                -- ipv4 / ipv6
  `details`     JSON NULL,
  `flags`       TINYINT NOT NULL DEFAULT 0,                 -- 1 Wartung, 2 abhaengig
  `received_at` DATETIME(3) NOT NULL,
  PRIMARY KEY (`token`,`source`,`time`,`node_seq`),
  KEY `seq` (`source`,`node_seq`),
  KEY `time` (`time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
PARTITION BY RANGE (TO_DAYS(`time`)) (
  PARTITION p20261010 VALUES LESS THAN (TO_DAYS('2026-10-11')),
  PARTITION p20261011 VALUES LESS THAN (TO_DAYS('2026-10-12')),
  PARTITION p20261012 VALUES LESS THAN (TO_DAYS('2026-10-13')),
  PARTITION p20261013 VALUES LESS THAN (TO_DAYS('2026-10-14')),
  PARTITION p20261014 VALUES LESS THAN (TO_DAYS('2026-10-15')),
  PARTITION p20261015 VALUES LESS THAN (TO_DAYS('2026-10-16')),
  PARTITION p20261016 VALUES LESS THAN (TO_DAYS('2026-10-17')),
  PARTITION p20261017 VALUES LESS THAN (TO_DAYS('2026-10-18')),
  PARTITION pMAX VALUES LESS THAN MAXVALUE
);

CREATE TABLE IF NOT EXISTS `hc2_hourly` (
  `token` VARCHAR(50) NOT NULL, `source` VARCHAR(40) NOT NULL, `hour` DATETIME NOT NULL,
  `count` INT NOT NULL DEFAULT 0, `up_count` INT NOT NULL DEFAULT 0,
  `min_ms` FLOAT NULL, `avg_ms` FLOAT NULL, `max_ms` FLOAT NULL,
  PRIMARY KEY (`token`,`source`,`hour`), KEY `hour` (`hour`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_daily` (
  `token` VARCHAR(50) NOT NULL, `source` VARCHAR(40) NOT NULL, `day` DATE NOT NULL,
  `count` INT NOT NULL DEFAULT 0, `up_count` INT NOT NULL DEFAULT 0,
  `min_ms` FLOAT NULL, `avg_ms` FLOAT NULL, `max_ms` FLOAT NULL,
  PRIMARY KEY (`token`,`source`,`day`), KEY `day` (`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_dirty_hours` (            -- nachzurechnende Stunden (rueckwirkende Messpunkte)
  `token` VARCHAR(50) NOT NULL, `source` VARCHAR(40) NOT NULL, `hour` DATETIME NOT NULL,
  PRIMARY KEY (`token`,`source`,`hour`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------------------------------------------------------------- Ereignisse / Stoerungen
CREATE TABLE IF NOT EXISTS `hc2_events` (
  `id`           BIGINT NOT NULL AUTO_INCREMENT,
  `event_id`     CHAR(32) NOT NULL,                         -- vom Erzeuger (Node oder hub), idempotent
  `token`        VARCHAR(50) NOT NULL,
  `userid`       INT NOT NULL,
  `source`       VARCHAR(40) NOT NULL DEFAULT '',           -- leer = Gesamtzustand
  `kind`         VARCHAR(20) NOT NULL,                      -- down, up, degraded, degraded_end, flapping_start, flapping_end, agent_offline, agent_online, ...
  `time`         DATETIME(3) NOT NULL,
  `from_state`   VARCHAR(12) NULL,
  `to_state`     VARCHAR(12) NULL,
  `reason`       VARCHAR(64) NULL,
  `message`      VARCHAR(500) NULL,
  `duration_sec` INT NOT NULL DEFAULT 0,
  `flaps`        SMALLINT NOT NULL DEFAULT 0,
  `flags`        TINYINT NOT NULL DEFAULT 0,                -- 1 Wartung, 2 still (keine Benachrichtigung)
  `incident_id`  BIGINT NULL,
  `notified_at`  DATETIME(3) NULL,
  PRIMARY KEY (`id`), UNIQUE KEY `event_id` (`event_id`),
  KEY `token_time` (`token`,`time`), KEY `user_time` (`userid`,`time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_incidents` (
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `token`      VARCHAR(50) NOT NULL,
  `userid`     INT NOT NULL,
  `started_at` DATETIME(3) NOT NULL,
  `ended_at`   DATETIME(3) NULL,
  `reason`     VARCHAR(64) NULL,
  `message`    VARCHAR(500) NULL,
  `sources`    VARCHAR(255) NOT NULL DEFAULT '',            -- beteiligte Messstellen
  `legacy_id`  INT NULL,                                    -- healthcheck_incidents.id
  PRIMARY KEY (`id`), KEY `token_start` (`token`,`started_at`), KEY `user_start` (`userid`,`started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------------------------------------------------------------- Kanaele / Versand
CREATE TABLE IF NOT EXISTS `hc2_channels` (
  `id`                    INT NOT NULL AUTO_INCREMENT,
  `userid`                INT NOT NULL,
  `node_id`              VARCHAR(32) NULL,                 -- NULL = Server-Kanal (hub sendet), sonst Agent-Kanal (Node sendet)
  `type`                  VARCHAR(20) NOT NULL,             -- smtp, telegram, discord, ntfy, gotify, webhook, pushover, app, ipv64_mail, ipv64_sms
  `name`                  VARCHAR(100) NOT NULL,
  `config_enc`            TEXT NOT NULL,                    -- JSON; Geheimnisse "enc:v1:..." (AES-GCM, Schluessel auf hub + Web-Server)
  `secret_only_local`     TINYINT NOT NULL DEFAULT 0,       -- Agent-Kanal: Server kennt nur Typ und Name
  `enabled`               TINYINT NOT NULL DEFAULT 1,
  `is_default`            TINYINT NOT NULL DEFAULT 0,
  `lang`                  CHAR(2) NOT NULL DEFAULT 'de',
  `notify_down`           TINYINT NOT NULL DEFAULT 1,
  `notify_up`             TINYINT NOT NULL DEFAULT 1,
  `verified`              TINYINT NOT NULL DEFAULT 1,       -- email/sms: 0 bis Code eingegeben
  `verify_key`            CHAR(16) NULL,
  `verify_expires`        DATETIME(3) NULL,
  `revision`              BIGINT NOT NULL DEFAULT 1,
  `created_at`            DATETIME(3) NOT NULL,
  `updated_at`            DATETIME(3) NOT NULL,
  `deleted_at`            DATETIME(3) NULL,
  `last_used`             DATETIME(3) NULL,
  `last_error`            VARCHAR(500) NOT NULL DEFAULT '',
  `legacy_integration_id` INT NULL,                         -- integrations.id bei Migration
  PRIMARY KEY (`id`), KEY `user_list` (`userid`,`deleted_at`), KEY `node` (`node_id`), KEY `legacy` (`legacy_integration_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_deliveries` (             -- Zustellprotokoll, Dedup ueber (event_id, channel_id)
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `event_id`   CHAR(32) NOT NULL,
  `channel_id` INT NOT NULL,
  `userid`     INT NOT NULL,
  `node_id`   VARCHAR(32) NOT NULL DEFAULT '',             -- gesetzt, wenn der Node gesendet hat
  `time`       DATETIME(3) NOT NULL,
  `kind`       VARCHAR(20) NOT NULL,
  `ok`         TINYINT NULL,                                -- NULL = Schattenmodus (nicht gesendet)
  `error`      VARCHAR(500) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`), UNIQUE KEY `dedup` (`event_id`,`channel_id`), KEY `user_time` (`userid`,`time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_send_orders` (            -- Sendeauftraege an Agent-Kanaele (Zustellung ueber den Socket)
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `node_id`   VARCHAR(32) NOT NULL,
  `channel_id` INT NOT NULL,
  `event_id`   CHAR(32) NOT NULL,
  `kind`       VARCHAR(20) NOT NULL DEFAULT 'event',        -- event, test, verify
  `payload`    JSON NOT NULL,
  `created_at` DATETIME(3) NOT NULL,
  `fetched_at` DATETIME(3) NULL,
  `done_at`    DATETIME(3) NULL,
  `ok`         TINYINT NULL,
  `error`      VARCHAR(500) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`), KEY `agent_open` (`node_id`,`done_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_commands` (               -- Kommandos Server -> Node (3.8), 1 h gueltig
  `id`         BIGINT NOT NULL AUTO_INCREMENT,
  `node_id`   VARCHAR(32) NOT NULL,
  `name`       VARCHAR(32) NOT NULL,                        -- run_check, test_check, pause, resume, set_log_level, ...
  `args`       JSON NULL,
  `created_at` DATETIME(3) NOT NULL,
  `done_at`    DATETIME(3) NULL,
  `ok`         TINYINT NULL,
  `output`     TEXT NULL,
  PRIMARY KEY (`id`), KEY `agent_open` (`node_id`,`done_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_testruns` (               -- Testlaeufe beim Umhaengen (3.11)
  `id`               BIGINT NOT NULL AUTO_INCREMENT,
  `userid`           INT NOT NULL,
  `token`            VARCHAR(50) NOT NULL,
  `definition`       JSON NOT NULL,
  `target_execution` ENUM('local','online','both') NOT NULL,
  `node_id`         VARCHAR(32) NULL,
  `nodes`      VARCHAR(600) NOT NULL DEFAULT '',          -- Testlauf auf mehreren Nodes
  `locations`        SET('nbg','fsn') NOT NULL DEFAULT 'nbg,fsn',
  `status`           ENUM('pending','running','ok','failed','expired') NOT NULL DEFAULT 'pending',
  `result`           JSON NULL,
  `created_at`       DATETIME(3) NOT NULL,
  `finished_at`      DATETIME(3) NULL,
  PRIMARY KEY (`id`), KEY `open` (`status`,`created_at`), KEY `userid` (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------------------------------------------------------------- Wartung / Einstellungen
CREATE TABLE IF NOT EXISTS `hc2_maintenance` (
  `id`           INT NOT NULL AUTO_INCREMENT,
  `userid`       INT NOT NULL,
  `node_id`     VARCHAR(32) NULL,
  `name`         VARCHAR(200) NOT NULL,
  `start_at`     DATETIME(3) NOT NULL,
  `end_at`       DATETIME(3) NOT NULL,
  `repeat`       ENUM('none','daily','weekly','monthly') NOT NULL DEFAULT 'none',
  `repeat_until` DATETIME(3) NULL,
  `tokens`       TEXT NULL,                                 -- betroffene Tokens kommagetrennt, leer = alle
  `active`       TINYINT NOT NULL DEFAULT 1,
  `revision`     BIGINT NOT NULL DEFAULT 1,
  `created_at`   DATETIME(3) NOT NULL,
  `updated_at`   DATETIME(3) NOT NULL,
  `deleted_at`   DATETIME(3) NULL,
  PRIMARY KEY (`id`), KEY `userid` (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_settings` (               -- Benachrichtigungs-Einstellungen je Account (notify.*)
  `userid` INT NOT NULL,
  `key`    VARCHAR(64) NOT NULL,
  `value`  VARCHAR(500) NOT NULL DEFAULT '',
  PRIMARY KEY (`userid`,`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_usage_daily` (            -- Tageskontingent Online-Checks (healthcheck_update_limit)
  `userid` INT NOT NULL, `day` DATE NOT NULL, `checks` INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`userid`,`day`), KEY `day` (`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_api_sends` (              -- Versand ueber ipv64-Kanaele per API v2 (Dedup, Tagesobergrenze)
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, `userid` INT NOT NULL, `channel_id` INT NOT NULL, `event_id` VARCHAR(100) NULL,
  `kind` VARCHAR(40) NOT NULL DEFAULT '', `source` VARCHAR(60) NOT NULL DEFAULT '', `sent_at` DATETIME(3) NOT NULL,
  `ok` TINYINT NOT NULL DEFAULT 1, `error` VARCHAR(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`), KEY `user_day` (`userid`,`sent_at`), KEY `dedup` (`userid`,`channel_id`,`event_id`), KEY `sent_at` (`sent_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_sms_counter` (            -- Tageslimit SMS je Account
  `userid` INT NOT NULL, `day` DATE NOT NULL, `count` INT NOT NULL DEFAULT 0,
  PRIMARY KEY (`userid`,`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------------------------------------------------------------- Konfigurations-Log / Revisionen
CREATE TABLE IF NOT EXISTS `hc2_revisions` (              -- Zaehler je Account (naechste Revision)
  `userid` INT NOT NULL, `next` BIGINT NOT NULL DEFAULT 1,
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_config_log` (             -- Quelle der Deltas fuer Nodes und hub, 30 Tage
  `id`        BIGINT NOT NULL AUTO_INCREMENT,
  `userid`    INT NOT NULL,
  `node_id`  VARCHAR(32) NULL,                             -- NULL = alle Nodes des Accounts
  `entity`    ENUM('check','channel','maintenance','node','settings') NOT NULL,
  `entity_id` VARCHAR(50) NOT NULL,
  `op`        ENUM('upsert','delete') NOT NULL,
  `revision`  BIGINT NOT NULL,
  `origin`    ENUM('portal','api','node','system') NOT NULL,
  `time`      DATETIME(3) NOT NULL,
  PRIMARY KEY (`id`), KEY `user_id` (`userid`,`id`), KEY `node_id` (`node_id`,`id`), KEY `time` (`time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_migration_log` (          -- Protokoll von bots/hc2_migrate.php
  `id`       BIGINT NOT NULL AUTO_INCREMENT,
  `userid`   INT NOT NULL,
  `time`     DATETIME(3) NOT NULL,
  `step`     VARCHAR(40) NOT NULL,
  `count`    INT NOT NULL DEFAULT 0,
  `note`     VARCHAR(500) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`), KEY `userid` (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_compare_log` (            -- Vergleichsbot alt/neu (Phase 5)
  `id`        BIGINT NOT NULL AUTO_INCREMENT,
  `time`      DATETIME(3) NOT NULL,
  `userid`    INT NOT NULL,
  `token`     VARCHAR(50) NOT NULL,
  `old_state` VARCHAR(12) NOT NULL,
  `new_state` VARCHAR(12) NOT NULL,
  `note`      VARCHAR(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`), KEY `time` (`time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hc2_schema_version` (
  `version` INT NOT NULL, `applied_at` DATETIME(3) NOT NULL,
  PRIMARY KEY (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
INSERT IGNORE INTO `hc2_schema_version` (`version`,`applied_at`) VALUES (1, UTC_TIMESTAMP(3));
