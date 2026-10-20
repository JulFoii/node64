-- Honeypot64 bei ipv64, Phase H2: Meldungen der Sensoren (POST /api/v2/honeypot/reports), Proben als Tagessummen,
-- Statistik fuer Beitragende. Hauptdatenbank ipv64, MariaDB 10.5+. Mehrfach ausfuehrbar (IF NOT EXISTS).
-- Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 4, 5, 6, 10, 13), Vertrag: internal/honeypot/report_types.go.
--
-- Alle Zeiten in UTC (UTC_TIMESTAMP()), `day` = UTC-Tag. Texte: utf8mb4; die API ersetzt 4-Byte-Zeichen vor dem
-- Schreiben, weil die Verbindung mit SET NAMES 'utf8' laeuft.
--
-- Fristen (Plan Abschnitt 4), umgesetzt von bots/honeypot_cleanup.php (taeglich):
--   hp_report_sources, hp_reports   volle IP: 90 Tage, dann je Tag nach hp_sources_archive verdichtet und geloescht
--   hp_sources_archive              IP gekuerzt auf /24 (IPv4) bzw. /48 (IPv6): 24 Monate (ASN/Land: H3)
--   hp_daily                        keine IPs: 24 Monate
--   hp_samples_*                    keine personenbezogenen Daten: unbegrenzt
--   hp_sensors                      solange der Sensor existiert; last_ip ist intern und wird nie ausgegeben
--
-- Partitionierung nach Tag (vorbereitet): hp_reports und hp_report_sources haben `day` in allen PRIMARY/UNIQUE KEYs
-- und keine Fremdschluessel. Werden sie gross, ohne Schluesselaenderung umstellen (einmalig, kopiert die Tabelle):
--   ALTER TABLE hp_report_sources PARTITION BY RANGE COLUMNS(`day`) (
--     PARTITION p20261101 VALUES LESS THAN ('2026-11-02'), ..., PARTITION pmax VALUES LESS THAN (MAXVALUE));
-- Danach taeglich vor Mitternacht UTC die leere pmax teilen (REORGANIZE PARTITION pmax INTO (PARTITION pYYYYMMDD
-- VALUES LESS THAN ('<morgen+1>'), PARTITION pmax VALUES LESS THAN (MAXVALUE))) und im Aufraeum-Cron statt
-- DELETE alte Tage mit ALTER TABLE ... DROP PARTITION entfernen (nach dem Verdichten). Gleiches fuer hp_reports.

-- Sensoren (eine Zeile je Installation, sensor.id aus der Meldung).
CREATE TABLE IF NOT EXISTS `hp_sensors` (
  `sensor_id` char(36) NOT NULL,
  `userid` int(11) NOT NULL,
  `version` varchar(32) NOT NULL DEFAULT '',
  `profile` varchar(16) NOT NULL DEFAULT '',
  `mode` varchar(16) NOT NULL DEFAULT '',
  `first_seen` datetime NOT NULL,
  `last_seen` datetime DEFAULT NULL,
  `last_ip` varchar(45) NOT NULL DEFAULT '' COMMENT 'oeffentliche IP aus der Verbindung, intern, nie veroeffentlicht',
  `last_report_id` varchar(80) NOT NULL DEFAULT '',
  `last_period_end` datetime DEFAULT NULL,
  `reports` int(10) unsigned NOT NULL DEFAULT 0,
  `disabled` tinyint(1) NOT NULL DEFAULT 0 COMMENT '1 = Meldungen werden mit 403 abgewiesen',
  PRIMARY KEY (`sensor_id`),
  KEY `userid` (`userid`, `last_seen`),
  KEY `last_ip` (`last_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Meldungen (nur anhaengend). report_id = <sensor.id>-<period.start unix>, darum ist day (UTC-Tag von period_start)
-- durch report_id festgelegt und UNIQUE (report_id, day) wirkt wie UNIQUE (report_id).
CREATE TABLE IF NOT EXISTS `hp_reports` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `day` date NOT NULL,
  `report_id` varchar(80) NOT NULL,
  `sensor_id` char(36) NOT NULL,
  `userid` int(11) NOT NULL,
  `schema_version` tinyint(3) unsigned NOT NULL DEFAULT 1,
  `version` varchar(32) NOT NULL DEFAULT '',
  `period_start` datetime NOT NULL,
  `period_end` datetime NOT NULL,
  `received_at` datetime NOT NULL,
  `sources` int(10) unsigned NOT NULL DEFAULT 0 COMMENT 'gespeicherte Quellen',
  `rejected` int(10) unsigned NOT NULL DEFAULT 0 COMMENT 'von ipv64 verworfen (privat/reserviert, eigene IP, unbekannte Art)',
  `dropped` bigint(20) unsigned NOT NULL DEFAULT 0 COMMENT 'vom Sensor wegen Grenzen weggelassen',
  `samples` int(10) unsigned NOT NULL DEFAULT 0,
  `overlap` tinyint(1) NOT NULL DEFAULT 0 COMMENT '1 = Zeitraum ueberschneidet die vorige Meldung des Sensors',
  `ip` varchar(45) NOT NULL DEFAULT '' COMMENT 'IP des Sensors, intern',
  `bytes` int(10) unsigned NOT NULL DEFAULT 0 COMMENT 'Groesse entpackt',
  PRIMARY KEY (`id`, `day`),
  UNIQUE KEY `report_id` (`report_id`, `day`),
  KEY `sensor` (`sensor_id`, `received_at`),
  KEY `userid` (`userid`, `received_at`),
  KEY `day` (`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Quellen je Meldung (je IP, Art, Dienst, Port zusammengefasst). Grundlage der Bewertung in H3.
CREATE TABLE IF NOT EXISTS `hp_report_sources` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `day` date NOT NULL COMMENT 'wie hp_reports.day',
  `report_ref` bigint(20) unsigned NOT NULL COMMENT 'hp_reports.id',
  `userid` int(11) NOT NULL,
  `sensor_id` char(36) NOT NULL,
  `ip` varchar(45) NOT NULL,
  `ip_bin` varbinary(16) NOT NULL,
  `kind` varchar(40) NOT NULL,
  `service` varchar(16) NOT NULL,
  `port` smallint(5) unsigned NOT NULL DEFAULT 0,
  `count` int(10) unsigned NOT NULL DEFAULT 1,
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `source` varchar(16) NOT NULL DEFAULT 'honeypot',
  `rule` varchar(64) NOT NULL DEFAULT '',
  `detail` varchar(256) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`, `day`),
  KEY `ip_last` (`ip_bin`, `last_seen`),
  KEY `user_last` (`userid`, `last_seen`),
  KEY `last` (`last_seen`),
  KEY `report` (`report_ref`),
  KEY `day` (`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Nach 90 Tagen verdichtet: Netz statt IP (/24 bzw. /48), je Tag, Netz, Art, Dienst, Port.
CREATE TABLE IF NOT EXISTS `hp_sources_archive` (
  `day` date NOT NULL,
  `net_bin` varbinary(16) NOT NULL COMMENT 'IPv4 /24 bzw. IPv6 /48, Rest genullt',
  `family` tinyint(1) NOT NULL COMMENT '4 oder 6',
  `kind` varchar(40) NOT NULL,
  `service` varchar(16) NOT NULL,
  `port` smallint(5) unsigned NOT NULL DEFAULT 0,
  `events` bigint(20) unsigned NOT NULL DEFAULT 0,
  `ips` int(10) unsigned NOT NULL DEFAULT 0 COMMENT 'verschiedene IPs im Netz',
  `accounts` int(10) unsigned NOT NULL DEFAULT 0 COMMENT 'verschiedene meldende Accounts',
  `asn` int(10) unsigned DEFAULT NULL COMMENT 'TODO H3: Anreicherung',
  `country` char(2) NOT NULL DEFAULT '' COMMENT 'TODO H3: Anreicherung',
  PRIMARY KEY (`day`, `net_bin`, `kind`, `service`, `port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Bereits verdichtete Tage (das Loeschen laeuft danach in Bloecken; ein Abbruch zaehlt nichts doppelt).
CREATE TABLE IF NOT EXISTS `hp_archive_days` (
  `day` date NOT NULL,
  `archived_at` datetime NOT NULL,
  PRIMARY KEY (`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Statistik je Tag, Account, Sensor, Art, Dienst, Port (Seite fuer Beitragende, GET /honeypot/stats).
CREATE TABLE IF NOT EXISTS `hp_daily` (
  `day` date NOT NULL,
  `userid` int(11) NOT NULL,
  `sensor_id` char(36) NOT NULL,
  `kind` varchar(40) NOT NULL,
  `service` varchar(16) NOT NULL,
  `port` smallint(5) unsigned NOT NULL DEFAULT 0,
  `events` bigint(20) unsigned NOT NULL DEFAULT 0 COMMENT 'Summe count',
  `sources` int(10) unsigned NOT NULL DEFAULT 0 COMMENT 'Zahl der Quell-Eintraege (nicht verschiedene IPs)',
  PRIMARY KEY (`day`, `userid`, `sensor_id`, `kind`, `service`, `port`),
  KEY `userid` (`userid`, `day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Proben als laufende Summen je Tag (alle Accounts zusammen, keine Rohdaten, keine IPs).
-- key_hash = SHA-256 ueber den Originaltext (bei Zugangsdaten: service NUL user NUL pass).
CREATE TABLE IF NOT EXISTS `hp_samples_creds` (
  `day` date NOT NULL,
  `key_hash` binary(32) NOT NULL,
  `service` varchar(16) NOT NULL,
  `username` varchar(256) NOT NULL DEFAULT '',
  `password` varchar(256) NOT NULL DEFAULT '',
  `pass_sha1` char(40) CHARACTER SET ascii NOT NULL DEFAULT '' COMMENT 'SHA-1 des Passworts (Passwortpruefung mit k-Anonymitaet, H6)',
  `count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `last_seen` datetime NOT NULL,
  PRIMARY KEY (`day`, `key_hash`),
  KEY `pass_sha1` (`pass_sha1`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hp_samples_paths` (
  `day` date NOT NULL,
  `key_hash` binary(32) NOT NULL,
  `path` varchar(1024) NOT NULL,
  `count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `last_seen` datetime NOT NULL,
  PRIMARY KEY (`day`, `key_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `hp_samples_uas` (
  `day` date NOT NULL,
  `key_hash` binary(32) NOT NULL,
  `user_agent` varchar(256) NOT NULL,
  `count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `last_seen` datetime NOT NULL,
  PRIMARY KEY (`day`, `key_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Payload-Anfaenge: sha256 vom Sensor (ueber die erfassten Bytes), head als base64 (hoechstens 256 Bytes).
CREATE TABLE IF NOT EXISTS `hp_samples_payloads` (
  `day` date NOT NULL,
  `sha256` char(64) CHARACTER SET ascii NOT NULL,
  `service` varchar(16) NOT NULL,
  `port` smallint(5) unsigned NOT NULL DEFAULT 0,
  `head_b64` varchar(344) CHARACTER SET ascii NOT NULL DEFAULT '',
  `count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `last_seen` datetime NOT NULL,
  PRIMARY KEY (`day`, `sha256`, `service`, `port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
