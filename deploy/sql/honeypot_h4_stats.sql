-- Honeypot64 bei ipv64, Phase H4 (Teil Statistik + Listen): Beitrag je Account zu den Proben (Schutz gegen Vergiften),
-- Ranglisten fuer Statistik und Text-Listen, Cache der Statistik. Hauptdatenbank ipv64, MariaDB 10.5+.
-- Mehrfach ausfuehrbar (IF NOT EXISTS, INSERT IGNORE). Voraussetzung: deploy/sql/honeypot.sql (H2), fuer die Statistik
-- auch honeypot_h3_scoring.sql (hp_scores). Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 7, 8, 10, 13).
--
-- Reihenfolge beim Einspielen: ERST diese Datei, DANN die neue api_v2_honeypot.php (sie schreibt hp_sample_contrib in
-- derselben Transaktion wie die Proben; fehlt die Tabelle, wird jede Meldung mit 500 abgewiesen und der Sensor holt
-- sie spaeter nach).
--
-- Geschrieben von api_v2_honeypot.php (hp_sample_contrib), honeypot/hp_stats_lib.php (hp_sample_top, hp_stats_cache;
-- aufgerufen von honeypot/stats.php, GET /threat/stats und bots/honeypot_lists.php). Alle Zeiten UTC.

-- Beitrag je Account: welcher Account hat an welchem Tag welche Probe gemeldet (und wie oft). Listen und Ranglisten
-- nehmen nur Proben, die mindestens N verschiedene Accounts in den letzten 30 Tagen gemeldet haben (N = 2 unter 20
-- aktiven Accounts, sonst 3). Ein einzelner Account kann so nichts in die Listen druecken.
--   kind      cred (key_hash wie hp_samples_creds), path (wie hp_samples_paths), ua (wie hp_samples_uas),
--             payload (key_hash = UNHEX(hp_samples_payloads.sha256), Dienst/Port zusammengefasst)
--   userid 0  Altbestand ohne Account-Bezug (Proben vor H4): zaehlt als ein Account
--   cnt       Summe count dieses Accounts an diesem Tag
-- Frist: 35 Tage (bots/honeypot_lists.php loescht aeltere Zeilen); die Proben selbst bleiben unbegrenzt.
CREATE TABLE IF NOT EXISTS `hp_sample_contrib` (
  `kind` varchar(8) CHARACTER SET ascii NOT NULL,
  `day` date NOT NULL,
  `key_hash` binary(32) NOT NULL,
  `userid` int(11) NOT NULL,
  `cnt` bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`kind`, `day`, `key_hash`, `userid`),
  KEY `day` (`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Altbestand der letzten 30 Tage als Account 0 (nur Schluessel, die noch keinen Beitrag haben).
INSERT IGNORE INTO `hp_sample_contrib` (`kind`, `day`, `key_hash`, `userid`, `cnt`)
  SELECT 'cred', s.`day`, s.`key_hash`, 0, s.`count` FROM `hp_samples_creds` s
  WHERE s.`day` >= UTC_DATE() - INTERVAL 30 DAY
    AND NOT EXISTS (SELECT 1 FROM `hp_sample_contrib` k WHERE k.`kind` = 'cred' AND k.`day` = s.`day` AND k.`key_hash` = s.`key_hash`);
INSERT IGNORE INTO `hp_sample_contrib` (`kind`, `day`, `key_hash`, `userid`, `cnt`)
  SELECT 'path', s.`day`, s.`key_hash`, 0, s.`count` FROM `hp_samples_paths` s
  WHERE s.`day` >= UTC_DATE() - INTERVAL 30 DAY
    AND NOT EXISTS (SELECT 1 FROM `hp_sample_contrib` k WHERE k.`kind` = 'path' AND k.`day` = s.`day` AND k.`key_hash` = s.`key_hash`);
INSERT IGNORE INTO `hp_sample_contrib` (`kind`, `day`, `key_hash`, `userid`, `cnt`)
  SELECT 'ua', s.`day`, s.`key_hash`, 0, s.`count` FROM `hp_samples_uas` s
  WHERE s.`day` >= UTC_DATE() - INTERVAL 30 DAY
    AND NOT EXISTS (SELECT 1 FROM `hp_sample_contrib` k WHERE k.`kind` = 'ua' AND k.`day` = s.`day` AND k.`key_hash` = s.`key_hash`);
INSERT IGNORE INTO `hp_sample_contrib` (`kind`, `day`, `key_hash`, `userid`, `cnt`)
  SELECT 'payload', s.`day`, UNHEX(s.`sha256`), 0, SUM(s.`count`) FROM `hp_samples_payloads` s
  WHERE s.`day` >= UTC_DATE() - INTERVAL 30 DAY
    AND NOT EXISTS (SELECT 1 FROM `hp_sample_contrib` k WHERE k.`kind` = 'payload' AND k.`day` = s.`day` AND k.`key_hash` = UNHEX(s.`sha256`))
  GROUP BY s.`day`, s.`sha256`;

-- "Neue Pfade heute": erstes Auftreten eines Pfads ohne Suche ueber alle Tage.
ALTER TABLE `hp_samples_paths` ADD INDEX IF NOT EXISTS `key_day` (`key_hash`, `day`);

-- Ranglisten (30 Tage, nur Eintraege ab der Account-Schwelle, bereinigt: ohne Steuer-/Bidi-Zeichen, E-Mail-Adressen,
-- zufaellige oder sehr lange Strings). Grundlage fuer Statistik, Suche, CSV-Export und die Text-Listen.
--   kind  pass, user, path, ua;  pos = Rang (1 = haeufigster)
--   events Summe count (je Account und Tag hoechstens HPS_CAP_DAY), accounts = verschiedene meldende Accounts
CREATE TABLE IF NOT EXISTS `hp_sample_top` (
  `kind` varchar(8) CHARACTER SET ascii NOT NULL,
  `pos` int(10) unsigned NOT NULL,
  `text` varchar(1024) NOT NULL,
  `events` bigint(20) unsigned NOT NULL DEFAULT 0,
  `accounts` int(10) unsigned NOT NULL DEFAULT 0,
  `last_seen` datetime NOT NULL,
  PRIMARY KEY (`kind`, `pos`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Cache der Statistik (JSON, hoechstens alle 10 Minuten neu berechnet).
CREATE TABLE IF NOT EXISTS `hp_stats_cache` (
  `name` varchar(32) CHARACTER SET ascii NOT NULL,
  `data` mediumtext NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
