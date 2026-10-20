-- Honeypot64 bei ipv64, Phase H3 (Teil Bewertung + Listen): Vertrauenswert je IP und Listen-Token fuer den Live-Stand.
-- Hauptdatenbank ipv64, MariaDB 10.5+. Mehrfach ausfuehrbar (IF NOT EXISTS), aendert keine bestehende Tabelle.
-- Voraussetzung: deploy/sql/honeypot.sql (H2). Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 6, 7, 8, "H3 Umsetzung").
--
-- Geschrieben von bots/blocklist/honeypot_score.php (alle 30 Minuten), gelesen von create_blocklists_v2.php (Listen),
-- blocklists/live.php (Live-Abruf) und der IP-Auskunft (Teil Freigaben, nur lesend). Alle Zeiten UTC.

-- Bewertung je IP (alle IPs mit Treffern in den letzten 14 Tagen; aeltere Zeilen loescht die Bewertung).
-- IPs von Sensoren und nicht oeffentliche Adressen stehen hier nie drin (die IP-Auskunft darf Sensoren nicht verraten).
--   accounts      unabhaengige Accounts (Accounts mit Sensoren im selben /24 bzw. /48 zaehlen als einer)
--   accounts_eff  dieselben, mit Vertrauen gewichtet (0.25 bis 1 je Account) - Grundlage der Schwelle
--   strong_eff    gewichtete Accounts mit Login/Exploit (Schwelle unter 20 aktiven Accounts)
--   lists         Listen, in denen die IP steht: v64 (Hauptliste), ssh, web, mail, rdp, scanner, research
--   reason        threshold (gelistet) | customer_ip | allowlist | infra | cdn (nicht gelistet trotz Schwelle) | '' (unter der Schwelle)
CREATE TABLE IF NOT EXISTS `hp_scores` (
  `ip_bin` varbinary(16) NOT NULL COMMENT 'INET6_ATON-Form, IPv4 4 Byte',
  `ip` varchar(45) NOT NULL,
  `family` tinyint(1) NOT NULL COMMENT '4 oder 6',
  `score` tinyint(3) unsigned NOT NULL DEFAULT 0 COMMENT 'Vertrauenswert 0-100',
  `accounts` smallint(5) unsigned NOT NULL DEFAULT 0,
  `accounts_eff` decimal(6,2) NOT NULL DEFAULT 0.00,
  `strong_eff` decimal(6,2) NOT NULL DEFAULT 0.00,
  `sensors` int(10) unsigned NOT NULL DEFAULT 0,
  `events` bigint(20) unsigned NOT NULL DEFAULT 0,
  `kinds` varchar(255) NOT NULL DEFAULT '' COMMENT 'Arten, Komma',
  `lists` varchar(64) NOT NULL DEFAULT '' COMMENT 'Komma: v64,ssh,web,mail,rdp,scanner,research',
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `listed` tinyint(1) NOT NULL DEFAULT 0,
  `listed_since` datetime DEFAULT NULL,
  `reason` varchar(16) NOT NULL DEFAULT '',
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`ip_bin`),
  KEY `listed` (`listed`, `score`),
  KEY `reason` (`reason`),
  KEY `updated_at` (`updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Listen-Token je Account fuer /blocklists/live/<token>/<datei> (getrennt vom API-Key, im Account sichtbar und widerrufbar).
-- uses_*: alle Abrufe des Tokens je 5-Minuten-Fenster (Obergrenze ueber alle Dateien).
CREATE TABLE IF NOT EXISTS `hp_list_tokens` (
  `userid` int(11) NOT NULL,
  `token` char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT 'genau 32 Zeichen [A-Za-z0-9]',
  `created_at` datetime NOT NULL,
  `last_used` datetime DEFAULT NULL,
  `uses_window_start` datetime DEFAULT NULL,
  `uses_in_window` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`userid`),
  UNIQUE KEY `token` (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Letzter Abruf je Token und Datei (hoechstens alle 5 Minuten dieselbe Datei; sonst 429 bzw. 304 mit ETag).
CREATE TABLE IF NOT EXISTS `hp_list_token_files` (
  `userid` int(11) NOT NULL,
  `file` varchar(64) CHARACTER SET ascii NOT NULL,
  `last_at` datetime NOT NULL,
  PRIMARY KEY (`userid`, `file`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
