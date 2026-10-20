-- Honeypot64 bei ipv64, Phase H5, Teil Fruehwarnung: eigene Netze je Account (hp_watch) und Treffer (hp_watch_alerts).
-- Hauptdatenbank ipv64, MariaDB 10.5+. Mehrfach ausfuehrbar (IF NOT EXISTS), aendert keine bestehende Tabelle.
-- Voraussetzung: honeypot.sql (H2) und honeypot_h3_scoring.sql (hp_scores). Planung: docs/PLAN-NODE64-HONEYPOT64.md
-- (Abschnitte 8, 11, "H5 Umsetzung").
--
-- Alle Zeiten in UTC. ip_bin/ip_start/ip_end = INET6_ATON-Form (IPv4 4 Byte, IPv6 16 Byte); Bereiche vergleicht man
-- nur bei gleicher Laenge: LENGTH(ip_start) = LENGTH(ip_bin) AND ip_start <= ip_bin AND ip_end >= ip_bin.
--
-- Wer liest/schreibt:
--   hp_watch          schreibt: API v2 POST/DELETE /threat/watch (api_v2_threat_watch.php), honeypot/watch.php;
--                     liest: bots/honeypot_watch.php (Cron), GET /threat/watch.
--                     verified = 1 setzt nur ein Admin (per SQL, siehe unten); ohne Nachweis gibt es nur Treffer fuer
--                     IPs, die auf der v64 Blocklist stehen (hp_scores.listed = 1, ohnehin oeffentlich).
--   hp_watch_alerts   schreibt: bots/honeypot_watch.php (alle 30 Minuten, 5 Minuten nach der Bewertung);
--                     liest: GET /threat/watch/alerts, honeypot/watch.php.
--
-- Fristen (bots/honeypot_watch.php): Treffer nach 90 Tagen geloescht.
--
-- Nachweis fuer ein Netz setzen (z. B. nach RIR-Eintrag oder Mail an die Abuse-Adresse):
--   UPDATE hp_watch SET verified = 1 WHERE id = <id>;

-- Eigene Netze (Fruehwarnung, Plan Abschnitt 11). Limits je Klasse: honeypot/hp_limits_lib.php.
CREATE TABLE IF NOT EXISTS `hp_watch` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `userid` int(11) NOT NULL,
  `cidr` varchar(49) NOT NULL COMMENT 'Netz in CIDR-Form, Netzadresse ohne Host-Bits (einzelne IP: /32 bzw. /128)',
  `ip_start` varbinary(16) NOT NULL COMMENT 'erste Adresse (INET6_ATON-Form)',
  `ip_end` varbinary(16) NOT NULL COMMENT 'letzte Adresse (INET6_ATON-Form)',
  `label` varchar(100) NOT NULL DEFAULT '',
  `verified` tinyint(1) NOT NULL DEFAULT 0 COMMENT '1 = Nachweis erbracht (nur Admin, per SQL): jede Sichtung meldet; 0 = nur gelistete IPs',
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_cidr` (`userid`, `cidr`),
  KEY `range` (`ip_start`, `ip_end`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Treffer: eine IP eines eigenen Netzes bzw. eine DynDNS-IP des Accounts ist bei der Bewertung aufgefallen.
-- Eine IP je Account hoechstens einmal je 24 h, ausser sie wird neu gelistet. Werte (listed, score, kinds, Sichtungen)
-- sind der Stand aus hp_scores beim Erzeugen.
--   network_id   hp_watch.id (bleibt stehen, wenn das Netz spaeter geloescht wird); NULL bei source = dyndns
--   cidr, label  Netz und Bezeichnung bzw. bei dyndns die IP als /32 bzw. /128 und die Domain
--   mailed_at    Mail an die Account-Adresse gesendet (gebuendelt je Lauf); NULL = noch nicht (wird 24 h lang nachgeholt)
CREATE TABLE IF NOT EXISTS `hp_watch_alerts` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `userid` int(11) NOT NULL,
  `ip` varchar(45) NOT NULL,
  `ip_bin` varbinary(16) NOT NULL,
  `network_id` int(10) unsigned DEFAULT NULL,
  `source` varchar(8) NOT NULL COMMENT 'network, dyndns',
  `cidr` varchar(49) NOT NULL DEFAULT '',
  `label` varchar(255) NOT NULL DEFAULT '',
  `listed` tinyint(1) NOT NULL DEFAULT 0,
  `score` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `kinds` varchar(255) NOT NULL DEFAULT '' COMMENT 'Arten, Komma',
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `created_at` datetime NOT NULL,
  `mailed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_created` (`userid`, `created_at`, `id`),
  KEY `user_ip` (`userid`, `ip_bin`, `id`),
  KEY `mail` (`mailed_at`, `created_at`),
  KEY `created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
