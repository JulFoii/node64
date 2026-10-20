-- Honeypot64 bei ipv64, Phase H3, Teil IP-Auskunft + Freigaben: Freigabeliste (hp_allowlist) und Freigabe-Antraege
-- (hp_release_requests). Hauptdatenbank ipv64, MariaDB 10.5+. Mehrfach ausfuehrbar (IF NOT EXISTS, INSERT IGNORE).
-- Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 6, 7, 9, 13, "H3 Umsetzung (Schnittstellen)").
--
-- Alle Zeiten in UTC (wie die anderen hp_*-Tabellen). ip_bin/ip_start/ip_end = INET6_ATON-Form (IPv4 4 Byte,
-- IPv6 16 Byte); Bereiche vergleicht man nur bei gleicher Laenge (LENGTH(ip_start) = LENGTH(<ip>)).
--
-- Wer liest/schreibt:
--   hp_allowlist          schreibt: bots/honeypot_release.php (source=request), honeypot/admin.php (manual/infra/cdn),
--                         dieses Skript (infra); liest: Bewertung (bots/blocklist/honeypot_score.php), IP-Auskunft.
--                         Gueltig, solange until IS NULL (dauerhaft) oder until > UTC_TIMESTAMP().
--   hp_release_requests   schreibt: honeypot/ip.php (Antrag, Bestaetigung), bots/honeypot_release.php (Pruefung),
--                         honeypot/admin.php (Entscheidung); liest: IP-Auskunft (Status).
--
-- Fristen (bots/honeypot_release.php): unbestaetigte Antraege nach 48 h geloescht, client_hash nach 2 Tagen geleert,
-- E-Mail 90 Tage nach der Entscheidung geleert, entschiedene Antraege nach 365 Tagen geloescht, abgelaufene
-- Freigaben aus Antraegen (source=request) 7 Tage nach Ablauf geloescht.

-- Freigabeliste: Netze/IPs, die nie auf die v64 Blocklist kommen (dauerhaft oder bis until).
CREATE TABLE IF NOT EXISTS `hp_allowlist` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `cidr` varchar(49) NOT NULL COMMENT 'Netz in CIDR-Form, Netzadresse ohne Host-Bits (einzelne IP: /32 bzw. /128)',
  `ip_start` varbinary(16) NOT NULL COMMENT 'erste Adresse (INET6_ATON-Form)',
  `ip_end` varbinary(16) NOT NULL COMMENT 'letzte Adresse (INET6_ATON-Form)',
  `reason` varchar(255) NOT NULL DEFAULT '',
  `source` varchar(16) NOT NULL DEFAULT 'manual' COMMENT 'manual, request, infra, cdn',
  `until` datetime DEFAULT NULL COMMENT 'UTC; NULL = dauerhaft',
  `created_at` datetime NOT NULL,
  `created_by` int(11) DEFAULT NULL COMMENT 'userid; NULL = automatisch (Cron, dieses Skript)',
  PRIMARY KEY (`id`),
  UNIQUE KEY `cidr_source` (`cidr`, `source`),
  KEY `range` (`ip_start`, `ip_end`),
  KEY `until` (`until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Freigabe-Antraege aus der IP-Auskunft (Plan Abschnitt 9). Anonym erst nach Bestaetigung per Mail-Link gueltig
-- (confirmed_at), eingeloggt sofort. Nur noetige Daten: IP, Begruendung, E-Mail (nur anonym, fuer Bestaetigung und
-- Bescheid; eingeloggt kommt die Adresse aus users), Status. Keine IP des Antragstellers im Klartext.
CREATE TABLE IF NOT EXISTS `hp_release_requests` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `ip` varchar(45) NOT NULL COMMENT 'beantragte IP (normalisiert)',
  `ip_bin` varbinary(16) NOT NULL,
  `userid` int(11) DEFAULT NULL COMMENT 'NULL = anonym',
  `email` varchar(254) NOT NULL DEFAULT '' COMMENT 'nur anonym; wird 90 Tage nach der Entscheidung geleert',
  `reason` varchar(2000) NOT NULL DEFAULT '',
  `status` varchar(16) NOT NULL DEFAULT 'open' COMMENT 'open, released, rejected, escalated',
  `created_at` datetime NOT NULL,
  `confirmed_at` datetime DEFAULT NULL COMMENT 'NULL = Mail-Bestaetigung ausstehend; ab hier laufen die 24 h',
  `decided_at` datetime DEFAULT NULL,
  `decided_by` int(11) DEFAULT NULL COMMENT 'userid; NULL = automatisch',
  `protected_until` datetime DEFAULT NULL COMMENT 'bei released: Schutz bis (UTC); NULL bei dauerhafter Freigabe',
  `note` varchar(2000) NOT NULL DEFAULT '' COMMENT 'intern: Pruefergebnis, Grund der Eskalation, Entscheidung',
  `token` char(32) CHARACTER SET ascii NOT NULL COMMENT 'Statuslink (ip.php?request=...)',
  `confirm_hash` char(64) CHARACTER SET ascii NOT NULL DEFAULT '' COMMENT 'SHA-256 des Bestaetigungs-Tokens aus der Mail; leer nach Bestaetigung',
  `client_hash` char(64) CHARACTER SET ascii NOT NULL DEFAULT '' COMMENT 'SHA-256 der IP des Antragstellers fuer die Drossel; nach 2 Tagen geleert',
  `lang` char(2) CHARACTER SET ascii NOT NULL DEFAULT 'de' COMMENT 'Sprache der Mails (de, en)',
  PRIMARY KEY (`id`),
  UNIQUE KEY `token` (`token`),
  KEY `ip_bin` (`ip_bin`, `created_at`),
  KEY `status` (`status`, `confirmed_at`),
  KEY `email` (`email`, `created_at`),
  KEY `userid` (`userid`, `created_at`),
  KEY `client` (`client_hash`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Startwerte: eigene Infrastruktur (Plan Abschnitt 6: "Nie listen: ... Infrastruktur von ipv64").
-- IPv4 als einzelne Adresse, IPv6 als das /64, das Hetzner Cloud dem Server zuteilt (Adresse ::1 daraus).
-- Quellen: docs/CDN64-ONLINE.md (Abschnitt 10) und die hub-Server von Healthchecks 2.0.
INSERT IGNORE INTO `hp_allowlist` (`cidr`, `ip_start`, `ip_end`, `reason`, `source`, `until`, `created_at`, `created_by`) VALUES
  ('91.99.98.96/32', INET6_ATON('91.99.98.96'), INET6_ATON('91.99.98.96'), 'srv07.cdn64.de (CDN64 Edge)', 'infra', NULL, UTC_TIMESTAMP(), NULL),
  ('2a01:4f8:1c18:5887::/64', INET6_ATON('2a01:4f8:1c18:5887::'), INET6_ATON('2a01:4f8:1c18:5887:ffff:ffff:ffff:ffff'), 'srv07.cdn64.de (CDN64 Edge)', 'infra', NULL, UTC_TIMESTAMP(), NULL),
  ('2.28.6.30/32', INET6_ATON('2.28.6.30'), INET6_ATON('2.28.6.30'), 'srv08.cdn64.de (CDN64 Edge)', 'infra', NULL, UTC_TIMESTAMP(), NULL),
  ('2a01:4f8:c015:bca8::/64', INET6_ATON('2a01:4f8:c015:bca8::'), INET6_ATON('2a01:4f8:c015:bca8:ffff:ffff:ffff:ffff'), 'srv08.cdn64.de (CDN64 Edge)', 'infra', NULL, UTC_TIMESTAMP(), NULL),
  ('188.245.6.138/32', INET6_ATON('188.245.6.138'), INET6_ATON('188.245.6.138'), 'hc-srv01.ipv64.net (hub Healthchecks 2.0)', 'infra', NULL, UTC_TIMESTAMP(), NULL),
  ('2a01:4f8:c014:46b::/64', INET6_ATON('2a01:4f8:c014:46b::'), INET6_ATON('2a01:4f8:c014:46b:ffff:ffff:ffff:ffff'), 'hc-srv01.ipv64.net (hub Healthchecks 2.0)', 'infra', NULL, UTC_TIMESTAMP(), NULL),
  ('178.105.50.207/32', INET6_ATON('178.105.50.207'), INET6_ATON('178.105.50.207'), 'hc-srv02.ipv64.net (hub Healthchecks 2.0)', 'infra', NULL, UTC_TIMESTAMP(), NULL),
  ('2a01:4f8:1c1f:b393::/64', INET6_ATON('2a01:4f8:1c1f:b393::'), INET6_ATON('2a01:4f8:1c1f:b393:ffff:ffff:ffff:ffff'), 'hc-srv02.ipv64.net (hub Healthchecks 2.0)', 'infra', NULL, UTC_TIMESTAMP(), NULL);

-- Platzhalter (Dennis ergaenzt die echten Adressen, Muster wie oben; IPv6-Netz nur, wenn es wirklich ganz uns gehoert):
--   Webserver ipv64.net (Portal, API)                        ('<ipv4>/32', INET6_ATON('<ipv4>'), INET6_ATON('<ipv4>'), 'ipv64.net Webserver', 'infra', NULL, UTC_TIMESTAMP(), NULL)
--   DNS-Server (PowerDNS, ns1/ns2 ...)                       dito, reason 'ipv64 DNS'
--   Mailserver (Versand no-reply@ipv64.net)                  dito, reason 'ipv64 Mail'
--   altes CDN srv01-srv06 (bis zur Abschaltung)              dito, reason 'CDN srv0x'
--   DynDNS-/Healthcheck-Messstellen, VPN-Gateways (Cloud Router), x64-Netze
-- Grosse CDNs gehoeren mit source = 'cdn' hinein (oder bleiben in der Bewertung ueber die Cloud-Listen ausgenommen).
