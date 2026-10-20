-- Honeypot64 bei ipv64: Herkunft der Angreifer (Land je IP). Hauptdatenbank ipv64, MariaDB 10.5+.
-- Mehrfach ausfuehrbar (IF NOT EXISTS). Voraussetzung: honeypot_h3_scoring.sql (hp_scores).
-- Gefuellt von bots/blocklist/honeypot_score.php (alle 30 Minuten) aus blocklists/country_ranges.txt.gz
-- (create_blocklists_v2.php, taeglich aus den RIR-Daten). Gelesen von der IP-Auskunft und der Statistik.
-- Planung: docs/PLAN-NODE64-HONEYPOT64.md, Abschnitt "Herkunft der Angreifer".
ALTER TABLE `hp_scores` ADD COLUMN IF NOT EXISTS `country` char(2) DEFAULT NULL COMMENT 'ISO 3166-1 alpha-2, NULL = unbekannt' AFTER `reason`;
