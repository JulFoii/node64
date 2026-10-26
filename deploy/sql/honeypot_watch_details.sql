-- Honeypot64 Fruehwarnung: Details je Treffer (warum die IP aufgefallen ist). Hauptdatenbank ipv64, MariaDB 10.5+.
-- Mehrfach ausfuehrbar. Vor dem Hochladen von bots/honeypot_watch.php einspielen (der Cron schreibt die Spalte).
-- Inhalt (JSON, bots/honeypot_watch.php -> hpl_watch_details): accounts, sensors, events, lists, reason und seen
-- (hoechstens 8 Zeilen: origin, service, port, kind, rule, count, sensors, last) - nur Anzahlen, keine Sensoren oder Inhalte.
ALTER TABLE `hp_watch_alerts` ADD COLUMN IF NOT EXISTS `details` text DEFAULT NULL COMMENT 'JSON: warum die IP aufgefallen ist' AFTER `last_seen`;
