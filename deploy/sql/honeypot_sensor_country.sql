-- Honeypot64: eingestellter Standort des Sensors (Node64 "Standort des Sensors" bzw. NODE64_HONEYPOT_COUNTRY, Meldung
-- sensor.country). Nur fuer die Live-Karte (Ziel-Land der Boegen), nicht fuer die Bewertung. NULL = automatisch (Land
-- der IP der Meldung). Hauptdatenbank ipv64, MariaDB 10.5+. Mehrfach ausfuehrbar.
-- Vor dem Hochladen von api_v2_honeypot.php und bots/honeypot_live.php einspielen (beide nutzen die Spalte).
ALTER TABLE `hp_sensors` ADD COLUMN IF NOT EXISTS `country` char(2) DEFAULT NULL COMMENT 'eingestellter Standort (ISO 3166-1), nur Live-Karte' AFTER `mode`;
