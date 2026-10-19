-- 2026-10-19: neue Check-Typen json (Bedingungen auf eine JSON-Antwort) und dns (Abfrage eines Namens).
-- Vor dem Ausrollen der hubs und Nodes mit Healthchecks 2.14.0 einspielen: ohne den erweiterten ENUM lehnt die
-- Datenbank solche Checks ab (auch rein lokale, weil verknuepfte Nodes alle Checks synchronisieren).
-- Nur Erweiterung der erlaubten Werte, bestehende Zeilen bleiben unveraendert.
ALTER TABLE hc2_checks MODIFY type ENUM('http','keyword','json','dns','icmp','tcp','port','cert','push','docker') NOT NULL;
