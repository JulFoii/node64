-- 2026-10-26: Check-Typen proxmox (Gaeste/Nodes „als Check“ aus der Proxmox-VE-Ueberwachung der Nodes) und whois
-- (WHOIS/RDAP, Healthchecks 2.31.0). Ohne den erweiterten ENUM lehnt die Datenbank sie ab: der hub meldet beim Sync
-- „database error“ (Error 1265 Data truncated for column 'type'), auf der Node steht ein Konflikt.
-- In der Healthchecks-2.0-Datenbank (ipv64_hc) ausfuehren. Nur Erweiterung der erlaubten Werte, bestehende Zeilen
-- bleiben unveraendert; mehrfach ausfuehrbar.
ALTER TABLE hc2_checks MODIFY type ENUM('http','keyword','json','dns','icmp','tcp','port','cert','push','docker','proxmox','whois') NOT NULL;
