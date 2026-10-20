-- Honeypot64 bei ipv64, Phase H4 (Teil DNS-Sperrliste bl.ipv64.net): Zustand des Abgleichs mit PowerDNS.
-- Hauptdatenbank ipv64, MariaDB 10.5+. Mehrfach ausfuehrbar (IF NOT EXISTS), aendert keine bestehende Tabelle.
-- Voraussetzung: honeypot_h3_scoring.sql (H3). Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 7, 8, H4).
--
-- Geschrieben nur von bots/honeypot_dnsbl.php: eine Zeile je Name, der in der Zone bl.ipv64.net steht (A und TXT).
-- Der Cron schreibt nur die Unterschiede zwischen Tagesstand und dieser Tabelle nach PowerDNS; eine Zeile wird erst
-- geaendert, wenn PowerDNS den Block bestaetigt hat (fehlgeschlagene Bloecke wiederholt der naechste Lauf).
-- Tabelle leeren = beim naechsten Lauf alles neu schreiben (Eintraege, die dann nicht mehr gelistet sind, bleiben in
-- der Zone stehen - dafuer lieber "php honeypot_dnsbl.php --full" verwenden).
CREATE TABLE IF NOT EXISTS `hp_dnsbl` (
  `name` varchar(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT 'Name relativ zur Zone: 4.3.2.1 bzw. 32 Nibbles',
  `ip` varchar(45) NOT NULL,
  `a` varchar(120) CHARACTER SET ascii NOT NULL COMMENT 'A-Records, Komma: 127.0.0.2,127.0.0.3',
  `txt` varchar(255) NOT NULL,
  `synced_at` datetime NOT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
