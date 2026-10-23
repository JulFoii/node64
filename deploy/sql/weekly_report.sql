-- Wochenbericht (deploy/web/weekly_report_lib.php): Schalter je Account (Standard an), Sprache, eigener Abmelde-Token
-- und Versandprotokoll je Woche. Datenbank ipv64 (Hauptdatenbank). Mehrfach ausfuehrbar.
ALTER TABLE users
	ADD COLUMN IF NOT EXISTS weekly_report TINYINT(1) NOT NULL DEFAULT 1,
	ADD COLUMN IF NOT EXISTS weekly_report_lang CHAR(2) NOT NULL DEFAULT 'de',
	ADD COLUMN IF NOT EXISTS report_token CHAR(32) NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS weekly_report_log (
	userid INT NOT NULL,
	week CHAR(8) NOT NULL,              -- ISO-Woche, z. B. 2026-W43
	sent_at DATETIME NOT NULL,
	ok TINYINT(1) NOT NULL DEFAULT 1,   -- 1 gesendet, 0 Fehler (bis zu 3 Versuche), 2 ohne Dienste (keine Mail)
	error VARCHAR(255) NOT NULL DEFAULT '',
	tries TINYINT NOT NULL DEFAULT 1,
	PRIMARY KEY (userid, week),
	KEY week (week)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
