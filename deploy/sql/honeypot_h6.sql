-- Honeypot64 bei ipv64, Phase H6 (Teil ipv64): Passwortpruefung mit k-Anonymitaet, Aenderungs-Feed der v64 Blocklist,
-- Fingerabdruecke (JA4/HASSH). Hauptdatenbank ipv64, MariaDB 10.5+. Mehrfach ausfuehrbar (IF NOT EXISTS), aendert keine
-- bestehende Tabelle. Voraussetzung: honeypot.sql (H2), honeypot_h3_scoring.sql (hp_scores), honeypot_h4_stats.sql
-- (hp_sample_contrib). Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 7, 8, 12, 14). Alle Zeiten UTC.
--
-- Reihenfolge beim Einspielen: ERST diese Datei, DANN die PHP-Dateien (api_v2_honeypot.php schreibt hp_samples_fps in
-- derselben Transaktion wie die Proben, sobald ein Sensor Fingerabdruecke meldet).

-- Passwortpruefung (GET /threat/passwords/range/{prefix}, Seite honeypot/password.php). Gepflegt von
-- bots/honeypot_passwords.php (Job pwrange in bots/honeypot_cron.php, alle 6 Stunden).
--   sha1     SHA-1 des Passworts (20 Byte); Abfrage als Bereich ueber die ersten 5 Hex-Zeichen
--   cnt      Summe der Proben der letzten 365 Tage
--   updated  letzter Lauf, in dem die Mehrfach-Account-Schwelle erfuellt war (nach 365 Tagen ohne: geloescht)
CREATE TABLE IF NOT EXISTS `hp_pw_range` (
  `sha1` binary(20) NOT NULL,
  `cnt` bigint(20) unsigned NOT NULL DEFAULT 0,
  `updated` datetime NOT NULL,
  PRIMARY KEY (`sha1`),
  KEY `updated` (`updated`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

-- Aenderungs-Feed (GET /threat/feed). Geschrieben von bots/blocklist/honeypot_score.php in derselben Transaktion wie
-- hp_scores (alle 30 Minuten), aelteste zuerst nach id; Frist 30 Tage (loescht ebenfalls honeypot_score.php).
--   action      add (neu gelistet), remove (nicht mehr gelistet), update (andere Listen)
--   lists       Listen danach (Komma: v64,ssh,web,mail,rdp,scanner,research), leer bei remove
--   prev_lists  Listen davor, leer bei add
CREATE TABLE IF NOT EXISTS `hp_list_changes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime NOT NULL,
  `action` varchar(8) CHARACTER SET ascii NOT NULL,
  `ip` varchar(45) CHARACTER SET ascii NOT NULL,
  `lists` varchar(64) CHARACTER SET ascii NOT NULL DEFAULT '',
  `prev_lists` varchar(64) CHARACTER SET ascii NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Fingerabdruecke der Werkzeuge (samples.fingerprints der Meldung): "ja4:<ja4>" (TLS ClientHello) bzw. "hassh:<md5>"
-- (SSH-KEXINIT des Clients), als laufende Summen je Tag wie hp_samples_paths. key_hash = SHA-256 ueber fp.
-- Beitrag je Account in hp_sample_contrib mit kind = 'fp' (Rangliste ab N Accounts, honeypot/hp_stats_lib.php).
CREATE TABLE IF NOT EXISTS `hp_samples_fps` (
  `day` date NOT NULL,
  `key_hash` binary(32) NOT NULL,
  `fp` varchar(80) CHARACTER SET ascii NOT NULL,
  `count` bigint(20) unsigned NOT NULL DEFAULT 0,
  `last_seen` datetime NOT NULL,
  PRIMARY KEY (`day`, `key_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
