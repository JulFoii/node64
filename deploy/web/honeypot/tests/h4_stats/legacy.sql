-- Altbestand vor H4 (Proben ohne Account-Bezug, gestern), wird von honeypot_h4_stats.sql als Account 0 uebernommen.
INSERT INTO hp_samples_creds (day, key_hash, service, username, password, pass_sha1, `count`, last_seen) VALUES
  (UTC_DATE() - INTERVAL 1 DAY, UNHEX(SHA2(CONCAT('ssh', CHAR(0), 'legacyuser', CHAR(0), 'legacy-pass'), 256)), 'ssh', 'legacyuser', 'legacy-pass', SHA1('legacy-pass'), 50, UTC_TIMESTAMP()),
  (UTC_DATE() - INTERVAL 1 DAY, UNHEX(SHA2(CONCAT('ssh', CHAR(0), 'legacyuser', CHAR(0), 'legacy-only'), 256)), 'ssh', 'legacyuser', 'legacy-only', SHA1('legacy-only'), 70, UTC_TIMESTAMP()),
  (UTC_DATE() - INTERVAL 40 DAY, UNHEX(SHA2(CONCAT('ssh', CHAR(0), 'old', CHAR(0), 'too-old'), 256)), 'ssh', 'old', 'too-old', SHA1('too-old'), 9, UTC_TIMESTAMP());
INSERT INTO hp_samples_paths (day, key_hash, path, `count`, last_seen) VALUES
  (UTC_DATE() - INTERVAL 1 DAY, UNHEX(SHA2('/legacy-path', 256)), '/legacy-path', 4, UTC_TIMESTAMP());
INSERT INTO hp_samples_uas (day, key_hash, user_agent, `count`, last_seen) VALUES
  (UTC_DATE() - INTERVAL 1 DAY, UNHEX(SHA2('legacy-agent/1.0', 256)), 'legacy-agent/1.0', 3, UTC_TIMESTAMP());
INSERT INTO hp_samples_payloads (day, sha256, service, port, head_b64, `count`, last_seen) VALUES
  (UTC_DATE() - INTERVAL 1 DAY, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'tcp', 23, '', 2, UTC_TIMESTAMP()),
  (UTC_DATE() - INTERVAL 1 DAY, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'tcp', 2323, '', 3, UTC_TIMESTAMP());
