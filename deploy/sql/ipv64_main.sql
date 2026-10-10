-- Aenderungen an der HAUPTDATENBANK ipv64 (Phase 1, S2). Idempotent.
-- 1) Flags je Account, 2) Online-Standorte je Klasse, 3) Sicht fuer den hub ohne Passwort-Hashes,
-- 4) Leserechte fuer den hub-Benutzer ipv64_hc (nur Sicht, user_class, healthchecks).
-- Host-Teil des Benutzers ggf. anpassen (privates Netz der hub-Server: 10.10.0.10 und 10.10.0.11).

USE `ipv64`;

ALTER TABLE `users`
  ADD COLUMN IF NOT EXISTS `hc2` TINYINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS `hc2_shadow` TINYINT NOT NULL DEFAULT 0;

ALTER TABLE `user_class`
  ADD COLUMN IF NOT EXISTS `hc_locations` TINYINT NOT NULL DEFAULT 1;
UPDATE `user_class` SET `hc_locations` = 2 WHERE `id` IN (2,3,4,5,6) AND `hc_locations` = 1;

-- Sicht fuer den hub: id, email (fuer ipv64_mail), Klasse, Flags, Limits. Keine Passwort-Hashes.
CREATE OR REPLACE SQL SECURITY DEFINER VIEW `hc2_users_v` AS
  SELECT u.`id`, u.`email`, u.`user_class`, u.`hc2`, u.`hc2_shadow`,
         c.`healthcheck_limit`, c.`hc_locations`, c.`sms_limit`
  FROM `users` u JOIN `user_class` c ON c.`id` = u.`user_class`;

-- Leserechte fuer den hub (Benutzer existiert bereits fuer die neue Datenbank; Host wie dort angelegt)
GRANT SELECT ON `ipv64`.`hc2_users_v` TO 'ipv64_hc'@'10.10.0.10';
GRANT SELECT ON `ipv64`.`hc2_users_v` TO 'ipv64_hc'@'10.10.0.11';
GRANT SELECT ON `ipv64`.`user_class`  TO 'ipv64_hc'@'10.10.0.10';
GRANT SELECT ON `ipv64`.`user_class`  TO 'ipv64_hc'@'10.10.0.11';
GRANT SELECT ON `ipv64`.`healthchecks` TO 'ipv64_hc'@'10.10.0.10';   -- nur fuer den Vergleichsbot (Phase 5)
GRANT SELECT ON `ipv64`.`healthchecks` TO 'ipv64_hc'@'10.10.0.11';
FLUSH PRIVILEGES;

-- Ausserdem braucht der PORTAL-Benutzer (der aus dbconnect.php) volle Rechte auf die neue Datenbank:
--   GRANT SELECT, INSERT, UPDATE, DELETE ON `<neue db>`.* TO '<portal-user>'@'<host>';
-- Das Portal spricht die neuen Tabellen dann als `<neue db>`.`hc2_checks` usw. an (gleicher Server).
