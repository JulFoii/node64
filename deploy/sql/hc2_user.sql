-- MySQL-Benutzer fuer die hub-Server (Phase 1, S2). Vor dem Ausfuehren HIER-EIN-LANGES-ZUFALLSPASSWORT
-- (4x) durch ein Passwort ersetzen, nie im Chat nennen. Datenbank: ipv64.
-- Rechte: nur hc2_*-Tabellen, lesend auf user_class, die Sicht hc2_users_v (keine Passwort-Hashes) und
-- healthchecks (Vergleichsbot Phase 5); ALTER auf hc2_measurements fuer die Partitionsrotation.
-- Zugriff nur von den vier hub-Adressen (v4 und v6), TLS erzwungen (REQUIRE SSL).
-- Idempotent: CREATE USER IF NOT EXISTS; GRANT ist ohnehin wiederholbar.

CREATE USER IF NOT EXISTS 'hc2'@'188.245.6.138' IDENTIFIED BY 'HIER-EIN-LANGES-ZUFALLSPASSWORT' REQUIRE SSL;
CREATE USER IF NOT EXISTS 'hc2'@'2a01:4f8:c014:46b::1' IDENTIFIED BY 'HIER-EIN-LANGES-ZUFALLSPASSWORT' REQUIRE SSL;
CREATE USER IF NOT EXISTS 'hc2'@'178.105.50.207' IDENTIFIED BY 'HIER-EIN-LANGES-ZUFALLSPASSWORT' REQUIRE SSL;
CREATE USER IF NOT EXISTS 'hc2'@'2a01:4f8:1c1f:b393::1' IDENTIFIED BY 'HIER-EIN-LANGES-ZUFALLSPASSWORT' REQUIRE SSL;

-- 188.245.6.138
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_locations` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_nodes` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_slot_leases` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_agents` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_agent_tokens` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_link_codes` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_checks` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_check_states` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_hourly` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_daily` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_dirty_hours` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_events` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_incidents` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_channels` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_deliveries` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_send_orders` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_commands` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_testruns` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_maintenance` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_settings` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_sms_counter` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_revisions` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_config_log` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_migration_log` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_compare_log` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_schema_version` TO 'hc2'@'188.245.6.138';
GRANT SELECT, INSERT, UPDATE, DELETE, ALTER ON `ipv64`.`hc2_measurements` TO 'hc2'@'188.245.6.138';
GRANT SELECT ON `ipv64`.`hc2_users_v` TO 'hc2'@'188.245.6.138';
GRANT SELECT ON `ipv64`.`user_class` TO 'hc2'@'188.245.6.138';
GRANT SELECT ON `ipv64`.`healthchecks` TO 'hc2'@'188.245.6.138';

-- 2a01:4f8:c014:46b::1
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_locations` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_nodes` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_slot_leases` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_agents` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_agent_tokens` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_link_codes` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_checks` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_check_states` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_hourly` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_daily` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_dirty_hours` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_events` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_incidents` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_channels` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_deliveries` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_send_orders` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_commands` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_testruns` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_maintenance` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_settings` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_sms_counter` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_revisions` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_config_log` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_migration_log` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_compare_log` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_schema_version` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT, INSERT, UPDATE, DELETE, ALTER ON `ipv64`.`hc2_measurements` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT ON `ipv64`.`hc2_users_v` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT ON `ipv64`.`user_class` TO 'hc2'@'2a01:4f8:c014:46b::1';
GRANT SELECT ON `ipv64`.`healthchecks` TO 'hc2'@'2a01:4f8:c014:46b::1';

-- 178.105.50.207
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_locations` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_nodes` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_slot_leases` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_agents` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_agent_tokens` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_link_codes` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_checks` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_check_states` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_hourly` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_daily` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_dirty_hours` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_events` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_incidents` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_channels` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_deliveries` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_send_orders` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_commands` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_testruns` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_maintenance` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_settings` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_sms_counter` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_revisions` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_config_log` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_migration_log` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_compare_log` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_schema_version` TO 'hc2'@'178.105.50.207';
GRANT SELECT, INSERT, UPDATE, DELETE, ALTER ON `ipv64`.`hc2_measurements` TO 'hc2'@'178.105.50.207';
GRANT SELECT ON `ipv64`.`hc2_users_v` TO 'hc2'@'178.105.50.207';
GRANT SELECT ON `ipv64`.`user_class` TO 'hc2'@'178.105.50.207';
GRANT SELECT ON `ipv64`.`healthchecks` TO 'hc2'@'178.105.50.207';

-- 2a01:4f8:1c1f:b393::1
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_locations` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_nodes` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_slot_leases` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_agents` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_agent_tokens` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_link_codes` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_checks` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_check_states` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_hourly` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_daily` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_dirty_hours` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_events` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_incidents` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_channels` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_deliveries` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_send_orders` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_commands` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_testruns` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_maintenance` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_settings` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_sms_counter` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_revisions` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_config_log` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_migration_log` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_compare_log` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE ON `ipv64`.`hc2_schema_version` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT, INSERT, UPDATE, DELETE, ALTER ON `ipv64`.`hc2_measurements` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT ON `ipv64`.`hc2_users_v` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT ON `ipv64`.`user_class` TO 'hc2'@'2a01:4f8:1c1f:b393::1';
GRANT SELECT ON `ipv64`.`healthchecks` TO 'hc2'@'2a01:4f8:1c1f:b393::1';

FLUSH PRIVILEGES;

-- Danach auf dem Web-Server: Port 3306 in der Firewall nur fuer die vier Adressen oben oeffnen,
-- MariaDB bind-address auf die oeffentliche Adresse (oder 0.0.0.0 und ::), TLS in my.cnf (ssl-cert/ssl-key/ssl-ca).
-- Pruefen: SHOW GRANTS FOR 'hc2'@'188.245.6.138';
