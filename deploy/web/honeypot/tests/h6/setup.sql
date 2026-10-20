-- Testumgebung Honeypot64 H6 (hp6i-*): Anmeldung (API v2), Tabellen, die die Bewertung liest. Nicht auf ipv64 einspielen.
CREATE TABLE users (id int NOT NULL PRIMARY KEY, email varchar(255) NOT NULL DEFAULT '', password char(60) NOT NULL DEFAULT '',
  reg_date datetime NOT NULL, account_status varchar(2) NOT NULL DEFAULT '1', user_class int NOT NULL DEFAULT 1, admin int NOT NULL DEFAULT 0,
  moderator int NOT NULL DEFAULT 0, class_valid_until datetime NOT NULL DEFAULT current_timestamp(), apikey varchar(100) NOT NULL DEFAULT '0');
CREATE TABLE user_class (id int NOT NULL PRIMARY KEY, name varchar(100) NOT NULL);
CREATE TABLE api_keys (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, userid int NOT NULL, token varchar(64) NOT NULL, name varchar(100) NOT NULL DEFAULT '',
  expire varchar(16) NOT NULL DEFAULT '0', used int NOT NULL DEFAULT 0);
CREATE TABLE account_links (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, owner_id int, manager_id int, status int);
CREATE TABLE subdomain_records (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, subdomain_id int NOT NULL DEFAULT 0, userid int NOT NULL, praefix varchar(255) NOT NULL DEFAULT '',
  domainname varchar(255) NOT NULL, content text NOT NULL, ttl int NOT NULL DEFAULT 60, type varchar(255) NOT NULL, deactivated int NOT NULL DEFAULT 0,
  cdn_tmp int NOT NULL DEFAULT 0, KEY userid (userid), KEY type (type));
CREATE TABLE vpn_public_ips (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, userid int NOT NULL, router_id int NOT NULL DEFAULT 0, vpn_server int NOT NULL DEFAULT 0,
  ip varchar(64) NOT NULL, type varchar(8) NOT NULL DEFAULT 'ipv6', deleted int(2) NOT NULL DEFAULT 0);
CREATE TABLE cdn_server (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(200) NOT NULL, hostname varchar(100) NOT NULL, ipv4 varchar(20) NOT NULL, ipv6 varchar(128) NOT NULL);
CREATE TABLE vpn_gw_server (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(200) NOT NULL, hostname varchar(100) NOT NULL, ipv4 varchar(20) NOT NULL, ipv6 varchar(128) NOT NULL);
CREATE TABLE dns64_server (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(128) NOT NULL, ipv4 varchar(32) NOT NULL, ipv6 varchar(64) NOT NULL);
CREATE TABLE bl_cloudflare (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, ip varchar(200) NOT NULL, timestamp datetime NOT NULL DEFAULT current_timestamp());
INSERT INTO bl_cloudflare (ip) VALUES ('104.16.0.0/13');
INSERT INTO user_class VALUES (1, 'Standard'), (2, 'VIP');
-- 1 Standard (meldet), 2 VIP (api_keys, meldet), 3 Standard inaktiv, 4 Standard (meldet), 5-7 Standard (Bewertung),
-- 8 Standard ohne Sensor, 9 VIP ohne Sensor
INSERT INTO users (id, email, reg_date, account_status, user_class, apikey) VALUES
  (1, 'u1@test.invalid', NOW() - INTERVAL 30 DAY, '1', 1, 'TestKeyAccountOne000000000000001'),
  (2, 'u2@test.invalid', NOW() - INTERVAL 30 DAY, '1', 2, '0'),
  (3, 'u3@test.invalid', NOW() - INTERVAL 30 DAY, '0', 1, 'TestKeyAccountThree0000000000003'),
  (4, 'u4@test.invalid', NOW() - INTERVAL 30 DAY, '1', 1, 'TestKeyAccountFour00000000000004'),
  (5, 'u5@test.invalid', NOW() - INTERVAL 30 DAY, '1', 1, '0'), (6, 'u6@test.invalid', NOW() - INTERVAL 30 DAY, '1', 1, '0'),
  (7, 'u7@test.invalid', NOW() - INTERVAL 30 DAY, '1', 1, '0'),
  (8, 'u8@test.invalid', NOW() - INTERVAL 30 DAY, '1', 1, 'TestKeyAccountEight0000000000008'),
  (9, 'u9@test.invalid', NOW() - INTERVAL 30 DAY, '1', 2, 'TestKeyAccountNine00000000000009');
INSERT INTO api_keys (userid, token, name) VALUES (2, 'TestKeyApiKeysTwo000000000000002', 'hp6i');
