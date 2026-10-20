-- Testumgebung Honeypot64 Herkunft (hp7g-*): Anmeldung (API v2), Tabellen, die die Bewertung liest. Nicht auf ipv64 einspielen.
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
INSERT INTO api_keys (userid, token, name) VALUES (2, 'TestKeyApiKeysTwo000000000000002', 'hp7g');

-- Blocklisten-Generator (Schema wie H4-Test) und Laenderdaten wie von read_countries_rir.php
CREATE TABLE blocklisten (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(50) NOT NULL, db_name varchar(50) NOT NULL, file_name varchar(30) NOT NULL,
  url varchar(255) NOT NULL DEFAULT '', last_updated datetime NOT NULL DEFAULT current_timestamp(), ips varchar(30) NOT NULL DEFAULT '0', disabled int NOT NULL DEFAULT 0,
  category varchar(16) NOT NULL DEFAULT 'attack', in_all tinyint NOT NULL DEFAULT 1, description varchar(255) NOT NULL DEFAULT '', source varchar(255) NOT NULL DEFAULT '', license varchar(100) NOT NULL DEFAULT '');
CREATE TABLE bl_test (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, ip varchar(200) NOT NULL);
INSERT INTO blocklisten (name, db_name, file_name) VALUES ('Testliste', 'bl_test', 'testliste');
INSERT INTO bl_test (ip) VALUES ('5.6.7.8'), ('9.10.11.0/24');
CREATE TABLE blocklisten_countries (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, country varchar(4) NOT NULL, country_name varchar(64) NOT NULL, file_name varchar(64) NOT NULL,
  ips varchar(30) NOT NULL DEFAULT '0', last_updated datetime NOT NULL DEFAULT current_timestamp());
CREATE TABLE bl_countries_ips (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, country varchar(4) NOT NULL, country_name varchar(64) NOT NULL DEFAULT '', ip varchar(200) NOT NULL,
  typ varchar(2) NOT NULL DEFAULT '4', KEY country (country));
-- 'cn' klein wie im Altbestand aus global.json, 'X1' (kein gueltiger Code, faellt aus country_ranges heraus)
INSERT INTO blocklisten_countries (country, country_name, file_name) VALUES ('DE', 'Germany', 'DE'), ('NL', 'Netherlands', 'NL'), ('US', 'United States', 'US'),
  ('cn', 'China', 'CN'), ('X1', 'Test', 'X1');
-- kleiner RIR-Testdatensatz (so zerlegt read_countries_rir.php die Zuteilungen in CIDR):
--   ripencc|DE|ipv4|5.1.0.0|768 -> 5.1.0.0/23 + 5.1.2.0/24; ripencc|DE|ipv4|5.1.3.0|256; ripencc|NL|ipv4|5.1.4.0|1024; ripencc|DE|ipv4|5.1.8.0|256
--   arin|US|ipv4|8.0.0.0|16777216 (als zwei /9), apnic|CN|ipv4|1.0.1.0|768 -> 1.0.1.0/24 + 1.0.2.0/23
--   Ueberlappung: CN 8.8.8.0/24 liegt in US 8.0.0.0/8 (faellt raus), DE 10.0.0.0/8 nicht routbar (faellt raus)
--   ripencc|DE|ipv6|2001:678::|29 + ripencc|DE|ipv6|2001:680::|29 (benachbart), apnic|CN|ipv6|240e::|20, X1 1.2.3.0/24
INSERT INTO bl_countries_ips (country, country_name, ip, typ) VALUES
  ('DE', 'Germany', '5.1.0.0/23', '4'), ('DE', 'Germany', '5.1.2.0/24', '4'), ('DE', 'Germany', '5.1.3.0/24', '4'), ('NL', 'Netherlands', '5.1.4.0/22', '4'),
  ('DE', 'Germany', '5.1.8.0/24', '4'), ('US', 'United States', '8.0.0.0/9', '4'), ('US', 'United States', '8.128.0.0/9', '4'),
  ('CN', 'China', '1.0.1.0/24', '4'), ('CN', 'China', '1.0.2.0/23', '4'), ('CN', 'China', '8.8.8.0/24', '4'), ('DE', 'Germany', '10.0.0.0/8', '4'),
  ('DE', 'Germany', '2001:678::/29', '6'), ('DE', 'Germany', '2001:680::/29', '6'), ('CN', 'China', '240e::/20', '6'), ('X1', 'Test', '1.2.3.0/24', '4');
