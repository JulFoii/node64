-- Testumgebung Honeypot64 H3 Bewertung + Listen (hp3a-*). Nicht auf ipv64 einspielen.
-- Minimal-Tabellen aus dem Schema des Dumps (nur die benutzten Spalten) und Stubs fuer hp_allowlist/hp_release_requests
-- nach der Plan-Schnittstelle (die echten Tabellen legt der Teil Freigaben an: honeypot_h3_release.sql).
CREATE TABLE users (id int NOT NULL PRIMARY KEY, email varchar(255) NOT NULL DEFAULT '', password char(60) NOT NULL DEFAULT '',
  reg_date datetime NOT NULL, account_status int(10) NOT NULL DEFAULT 1, user_class int(10) NOT NULL DEFAULT 1, admin int(2) NOT NULL DEFAULT 0,
  class_valid_until datetime NOT NULL DEFAULT current_timestamp(), apikey varchar(100) NOT NULL DEFAULT '0');
CREATE TABLE user_class (id int(10) NOT NULL PRIMARY KEY, name varchar(100) NOT NULL);
INSERT INTO user_class VALUES (1, 'Standard'), (2, 'VIP'), (3, 'Premium');

CREATE TABLE subdomain_records (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, subdomain_id int NOT NULL DEFAULT 0, userid int NOT NULL, praefix varchar(255) NOT NULL DEFAULT '',
  domainname varchar(255) NOT NULL, content text NOT NULL, ttl int NOT NULL DEFAULT 60, type varchar(255) NOT NULL, deactivated int(2) NOT NULL DEFAULT 0, KEY type (type));
CREATE TABLE vpn_public_ips (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, userid int NOT NULL, router_id int NOT NULL DEFAULT 0, vpn_server int NOT NULL DEFAULT 0,
  ip varchar(64) NOT NULL, type varchar(8) NOT NULL DEFAULT 'ipv6', deleted int(2) NOT NULL DEFAULT 0);
CREATE TABLE cdn_server (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(200) NOT NULL, hostname varchar(100) NOT NULL, ipv4 varchar(20) NOT NULL, ipv6 varchar(128) NOT NULL);
CREATE TABLE vpn_gw_server (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(200) NOT NULL, hostname varchar(100) NOT NULL, ipv4 varchar(20) NOT NULL, ipv6 varchar(128) NOT NULL);
CREATE TABLE dns64_server (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(128) NOT NULL, ipv4 varchar(32) NOT NULL, ipv6 varchar(64) NOT NULL);

-- Blocklisten (Generator): eine kleine Quellliste fuer "all", Laender leer
CREATE TABLE blocklisten (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(50) NOT NULL, db_name varchar(50) NOT NULL, file_name varchar(30) NOT NULL,
  url varchar(255) NOT NULL DEFAULT '', last_updated datetime NOT NULL DEFAULT current_timestamp(), ips varchar(30) NOT NULL DEFAULT '0', disabled int NOT NULL DEFAULT 0,
  category varchar(16) NOT NULL DEFAULT 'attack', in_all tinyint NOT NULL DEFAULT 1, description varchar(255) NOT NULL DEFAULT '', source varchar(255) NOT NULL DEFAULT '', license varchar(100) NOT NULL DEFAULT '');
CREATE TABLE bl_test (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, ip varchar(200) NOT NULL);
CREATE TABLE bl_cloudflare (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, ip varchar(200) NOT NULL, timestamp datetime NOT NULL DEFAULT current_timestamp());
INSERT INTO blocklisten (name, db_name, file_name) VALUES ('Testliste', 'bl_test', 'testliste');
INSERT INTO bl_test (ip) VALUES ('5.6.7.8'), ('9.10.11.0/24');
INSERT INTO bl_cloudflare (ip) VALUES ('104.16.0.0/13'), ('2606:4700::/32');
CREATE TABLE blocklisten_countries (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, country varchar(4) NOT NULL, country_name varchar(64) NOT NULL, file_name varchar(64) NOT NULL,
  ips varchar(30) NOT NULL DEFAULT '0', last_updated datetime NOT NULL DEFAULT current_timestamp());
CREATE TABLE bl_countries_ips (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, country varchar(4) NOT NULL, ip varchar(200) NOT NULL);

-- Stub Teil Freigaben (Plan "H3 Umsetzung")
CREATE TABLE hp_allowlist (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, cidr varchar(64) NOT NULL, ip_start varbinary(16) NOT NULL, ip_end varbinary(16) NOT NULL,
  reason varchar(255) NOT NULL DEFAULT '', source varchar(16) NOT NULL DEFAULT 'manual', `until` datetime DEFAULT NULL, created_at datetime NOT NULL, created_by int DEFAULT NULL);
CREATE TABLE hp_release_requests (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, ip varchar(45) NOT NULL, ip_bin varbinary(16) NOT NULL, userid int DEFAULT NULL,
  email varchar(255) NOT NULL DEFAULT '', reason text NOT NULL, status varchar(16) NOT NULL DEFAULT 'open', created_at datetime NOT NULL, decided_at datetime DEFAULT NULL,
  protected_until datetime DEFAULT NULL, note text NOT NULL DEFAULT '');
