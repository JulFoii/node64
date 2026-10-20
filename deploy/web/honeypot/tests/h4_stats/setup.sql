-- Testumgebung Honeypot64 H4 Statistik + Listen (hp4a-*). Nicht auf ipv64 einspielen.
-- Anmeldung wie in H2/H3 (nur benutzte Spalten aus dem Schema des Dumps), Blocklisten-Generator wie in H3.
CREATE TABLE users (id int NOT NULL PRIMARY KEY, email varchar(255) NOT NULL DEFAULT '', password char(60) NOT NULL DEFAULT '',
  reg_date datetime NOT NULL DEFAULT '2026-01-01 00:00:00', account_status int(10) NOT NULL DEFAULT 1, user_class int(10) NOT NULL DEFAULT 1,
  admin int(2) NOT NULL DEFAULT 0, moderator int NOT NULL DEFAULT 0, class_valid_until datetime NOT NULL DEFAULT current_timestamp(), apikey varchar(100) NOT NULL DEFAULT '0');
CREATE TABLE user_class (id int(10) NOT NULL PRIMARY KEY, name varchar(100) NOT NULL);
CREATE TABLE api_keys (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, userid int NOT NULL, token varchar(64) NOT NULL, name varchar(100) NOT NULL DEFAULT '',
  expire varchar(16) NOT NULL DEFAULT '0', used int NOT NULL DEFAULT 0);
CREATE TABLE account_links (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, owner_id int, manager_id int, status int);
INSERT INTO user_class VALUES (1, 'Standard'), (2, 'VIP');

CREATE TABLE blocklisten (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(50) NOT NULL, db_name varchar(50) NOT NULL, file_name varchar(30) NOT NULL,
  url varchar(255) NOT NULL DEFAULT '', last_updated datetime NOT NULL DEFAULT current_timestamp(), ips varchar(30) NOT NULL DEFAULT '0', disabled int NOT NULL DEFAULT 0,
  category varchar(16) NOT NULL DEFAULT 'attack', in_all tinyint NOT NULL DEFAULT 1, description varchar(255) NOT NULL DEFAULT '', source varchar(255) NOT NULL DEFAULT '', license varchar(100) NOT NULL DEFAULT '');
CREATE TABLE bl_test (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, ip varchar(200) NOT NULL);
INSERT INTO blocklisten (name, db_name, file_name) VALUES ('Testliste', 'bl_test', 'testliste');
INSERT INTO bl_test (ip) VALUES ('5.6.7.8'), ('9.10.11.0/24');
CREATE TABLE blocklisten_countries (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, country varchar(4) NOT NULL, country_name varchar(64) NOT NULL, file_name varchar(64) NOT NULL,
  ips varchar(30) NOT NULL DEFAULT '0', last_updated datetime NOT NULL DEFAULT current_timestamp());
CREATE TABLE bl_countries_ips (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, country varchar(4) NOT NULL, ip varchar(200) NOT NULL);
