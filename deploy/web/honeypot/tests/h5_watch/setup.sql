-- Testumgebung (hp5w-*): Anmeldung wie in H2/H3 und die Spalten von subdomain_records, die die Fruehwarnung liest
-- (Schema wie auf ipv64). Nicht auf ipv64 einspielen.
CREATE TABLE users (id int NOT NULL PRIMARY KEY, email varchar(255) NOT NULL DEFAULT '', apikey varchar(64) NOT NULL DEFAULT '0',
  account_status varchar(2) NOT NULL DEFAULT '1', user_class int NOT NULL DEFAULT 1, admin int NOT NULL DEFAULT 0, moderator int NOT NULL DEFAULT 0);
CREATE TABLE user_class (id int NOT NULL PRIMARY KEY, name varchar(32) NOT NULL);
CREATE TABLE api_keys (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, userid int NOT NULL, token varchar(64) NOT NULL, name varchar(100) NOT NULL DEFAULT '',
  expire varchar(16) NOT NULL DEFAULT '0', used int NOT NULL DEFAULT 0);
CREATE TABLE account_links (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, owner_id int, manager_id int, status int);
CREATE TABLE subdomain_records (
  id int NOT NULL AUTO_INCREMENT PRIMARY KEY, subdomain_id int NOT NULL DEFAULT 1, userid int NOT NULL, praefix varchar(255) NOT NULL DEFAULT '',
  domainname varchar(255) NOT NULL, content text NOT NULL, ttl int NOT NULL DEFAULT 60, type varchar(255) NOT NULL, deactivated int NOT NULL DEFAULT 0,
  cdn_tmp int NOT NULL DEFAULT 0, KEY userid (userid), KEY type (type));
INSERT INTO user_class VALUES (1, 'Standard'), (2, 'VIP');
-- 1 Standard (users.apikey), 2 VIP (api_keys), 3 Standard inaktiv, 4 Standard (fuer act-as nicht noetig), 5-8 geteilte DynDNS-IP
INSERT INTO users (id, email, apikey, account_status, user_class) VALUES
  (1, 'a@test.invalid', 'TestKeyAccountOne000000000000001', '1', 1), (2, 'b@test.invalid', '0', '1', 2), (3, 'c@test.invalid', 'TestKeyAccountThree0000000000003', '0', 1),
  (4, 'd@test.invalid', 'TestKeyAccountFour00000000000004', '1', 1), (5, 'e5@test.invalid', '0', '1', 1), (6, 'e6@test.invalid', '0', '1', 1),
  (7, 'e7@test.invalid', '0', '1', 1), (8, 'e8@test.invalid', '0', '1', 1);
INSERT INTO api_keys (userid, token, name) VALUES (2, 'TestKeyApiKeysTwo000000000000002', 'hp5w');
INSERT INTO subdomain_records (userid, praefix, domainname, content, type, deactivated, cdn_tmp) VALUES
  (1, '', 'home.ipv64.net', '45.9.9.9', 'A', 0, 0),
  (1, 'nas', 'home.ipv64.net', '2a0b:4d07:1::9', 'AAAA', 0, 0),
  (1, '', 'old.ipv64.net', '45.9.9.10', 'A', 1, 0),
  (1, 'cdn', 'home.ipv64.net', '45.9.9.11', 'A', 0, 1),
  (1, 'lan', 'home.ipv64.net', '192.168.1.5', 'A', 0, 0),
  (1, 'www', 'home.ipv64.net', 'home.ipv64.net', 'CNAME', 0, 0),
  (1, '', 'office.ipv64.net', ' 45.1.1.50 ', 'A', 0, 0),
  (2, '', 'b.ipv64.net', '45.9.9.20', 'A', 0, 0),
  (5, '', 'h5.ipv64.net', '47.7.7.7', 'A', 0, 0), (6, '', 'h6.ipv64.net', '47.7.7.7', 'A', 0, 0),
  (7, '', 'h7.ipv64.net', '47.7.7.7', 'A', 0, 0), (8, '', 'h8.ipv64.net', '47.7.7.7', 'A', 0, 0);
