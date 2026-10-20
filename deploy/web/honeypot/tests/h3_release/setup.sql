-- Testumgebung (hp3b-*): Anmeldung wie in H2, dazu users.admin, Stub hp_scores (Schnittstelle laut Plan, Teil Bewertung)
-- und eine Cloud-Liste (blocklisten.category = 'cloud'). Nicht auf ipv64 einspielen.
CREATE TABLE users (id int NOT NULL PRIMARY KEY, email varchar(255) NOT NULL DEFAULT '', apikey varchar(64) NOT NULL DEFAULT '0',
  account_status varchar(2) NOT NULL DEFAULT '1', user_class int NOT NULL DEFAULT 1, admin int NOT NULL DEFAULT 0, moderator int NOT NULL DEFAULT 0);
CREATE TABLE user_class (id int NOT NULL PRIMARY KEY, name varchar(32) NOT NULL);
CREATE TABLE api_keys (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, userid int NOT NULL, token varchar(64) NOT NULL, name varchar(100) NOT NULL DEFAULT '',
  expire varchar(16) NOT NULL DEFAULT '0', used int NOT NULL DEFAULT 0);
CREATE TABLE account_links (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, owner_id int, manager_id int, status int);
INSERT INTO user_class VALUES (1, 'Standard'), (2, 'VIP');
INSERT INTO users (id, email, apikey, user_class, admin) VALUES (1, 'a@test.invalid', 'TestKeyAccountOne000000000000001', 1, 0), (2, 'admin@test.invalid', '0', 2, 1), (3, 'c@test.invalid', '0', 1, 0);

CREATE TABLE hp_scores (
  ip_bin varbinary(16) NOT NULL PRIMARY KEY, ip varchar(45) NOT NULL, family tinyint NOT NULL, score tinyint unsigned NOT NULL DEFAULT 0,
  accounts int NOT NULL DEFAULT 0, sensors int NOT NULL DEFAULT 0, events bigint NOT NULL DEFAULT 0, kinds varchar(512) NOT NULL DEFAULT '',
  lists varchar(128) NOT NULL DEFAULT '', first_seen datetime NULL, last_seen datetime NULL, listed tinyint(1) NOT NULL DEFAULT 0,
  listed_since datetime NULL, reason varchar(32) NOT NULL DEFAULT '', updated_at datetime NULL);

CREATE TABLE blocklisten (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, name varchar(100) NOT NULL, db_name varchar(100) NOT NULL, file_name varchar(100) NOT NULL DEFAULT '',
  disabled int NOT NULL DEFAULT 0, category varchar(20) NOT NULL DEFAULT 'attack');
CREATE TABLE bl_aws (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, ip varchar(200) NOT NULL);
CREATE TABLE bl_spam (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, ip varchar(200) NOT NULL);
INSERT INTO blocklisten (name, db_name, file_name, category) VALUES ('Amazon AWS', 'bl_aws', 'aws', 'cloud'), ('Spam', 'bl_spam', 'spam', 'attack');
INSERT INTO bl_aws (ip) VALUES ('52.95.0.0/16'), ('2600:1f00::/24');
INSERT INTO bl_spam (ip) VALUES ('45.1.0.0/16');
