-- IPv64.net Blocklisten: neue Listen und Angaben fuer index.json
-- Einmal einspielen, BEVOR die neuen Dateien read_blocklists.php / create_blocklists_v2.php hochgeladen sind
-- (die alten Dateien ignorieren die neuen Spalten und Zeilen ohne passenden Leser).

-- 1. Neue Spalten
ALTER TABLE blocklisten
  ADD COLUMN category varchar(20) NOT NULL DEFAULT 'attack' COMMENT 'attack | botnet | tor | doh | cloud',
  ADD COLUMN in_all tinyint(1) NOT NULL DEFAULT 1 COMMENT '1 = Teil der Gesamtliste all (und all_notor, wenn nicht tor)',
  ADD COLUMN description varchar(255) NOT NULL DEFAULT '' COMMENT 'englisch, erscheint auf der Listenseite und in index.json',
  ADD COLUMN source varchar(255) NOT NULL DEFAULT '' COMMENT 'Projektseite der Quelle',
  ADD COLUMN license varchar(100) NOT NULL DEFAULT '';

-- 2. Bestehende Listen beschreiben (Inhalt und Gesamtliste bleiben wie bisher)
UPDATE blocklisten SET category = 'attack', description = 'Networks Spamhaus lists as controlled by criminals (DROP, IPv4 and IPv6)', source = 'https://www.spamhaus.org/blocklists/do-not-route-or-peer/', license = 'Spamhaus DROP terms' WHERE file_name = 'spamhaus_drop';
UPDATE blocklisten SET category = 'attack', description = 'FireHOL Level 1: curated collection with a low false positive risk', source = 'https://iplists.firehol.org/?ipset=firehol_level1', license = 'per source, see FireHOL' WHERE file_name = 'firehole_l1';
UPDATE blocklisten SET category = 'attack', description = 'DShield: the 20 most active attacking /24 networks', source = 'https://www.dshield.org/block.txt', license = 'CC BY-NC-SA 2.5' WHERE file_name = 'dshield1';
UPDATE blocklisten SET category = 'tor', description = 'Tor exit nodes (IPv4 and IPv6, from the Tor Project)', source = 'https://metrics.torproject.org/onionoo.html', license = 'CC0' WHERE file_name = 'tor_exit';
UPDATE blocklisten SET category = 'tor', description = 'All running Tor relays (IPv4 and IPv6, from the Tor Project)', source = 'https://metrics.torproject.org/onionoo.html', license = 'CC0' WHERE file_name = 'tor_all';
UPDATE blocklisten SET category = 'attack', description = 'blocklist.de: attackers on SSH, mail, web and other services in the last 48 hours', source = 'https://www.blocklist.de/', license = 'free to use (blocklist.de)' WHERE file_name = 'blocklistde_all';

-- 3. Neue Listen: je eine Quelltabelle wie die bestehenden
CREATE TABLE IF NOT EXISTS bl_feodo     (id int(11) NOT NULL AUTO_INCREMENT, ip varchar(200) NOT NULL, timestamp datetime NOT NULL DEFAULT current_timestamp(), PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS bl_et_comp   (id int(11) NOT NULL AUTO_INCREMENT, ip varchar(200) NOT NULL, timestamp datetime NOT NULL DEFAULT current_timestamp(), PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS bl_cins      (id int(11) NOT NULL AUTO_INCREMENT, ip varchar(200) NOT NULL, timestamp datetime NOT NULL DEFAULT current_timestamp(), PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS bl_ipsum3    (id int(11) NOT NULL AUTO_INCREMENT, ip varchar(200) NOT NULL, timestamp datetime NOT NULL DEFAULT current_timestamp(), PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS bl_doh       (id int(11) NOT NULL AUTO_INCREMENT, ip varchar(200) NOT NULL, timestamp datetime NOT NULL DEFAULT current_timestamp(), PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS bl_cloudflare (id int(11) NOT NULL AUTO_INCREMENT, ip varchar(200) NOT NULL, timestamp datetime NOT NULL DEFAULT current_timestamp(), PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS bl_aws       (id int(11) NOT NULL AUTO_INCREMENT, ip varchar(200) NOT NULL, timestamp datetime NOT NULL DEFAULT current_timestamp(), PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
CREATE TABLE IF NOT EXISTS bl_gcp       (id int(11) NOT NULL AUTO_INCREMENT, ip varchar(200) NOT NULL, timestamp datetime NOT NULL DEFAULT current_timestamp(), PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- url: mehrere Adressen durch Leerzeichen getrennt (werden zusammen gelesen)
INSERT INTO blocklisten (name, db_name, file_name, url, ips, disabled, category, in_all, description, source, license) VALUES
('abuse.ch Feodo Tracker', 'bl_feodo', 'feodo', 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt', '0', 0, 'botnet', 1, 'Botnet command and control servers (Emotet, Dridex, QakBot and others)', 'https://feodotracker.abuse.ch/blocklist/', 'CC0'),
('ET Compromised', 'bl_et_comp', 'et_compromised', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', '0', 0, 'attack', 1, 'Emerging Threats (Proofpoint): known compromised hosts', 'https://rules.emergingthreats.net/blockrules/', 'ET Open'),
('CINS Army', 'bl_cins', 'cins_army', 'https://cinsscore.com/list/ci-badguys.txt', '0', 0, 'attack', 0, 'CINS Army: addresses with a poor reputation from the Sentinel IPS network (up to 15,000)', 'https://cinsscore.com/', 'free to use (CINS)'),
('IPsum Level 3', 'bl_ipsum3', 'ipsum_l3', 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt', '0', 0, 'attack', 0, 'IPsum: addresses found on at least 3 public blocklists', 'https://github.com/stamparm/ipsum', 'Unlicense'),
('DoH Server', 'bl_doh', 'doh_servers', 'https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt', '0', 0, 'doh', 0, 'Public DNS over HTTPS servers: block outgoing so devices cannot bypass your own DNS', 'https://github.com/dibdot/DoH-IP-blocklists', 'GPL-3.0'),
('Cloudflare', 'bl_cloudflare', 'cloudflare', 'https://www.cloudflare.com/ips-v4 https://www.cloudflare.com/ips-v6', '0', 0, 'cloud', 0, 'Cloudflare networks: allow only these when a server should be reachable through Cloudflare only', 'https://www.cloudflare.com/ips/', 'published by the provider'),
('Amazon AWS', 'bl_aws', 'aws', 'https://ip-ranges.amazonaws.com/ip-ranges.json', '0', 0, 'cloud', 0, 'All Amazon AWS networks (data centers, many scanners and bots)', 'https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html', 'published by the provider'),
('Google Cloud', 'bl_gcp', 'gcp', 'https://www.gstatic.com/ipranges/cloud.json', '0', 0, 'cloud', 0, 'Google Cloud customer networks (without Google services)', 'https://cloud.google.com/compute/docs/faq#find_ip_range', 'published by the provider');
