-- CDN64 online (Tunnel zu srv07/srv08.cdn64.de), Phase T3. Hauptdatenbank ipv64, MariaDB 10.5+.
-- Eigene Tabellen mit Praefix cdn64o_, getrennt vom alten CDN (cdn_domains, cdn_server, ...).
-- Planung: docs/CDN64-ONLINE.md, Abschnitt 8. Mehrfach ausfuehrbar (IF NOT EXISTS).

-- Server (srv07/srv08); das Geheimnis kennt nur der Server, hier steht sein SHA-256.
CREATE TABLE IF NOT EXISTS `cdn64o_edges` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(32) NOT NULL,
  `hostname` varchar(253) NOT NULL,
  `ipv4` varchar(45) NOT NULL DEFAULT '',
  `ipv6` varchar(45) NOT NULL DEFAULT '',
  `tunnel_port` int(5) NOT NULL DEFAULT 7844,
  `secret_hash` char(64) NOT NULL,
  `disabled` tinyint(1) NOT NULL DEFAULT 0,
  `last_seen` datetime DEFAULT NULL,
  `version` varchar(32) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Tunnel je Node (Token nur als SHA-256).
CREATE TABLE IF NOT EXISTS `cdn64o_tunnels` (
  `id` varchar(24) NOT NULL,
  `userid` int(11) NOT NULL,
  `node_id` varchar(64) NOT NULL DEFAULT '',
  `name` varchar(100) NOT NULL DEFAULT '',
  `token_hash` char(64) NOT NULL,
  `status` varchar(16) NOT NULL DEFAULT 'active',
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_seen` datetime DEFAULT NULL,
  `last_edge` varchar(32) NOT NULL DEFAULT '',
  `node_version` varchar(32) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `userid` (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Namen hinter CDN64 online (mode 1 durchreichen, 2 terminieren, 3 direkt zum Ziel).
CREATE TABLE IF NOT EXISTS `cdn64o_hosts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userid` int(11) NOT NULL,
  `fqdn` varchar(253) NOT NULL,
  `subdomain_id` int(11) NOT NULL,
  `praefix` varchar(255) NOT NULL DEFAULT '',
  `wildcard` tinyint(1) NOT NULL DEFAULT 0,
  `mode` tinyint(1) NOT NULL DEFAULT 1,
  `status` varchar(16) NOT NULL DEFAULT 'pending',
  `blocked_reason` varchar(32) NOT NULL DEFAULT '',
  `error` varchar(255) NOT NULL DEFAULT '',
  `created_via` varchar(8) NOT NULL DEFAULT 'node',
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `fqdn` (`fqdn`),
  KEY `userid` (`userid`),
  KEY `subdomain_id` (`subdomain_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Welche Tunnels einen Host bedienen (mehrere Nodes je Host moeglich, G3).
CREATE TABLE IF NOT EXISTS `cdn64o_host_tunnels` (
  `host_id` int(11) NOT NULL,
  `tunnel_id` varchar(24) NOT NULL,
  `priority` int(5) NOT NULL DEFAULT 0,
  PRIMARY KEY (`host_id`, `tunnel_id`),
  KEY `tunnel_id` (`tunnel_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- DNS-Umstellung: angelegte Server-Eintraege (role=edge, in subdomain_records mit cdn_tmp=3) und deaktivierte
-- Originale (role=original). Statt der Spalten cdn_token/cdn_status des alten CDN.
CREATE TABLE IF NOT EXISTS `cdn64o_records` (
  `host_id` int(11) NOT NULL,
  `record_id` int(11) NOT NULL,
  `role` varchar(12) NOT NULL,
  PRIMARY KEY (`host_id`, `record_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Traffic je Host und Tag (alle Modi; gemeldet von den Servern).
CREATE TABLE IF NOT EXISTS `cdn64o_traffic` (
  `host_id` int(11) NOT NULL,
  `userid` int(11) NOT NULL,
  `day` date NOT NULL,
  `bytes_in` bigint(20) NOT NULL DEFAULT 0,
  `bytes_out` bigint(20) NOT NULL DEFAULT 0,
  `conns` bigint(20) NOT NULL DEFAULT 0,
  `rejected` bigint(20) NOT NULL DEFAULT 0,
  PRIMARY KEY (`host_id`, `day`),
  KEY `userid_day` (`userid`, `day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Verlauf je Host (Anzeige, Support).
CREATE TABLE IF NOT EXISTS `cdn64o_events` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `host_id` int(11) NOT NULL DEFAULT 0,
  `userid` int(11) NOT NULL,
  `time` datetime NOT NULL DEFAULT current_timestamp(),
  `kind` varchar(32) NOT NULL,
  `message` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `host_id` (`host_id`),
  KEY `userid_time` (`userid`, `time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Bandbreiten-Limit je Klasse in Mbit/s (0 = frei). Supporter-Wert setzt Dennis.
ALTER TABLE `user_class` ADD COLUMN IF NOT EXISTS `cdn_bandwidth` int(11) NOT NULL DEFAULT 0 AFTER `cdn_traffic`;

-- Die beiden Server. secret_hash = SHA-256 (hex) des Geheimnisses aus /etc/cdn64-edge/config.yaml (api_secret).
INSERT INTO `cdn64o_edges` (`name`, `hostname`, `ipv4`, `ipv6`, `secret_hash`) VALUES
  ('srv07', 'srv07.cdn64.de', '91.99.98.96', '2a01:4f8:1c18:5887::1', 'b179930abfcbe583cb403d76587d361f828b1217385a6d652c2c87c00c7d6a69'),
  ('srv08', 'srv08.cdn64.de', '2.28.6.30', '2a01:4f8:c015:bca8::1', 'd1161cfa69ef92a03d9a4c47bd9d01c8b31c13dcb402ea23aec6ea6ff32de877')
  ON DUPLICATE KEY UPDATE `hostname` = VALUES(`hostname`), `ipv4` = VALUES(`ipv4`), `ipv6` = VALUES(`ipv6`), `secret_hash` = VALUES(`secret_hash`);

-- T5 (Modus 2): Zertifikate der Server je Name, verschluesselt (AES-256-GCM, Schluessel nur auf den Servern).
CREATE TABLE IF NOT EXISTS `cdn64o_certs` (
  `fqdn` varchar(253) NOT NULL,
  `blob` mediumtext NOT NULL,
  `not_after` datetime NOT NULL,
  `edge` varchar(32) NOT NULL DEFAULT '',
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`fqdn`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- T6: Anfragen je Host und Tag (Modus 2; in Modus 1 sieht der Server nur Verbindungen).
ALTER TABLE `cdn64o_traffic` ADD COLUMN IF NOT EXISTS `requests` bigint(20) NOT NULL DEFAULT 0 AFTER `conns`;

-- T6 (G6): ausgefallenen Server aus dem DNS nehmen. withdrawn = seine A/AAAA sind gerade aus allen CDN64-Namen
-- entfernt; back_since = seit wann er nach einem Ausfall wieder da ist (Wiedereintrag nach 30 s).
ALTER TABLE `cdn64o_edges` ADD COLUMN IF NOT EXISTS `withdrawn` tinyint(1) NOT NULL DEFAULT 0 AFTER `disabled`;
ALTER TABLE `cdn64o_edges` ADD COLUMN IF NOT EXISTS `back_since` datetime DEFAULT NULL AFTER `withdrawn`;
