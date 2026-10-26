-- IPv64.net Admin-Bereich (admin.php): Protokoll aller Admin-Aktionen. Hauptdatenbank ipv64, MariaDB 10.5+.
-- Mehrfach ausfuehrbar (IF NOT EXISTS). Zeiten in UTC (UTC_TIMESTAMP()).
CREATE TABLE IF NOT EXISTS `admin_audit` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `created_at` datetime NOT NULL,
  `admin_id` int(11) NOT NULL,
  `target_id` int(11) NOT NULL DEFAULT 0,
  `action` varchar(50) NOT NULL,
  `details` varchar(1000) NOT NULL DEFAULT '',
  `ip` varchar(45) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `idx_admin_audit_target` (`target_id`, `id`),
  KEY `idx_admin_audit_time` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
