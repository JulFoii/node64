-- Node64: eine Liste aller Nodes eines Accounts (nodes.php, API v2 POST /node64/hello und GET /node64/nodes in
-- api_v2_hc2.php). Hauptdatenbank ipv64, MariaDB 10.5+. Mehrfach ausfuehrbar (IF NOT EXISTS). Alle Zeiten UTC.
--
-- Eine Zeile je Container (node_id = Einstellung node.id; Modus ohne Oberflaeche: die Sensor-Kennung). Die Node meldet
-- sich mit dem API-Key beim Start, alle 15 Minuten und nach Aenderungen; jede andere Anfrage mit X-Node64-Node
-- frischt last_seen auf. Verknuepft mit hc2_nodes (Datenbank ipv64_hc, ueber hub_node_id), hp_sensors (sensor_id)
-- und cdn64o_tunnels (tunnel_id). removed_at gesetzt = auf ipv64.net entfernt: hello antwortet 403 node_removed.
CREATE TABLE IF NOT EXISTS `node64_nodes` (
  `userid` int(11) NOT NULL,
  `node_id` varchar(64) NOT NULL,
  `name` varchar(100) NOT NULL DEFAULT '',
  `location` varchar(100) NOT NULL DEFAULT '',
  `version` varchar(32) NOT NULL DEFAULT '',
  `os_arch` varchar(32) NOT NULL DEFAULT '',
  `mode` varchar(16) NOT NULL DEFAULT '' COMMENT 'headless = Modus ohne Oberflaeche',
  `modules` varchar(255) NOT NULL DEFAULT '' COMMENT 'laufende Module, kommagetrennt',
  `hc_linked` tinyint(1) NOT NULL DEFAULT 0,
  `hub_node_id` varchar(32) NOT NULL DEFAULT '' COMMENT 'hc2_nodes.node_id',
  `sensor_id` varchar(36) NOT NULL DEFAULT '' COMMENT 'hp_sensors.sensor_id',
  `tunnel_id` varchar(24) NOT NULL DEFAULT '' COMMENT 'cdn64o_tunnels.id',
  `dyndns` tinyint(1) NOT NULL DEFAULT 0,
  `api_key_id` int(11) DEFAULT NULL COMMENT 'api_keys.id der letzten Anmeldung (NULL = Account-Key)',
  `first_seen` datetime NOT NULL,
  `last_seen` datetime DEFAULT NULL COMMENT 'letzte Anfrage der Node (hello oder X-Node64-Node)',
  `last_hello` datetime DEFAULT NULL,
  `last_ip` varchar(45) NOT NULL DEFAULT '' COMMENT 'intern, nie ausgegeben',
  `removed_at` datetime DEFAULT NULL,
  `sensor_disabled` tinyint(1) NOT NULL DEFAULT 0 COMMENT '1 = hp_sensors.disabled beim Entfernen gesetzt (nur dann beim Zulassen wieder frei)',
  PRIMARY KEY (`userid`, `node_id`),
  KEY `hub_node_id` (`hub_node_id`),
  KEY `sensor_id` (`sensor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
