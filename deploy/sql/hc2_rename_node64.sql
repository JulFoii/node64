-- Umbenennung Agent -> Node64 in der Datenbank ipv64_hc (einmalig; auf dem Produktivsystem am 2026-10-11 ausgefuehrt).
-- Reihenfolge: zuerst die hub-Instanzen-Tabelle freimachen, dann die Nodes (frueher Agents) umbenennen.
USE `ipv64_hc`;
RENAME TABLE `hc2_nodes` TO `hc2_hubs`;
RENAME TABLE `hc2_agents` TO `hc2_nodes`;
RENAME TABLE `hc2_agent_tokens` TO `hc2_node_tokens`;
ALTER TABLE `hc2_nodes` CHANGE `agent_id` `node_id` VARCHAR(32) NOT NULL;
ALTER TABLE `hc2_node_tokens` CHANGE `agent_id` `node_id` VARCHAR(32) NOT NULL;
ALTER TABLE `hc2_link_codes` CHANGE `agent_id` `node_id` VARCHAR(32) NOT NULL, CHANGE `agent_name` `node_name` VARCHAR(100) NOT NULL, CHANGE `agent_version` `node_version` VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE `hc2_checks` CHANGE `agent_id` `node_id` VARCHAR(32) NULL;
ALTER TABLE `hc2_measurements` CHANGE `agent_seq` `node_seq` BIGINT NOT NULL DEFAULT 0;
ALTER TABLE `hc2_channels` CHANGE `agent_id` `node_id` VARCHAR(32) NULL;
ALTER TABLE `hc2_deliveries` CHANGE `agent_id` `node_id` VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE `hc2_send_orders` CHANGE `agent_id` `node_id` VARCHAR(32) NOT NULL;
ALTER TABLE `hc2_commands` CHANGE `agent_id` `node_id` VARCHAR(32) NOT NULL;
ALTER TABLE `hc2_testruns` CHANGE `agent_id` `node_id` VARCHAR(32) NULL;
ALTER TABLE `hc2_maintenance` CHANGE `agent_id` `node_id` VARCHAR(32) NULL;
ALTER TABLE `hc2_config_log` CHANGE `agent_id` `node_id` VARCHAR(32) NULL,
  MODIFY `entity` ENUM('check','channel','maintenance','node','settings') NOT NULL;
UPDATE `hc2_config_log` SET `entity` = 'node' WHERE `entity` = 'agent';
INSERT IGNORE INTO `hc2_schema_version` (`version`, `applied_at`) VALUES (2, UTC_TIMESTAMP(3));
ALTER TABLE `hc2_config_log` MODIFY `origin` ENUM('portal','api','node','system') NOT NULL;
UPDATE `hc2_config_log` SET `origin` = 'node' WHERE `origin` = 'agent';
