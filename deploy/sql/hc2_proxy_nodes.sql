-- 2026-10-15: Stellvertreter-Nodes. Ein nicht verknuepftes Mitglied einer lokalen Gruppe meldet seine Messwerte und
-- Zustaende ueber die weiterreichende Node der Gruppe (proxy_via = deren node_id). Solche Nodes haben keinen Token;
-- der hub zeigt ihre Daten nur an, die Gruppe benachrichtigt selbst.
ALTER TABLE hc2_nodes ADD COLUMN IF NOT EXISTS proxy_via VARCHAR(32) NULL DEFAULT NULL AFTER node;
ALTER TABLE hc2_nodes ADD INDEX IF NOT EXISTS proxy_via (proxy_via);
