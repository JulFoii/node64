-- 2026-10-12: mehrere messende Nodes je Check (node_id bleibt Besitzer: Bearbeiten, Benachrichtigung)
ALTER TABLE hc2_checks ADD COLUMN IF NOT EXISTS nodes VARCHAR(600) NOT NULL DEFAULT '' AFTER node_id;   -- messende Nodes, Komma-Liste
ALTER TABLE hc2_testruns ADD COLUMN IF NOT EXISTS nodes VARCHAR(600) NOT NULL DEFAULT '' AFTER node_id; -- Testlauf auf mehreren Nodes
UPDATE hc2_checks SET nodes = node_id WHERE nodes = '' AND node_id IS NOT NULL AND execution IN ('local','both') AND deleted_at IS NULL;
