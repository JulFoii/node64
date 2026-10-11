-- 2026-10-11: Gruppen fuer Checks und Index fuer den Zustands-Abgleich an die Nodes (bereits live eingespielt)
ALTER TABLE hc2_checks ADD COLUMN IF NOT EXISTS group_name VARCHAR(100) NOT NULL DEFAULT '' AFTER tags;
ALTER TABLE hc2_check_states ADD INDEX IF NOT EXISTS updated (updated_at);
