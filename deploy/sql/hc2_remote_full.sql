-- 2026-10-14: Fernverwaltung standardmaessig vollstaendig (Portal, API v2 und hub setzen den Wert ohnehin immer)
ALTER TABLE `hc2_nodes` ALTER `remote_mgmt` SET DEFAULT 'full';
