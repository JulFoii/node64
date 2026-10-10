-- Zwei-Faktor-Anmeldung und API-Keys

ALTER TABLE sessions ADD COLUMN totp_ok INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN totp_recovery TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS api_keys (
	id           INTEGER PRIMARY KEY,
	user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	name         TEXT NOT NULL,
	key_hash     TEXT NOT NULL UNIQUE,
	key_hint     TEXT NOT NULL DEFAULT '',
	created_at   TEXT NOT NULL,
	last_used_at TEXT NOT NULL DEFAULT ''
);
