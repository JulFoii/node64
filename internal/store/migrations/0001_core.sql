-- Kern des Agents: Einstellungen, Benutzer, Sitzungen, Module, Audit-Log.
-- Zeiten als RFC 3339 in UTC.

CREATE TABLE IF NOT EXISTS settings (
	key        TEXT PRIMARY KEY,
	value      TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY,
	username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	totp_secret   TEXT NOT NULL DEFAULT '',
	lang          TEXT NOT NULL DEFAULT '',
	timezone      TEXT NOT NULL DEFAULT '',
	created_at    TEXT NOT NULL,
	last_login_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sessions (
	id           TEXT PRIMARY KEY,
	user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf         TEXT NOT NULL,
	created_at   TEXT NOT NULL,
	last_seen_at TEXT NOT NULL,
	expires_at   TEXT NOT NULL,
	ip           TEXT NOT NULL DEFAULT '',
	user_agent   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS modules (
	name       TEXT PRIMARY KEY,
	enabled    INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
	id      INTEGER PRIMARY KEY,
	time    TEXT NOT NULL,
	actor   TEXT NOT NULL,
	action  TEXT NOT NULL,
	target  TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT '',
	ip      TEXT NOT NULL DEFAULT '',
	origin  TEXT NOT NULL DEFAULT 'local'
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(time);
