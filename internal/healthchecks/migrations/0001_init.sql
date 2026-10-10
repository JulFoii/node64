-- Modul Health-Checks. Zeiten als "2006-01-02T15:04:05.000Z" (UTC, feste Breite,
-- damit Zeichenkettenvergleiche der Zeitreihenfolge entsprechen).

CREATE TABLE IF NOT EXISTS hc_checks (
	token              TEXT PRIMARY KEY,
	type               TEXT NOT NULL,
	name               TEXT NOT NULL,
	target             TEXT NOT NULL DEFAULT '',
	params             TEXT NOT NULL DEFAULT '{}',
	interval_sec       INTEGER NOT NULL DEFAULT 60,
	retry_interval_sec INTEGER NOT NULL DEFAULT 20,
	retries            INTEGER NOT NULL DEFAULT 1,
	connect_timeout_ms INTEGER NOT NULL DEFAULT 5000,
	total_timeout_ms   INTEGER NOT NULL DEFAULT 10000,
	invert             INTEGER NOT NULL DEFAULT 0,
	stabilize          INTEGER NOT NULL DEFAULT 3,
	ip_mode            TEXT NOT NULL DEFAULT 'auto',
	tags               TEXT NOT NULL DEFAULT '',
	description        TEXT NOT NULL DEFAULT '',
	paused             INTEGER NOT NULL DEFAULT 0,
	parent_token       TEXT NOT NULL DEFAULT '',
	critical           INTEGER NOT NULL DEFAULT 0,
	execution          TEXT NOT NULL DEFAULT 'local',
	notify_down        INTEGER NOT NULL DEFAULT 1,
	notify_up          INTEGER NOT NULL DEFAULT 1,
	channels           TEXT NOT NULL DEFAULT '',
	repeat_minutes     INTEGER NOT NULL DEFAULT 0,
	revision           INTEGER NOT NULL DEFAULT 1,
	created_at         TEXT NOT NULL,
	updated_at         TEXT NOT NULL,
	updated_by         TEXT NOT NULL DEFAULT '',
	-- Laufzeitzustand (vom Scheduler gepflegt)
	state              TEXT NOT NULL DEFAULT 'pending',
	state_since        TEXT NOT NULL DEFAULT '',
	last_check_at      TEXT NOT NULL DEFAULT '',
	next_check_at      TEXT NOT NULL DEFAULT '',
	consecutive_fail   INTEGER NOT NULL DEFAULT 0,
	consecutive_ok     INTEGER NOT NULL DEFAULT 0,
	last_status        TEXT NOT NULL DEFAULT '',
	last_latency_ms    REAL NOT NULL DEFAULT 0,
	last_reason        TEXT NOT NULL DEFAULT '',
	last_message       TEXT NOT NULL DEFAULT '',
	last_push_at       TEXT NOT NULL DEFAULT '',
	down_since         TEXT NOT NULL DEFAULT '',
	flap_since         TEXT NOT NULL DEFAULT '',
	transitions        TEXT NOT NULL DEFAULT '',
	incident_id        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hc_checks_parent ON hc_checks(parent_token);

-- Messpunkte, append-only. agent_seq ist die laufende Nummer fuer den
-- spaeteren Sync (idempotent je Agent).
CREATE TABLE IF NOT EXISTS hc_measurements (
	agent_seq   INTEGER PRIMARY KEY AUTOINCREMENT,
	token       TEXT NOT NULL,
	time        TEXT NOT NULL,
	status      INTEGER NOT NULL,          -- 1 up, 0 down
	latency_ms  REAL NOT NULL DEFAULT 0,
	reason      TEXT NOT NULL DEFAULT '',
	message     TEXT NOT NULL DEFAULT '',
	family      TEXT NOT NULL DEFAULT '',
	details     TEXT NOT NULL DEFAULT '',
	flags       INTEGER NOT NULL DEFAULT 0 -- 1 Wartung, 2 abhaengig gestoert
);
CREATE INDEX IF NOT EXISTS idx_hc_measurements_token_time ON hc_measurements(token, time);
CREATE INDEX IF NOT EXISTS idx_hc_measurements_time ON hc_measurements(time);

-- Statuswechsel mit eindeutiger Ereignis-ID (gegen Doppelalarme beim Sync)
CREATE TABLE IF NOT EXISTS hc_events (
	id           INTEGER PRIMARY KEY,
	event_id     TEXT NOT NULL UNIQUE,
	token        TEXT NOT NULL,
	kind         TEXT NOT NULL,
	time         TEXT NOT NULL,
	from_state   TEXT NOT NULL DEFAULT '',
	to_state     TEXT NOT NULL DEFAULT '',
	reason       TEXT NOT NULL DEFAULT '',
	message      TEXT NOT NULL DEFAULT '',
	duration_sec INTEGER NOT NULL DEFAULT 0,
	flaps        INTEGER NOT NULL DEFAULT 0,
	flags        INTEGER NOT NULL DEFAULT 0, -- 1 Wartung, 2 stumm
	incident_id  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hc_events_token_time ON hc_events(token, time);
CREATE INDEX IF NOT EXISTS idx_hc_events_time ON hc_events(time);

-- Stoerungen: Beginn bis Ende einer Down-Phase
CREATE TABLE IF NOT EXISTS hc_incidents (
	id         INTEGER PRIMARY KEY,
	token      TEXT NOT NULL,
	started_at TEXT NOT NULL,
	ended_at   TEXT NOT NULL DEFAULT '',
	reason     TEXT NOT NULL DEFAULT '',
	message    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hc_incidents_token ON hc_incidents(token, started_at);

-- Verdichtung: Stundenwerte (1 Jahr) und Tageswerte (unbegrenzt)
CREATE TABLE IF NOT EXISTS hc_hourly (
	token    TEXT NOT NULL,
	hour     TEXT NOT NULL,   -- Stundenbeginn UTC
	count    INTEGER NOT NULL,
	up_count INTEGER NOT NULL,
	min_ms   REAL NOT NULL,
	avg_ms   REAL NOT NULL,
	max_ms   REAL NOT NULL,
	PRIMARY KEY (token, hour)
);
CREATE TABLE IF NOT EXISTS hc_daily (
	token    TEXT NOT NULL,
	day      TEXT NOT NULL,    -- YYYY-MM-DD UTC
	count    INTEGER NOT NULL,
	up_count INTEGER NOT NULL,
	min_ms   REAL NOT NULL,
	avg_ms   REAL NOT NULL,
	max_ms   REAL NOT NULL,
	PRIMARY KEY (token, day)
);

-- Wartungsfenster: einmalig oder wiederkehrend
CREATE TABLE IF NOT EXISTS hc_maintenance (
	id           INTEGER PRIMARY KEY,
	name         TEXT NOT NULL,
	start_at     TEXT NOT NULL,
	end_at       TEXT NOT NULL,
	repeat       TEXT NOT NULL DEFAULT 'none', -- none, daily, weekly, monthly
	repeat_until TEXT NOT NULL DEFAULT '',
	tokens       TEXT NOT NULL DEFAULT '',     -- Komma-Liste, leer = alle Checks
	active       INTEGER NOT NULL DEFAULT 1,
	created_at   TEXT NOT NULL
);

-- Outbox fuer den spaeteren Sync (vorbereitet, im Entwurf ungenutzt)
CREATE TABLE IF NOT EXISTS hc_outbox (
	id         INTEGER PRIMARY KEY,
	kind       TEXT NOT NULL,
	payload    TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hc_tombstones (
	token      TEXT PRIMARY KEY,
	revision   INTEGER NOT NULL,
	deleted_at TEXT NOT NULL
);
