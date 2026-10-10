<?php
/**
 * Healthchecks 2.0: Migration eines Accounts aus den alten Tabellen (healthchecks, healthcheck_events,
 * healthcheck_incidents, integrations) in die neue Datenbank ipv64_hc (hc2_*).
 *
 * Nur per CLI:
 *   php hc2_migrate.php <userid|email> [--dry-run] [--activate]
 *   php hc2_migrate.php all [--class N] [--limit N] [--dry-run] [--activate]
 *
 * --dry-run   nur zaehlen und zeigen, nichts schreiben
 * --activate  am Ende users.hc2 = 1 setzen (sonst bleibt der Account im alten System)
 *
 * Idempotent: ein zweiter Lauf aendert nichts (Checks ueber token, Kanaele ueber legacy_integration_id,
 * Stoerungen ueber legacy_id, Messpunkte per INSERT IGNORE). Alte Tabellen werden nie veraendert.
 *
 * Geheimnisse der Kanaele werden wie im Agent verschluesselt (AES-256-GCM, "enc:v1:" + Base64 ohne Padding).
 * Schluessel: 32 Rohbytes in HC2_KEY_FILE (dieselbe Datei liegt auf den hub-Servern als secret.key).
 */

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

include("/var/www/clients/client1/web58/web/dbconnect.php");

const HC2DB        = HC2_DB;                                       // neue Datenbank, Verbindung ueber hc2_pdo() aus dbconnect.php
const RAW_DAYS     = 7;                                            // Rohdaten-Fenster wie im neuen System
const LOCATIONS    = array('nbg', 'fsn');
const PUSH_UNITS   = array(1 => 60, 2 => 3600, 3 => 86400);        // zeit2/grace2: 1=min, 2=h, 3=d
const ACTIVE_UNITS = array(0 => 1, 1 => 60, 2 => 3600);            // checkintervall2: 0=s, 1=min, 2=h

// ---------------------------------------------------------------- Argumente
$args = array_slice($argv, 1);
$who = null; $dry = false; $activate = false; $limit = 0; $class = 0;
for ($i = 0; $i < count($args); $i++) {
	$a = $args[$i];
	if ($a === '--dry-run') { $dry = true; }
	elseif ($a === '--activate') { $activate = true; }
	elseif ($a === '--limit') { $limit = (int)($args[++$i] ?? 0); }
	elseif ($a === '--class') { $class = (int)($args[++$i] ?? 0); }
	elseif ($who === null) { $who = $a; }
}
if ($who === null) {
	fwrite(STDERR, "Aufruf: php hc2_migrate.php <userid|email|all> [--dry-run] [--activate] [--limit N] [--class N]\n");
	exit(2);
}

// ---------------------------------------------------------------- Hilfen
function out(string $s): void { echo date('H:i:s') . ' ' . $s . "\n"; }
function dec($s): string { return htmlspecialchars_decode((string)$s, ENT_QUOTES); }
/** Europe/Berlin (alte Tabellen) -> UTC mit Millisekunden */
function utc($s): ?string {
	if ($s === null || $s === '' || $s === '0000-00-00 00:00:00') { return null; }
	$d = new DateTime($s, new DateTimeZone('Europe/Berlin'));
	$d->setTimezone(new DateTimeZone('UTC'));
	return $d->format('Y-m-d H:i:s.v');
}
function now_utc(): string { return gmdate('Y-m-d H:i:s') . '.000'; }
function slot(string $token): int { return crc32($token) % 1024; }

/** Verschluesselung kompatibel zum Agent (internal/secrets): enc:v1:<base64raw(nonce12 + ciphertext + tag16)> */
function hc2_key(): ?string {
	$key = is_file(HC2_KEY_FILE) ? file_get_contents(HC2_KEY_FILE) : null;
	if ($key !== null && strlen($key) !== 32) { throw new RuntimeException(HC2_KEY_FILE . ' muss genau 32 Bytes haben'); }
	return $key;
}
// hc2_encrypt() kommt aus dbconnect.php (hc2-Block)

/** Kanal-Konfiguration je Typ: Felder wie im Agent (internal/notify/channel.go); geheime Felder verschluesselt */
const SECRET_FIELDS = array('bot_token', 'webhook_url', 'token', 'password', 'app_token', 'user_key', 'headers', 'device_token');
function channel_config(string $type, array $o): array {
	$c = array();
	switch ($type) {
		case 'telegram':  $c = array('bot_token' => $o['apitoken'] ?? '', 'chat_id' => $o['chatid'] ?? ''); break;
		case 'gotify':    $c = array('server' => rtrim($o['serverurl'] ?? '', '/'), 'app_token' => $o['apptoken'] ?? '', 'priority' => (string)($o['priority'] ?? '5')); break;
		case 'ntfy':
			$u = (string)($o['serverurl'] ?? ''); $p = parse_url($u);
			$server = ($p['scheme'] ?? 'https') . '://' . ($p['host'] ?? '') . (isset($p['port']) ? ':' . $p['port'] : '');
			$topic = trim($p['path'] ?? '', '/');
			$c = array('server' => $server, 'topic' => $topic, 'priority_down' => (string)($o['downprio'] ?? '4'), 'priority_up' => (string)($o['upprio'] ?? '3')); break;
		case 'pushover':  $c = array('user_key' => $o['usertoken'] ?? '', 'app_token' => $o['apptoken'] ?? '', 'device' => $o['device'] ?? '', 'priority_down' => (string)($o['downprio'] ?? '0'), 'priority_up' => (string)($o['upprio'] ?? '0')); break;
		case 'discord':   $c = array('webhook_url' => $o['webhookurl'] ?? '', 'ping_user' => $o['pinguser'] ?? '', 'ping_group' => $o['pinggroup'] ?? ''); break;
		case 'webhook':   $c = array('url' => $o['webhookdown'] ?? ($o['webhookup'] ?? ''), 'url_up' => $o['webhookup'] ?? '', 'method' => 'POST'); break;
		case 'app':       $c = array('device_token' => $o['devicetoken'] ?? ''); break;
		case 'ipv64_mail': $c = array('email' => $o['email'] ?? ''); break;
		case 'ipv64_sms': $c = array('number' => $o['completenumber'] ?? (($o['countrycode'] ?? '') . ($o['number'] ?? ''))); break;
	}
	foreach ($c as $k => $v) {
		$c[$k] = dec($v);
		if (in_array($k, SECRET_FIELDS, true) && $c[$k] !== '') { $c[$k] = hc2_encrypt($c[$k]); }
	}
	return $c;
}
const TYPE_MAP = array('telegram' => 'telegram', 'gotify' => 'gotify', 'discord' => 'discord', 'ntfy' => 'ntfy', 'pushover' => 'pushover',
	'webhook' => 'webhook', 'mobil' => 'app', 'email' => 'ipv64_mail', 'sms' => 'ipv64_sms');
const CHECK_TYPE_MAP = array('health' => 'push', 'ping' => 'icmp', 'web' => 'http', 'tcp' => 'tcp', 'keyword' => 'keyword');
/** alt: 0 new / 1 up / 2 paused / 3 warning / 4 down / 5 stabilizing */
const STATE_MAP = array(0 => 'pending', 1 => 'up', 2 => 'paused', 3 => 'down', 4 => 'down', 5 => 'stabilizing');

function q(PDO $pdo, string $sql, array $p = array()): PDOStatement { $st = $pdo->prepare($sql); $st->execute($p); return $st; }
function one(PDO $pdo, string $sql, array $p = array()) { $r = q($pdo, $sql, $p)->fetch(PDO::FETCH_ASSOC); return $r === false ? null : $r; }

// ---------------------------------------------------------------- Migration eines Accounts
function migrate_user(PDO $pdo, array $user, bool $dry, bool $activate): void {
	$uid = (int)$user['id']; $db = HC2DB; $now = now_utc();
	$hc = hc2_pdo();   // schreibt nach ipv64_hc; $pdo liest nur die alten Tabellen
	$class = one($pdo, "SELECT * FROM user_class WHERE id = :c", array('c' => $user['user_class'])) ?: array('hc_locations' => 1, 'healthcheck_limit' => 0);
	$hcLocations = (int)($class['hc_locations'] ?? 1);
	$stats = array('channels' => 0, 'checks' => 0, 'states' => 0, 'measurements' => 0, 'daily' => 0, 'incidents' => 0);
	out("== Account $uid ({$user['email']}), Klasse {$user['user_class']}, Standorte je Check: $hcLocations" . ($dry ? ' [dry-run]' : ''));

	if (!$dry) { $hc->beginTransaction(); }
	try {
		// 1) Kanaele: Standardkanal "Account-E-Mail" (alt: integration "0") + alle Integrationen
		$channelByLegacy = array();
		$mailDefault = one($hc, "SELECT id FROM `$db`.hc2_channels WHERE userid = :u AND type = 'ipv64_mail' AND legacy_integration_id = 0", array('u' => $uid));
		if ($mailDefault === null) {
			if (!$dry) {
				q($hc, "INSERT INTO `$db`.hc2_channels (userid, type, name, config_enc, enabled, is_default, lang, verified, created_at, updated_at, legacy_integration_id)
					VALUES (:u, 'ipv64_mail', 'Account-E-Mail', :cfg, 1, 1, 'de', 1, :t, :t, 0)",
					array('u' => $uid, 'cfg' => json_encode(array('email' => $user['email'])), 't' => $now));
				$channelByLegacy[0] = (int)$hc->lastInsertId();
			}
			$stats['channels']++;
		} else { $channelByLegacy[0] = (int)$mailDefault['id']; }

		foreach (q($pdo, "SELECT * FROM integrations WHERE userid = :u ORDER BY id", array('u' => $uid))->fetchAll(PDO::FETCH_ASSOC) as $in) {
			$type = TYPE_MAP[$in['integration']] ?? null;
			if ($type === null) { out("  ! Integration {$in['id']} Typ '{$in['integration']}' unbekannt, uebersprungen"); continue; }
			$existing = one($hc, "SELECT id FROM `$db`.hc2_channels WHERE userid = :u AND legacy_integration_id = :l", array('u' => $uid, 'l' => $in['id']));
			if ($existing !== null) { $channelByLegacy[(int)$in['id']] = (int)$existing['id']; continue; }
			$o = json_decode((string)$in['options'], true); if (!is_array($o)) { $o = array(); }
			$cfg = $dry ? array() : channel_config($type, $o);
			$verified = ($type === 'ipv64_mail' || $type === 'ipv64_sms') ? ((int)$in['status'] === 1 ? 1 : 0) : 1;
			if (!$dry) {
				q($hc, "INSERT INTO `$db`.hc2_channels (userid, type, name, config_enc, enabled, is_default, lang, verified, created_at, updated_at, last_used, legacy_integration_id)
					VALUES (:u, :ty, :n, :cfg, :en, :def, 'de', :ver, :c, :c, :lu, :l)",
					array('u' => $uid, 'ty' => $type, 'n' => mb_substr(dec($in['name']) !== '' ? dec($in['name']) : ucfirst($type), 0, 100), 'cfg' => json_encode($cfg, JSON_UNESCAPED_SLASHES),
						'en' => (int)$in['status'] === 1 ? 1 : 0, 'def' => (int)$in['default_inte'] === 1 ? 1 : 0, 'ver' => $verified,
						'c' => utc($in['add_time']) ?? $now, 'lu' => utc($in['last_used']), 'l' => $in['id']));
				$channelByLegacy[(int)$in['id']] = (int)$hc->lastInsertId();
			}
			$stats['channels']++;
		}

		// 2) Checks
		$since = gmdate('Y-m-d H:i:s', time() - RAW_DAYS * 86400);          // in UTC; alte Tabellen speichern Berlin-Zeit
		$sinceBerlin = (new DateTime($since, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('Europe/Berlin'))->format('Y-m-d H:i:s');
		foreach (q($pdo, "SELECT * FROM healthchecks WHERE userid = :u ORDER BY id", array('u' => $uid))->fetchAll(PDO::FETCH_ASSOC) as $h) {
			$type = CHECK_TYPE_MAP[$h['type']] ?? null;
			if ($type === null) { out("  ! Check {$h['id']} Typ '{$h['type']}' unbekannt, uebersprungen"); continue; }
			$token = $h['healthtoken'];
			$opt = json_decode((string)$h['type_options'], true); if (!is_array($opt)) { $opt = array(); }
			$params = array(); $target = ''; $interval = 60; $retry = 20; $retries = 1; $ipMode = 'auto';
			if ($type === 'push') {
				$params['period_seconds'] = (int)$h['zeit1'] * (PUSH_UNITS[(int)$h['zeit2']] ?? 60);
				$params['grace_seconds']  = (int)$h['grace1'] * (PUSH_UNITS[(int)$h['grace2']] ?? 60);
			} else {
				$interval = max(20, (int)($opt['checkintervall1'] ?? 5) * (ACTIVE_UNITS[(int)($opt['checkintervall2'] ?? 1)] ?? 60));
				$retry = max(5, min($interval, (int)($opt['fehlerintervall1'] ?? 1) * (ACTIVE_UNITS[(int)($opt['fehlerintervall2'] ?? 1)] ?? 60)));
				$retries = max(0, min(10, (int)($opt['checkcount'] ?? 3) - 1));
				if ($type === 'icmp' || $type === 'tcp') {
					$target = dec($opt['hostnameip'] ?? '');
					if (($opt['preferv4'] ?? '') === 'on') { $ipMode = 'ipv4'; }
					if ($type === 'tcp') { $target .= ':' . (int)($opt['tcpport'] ?? 0); }
				} else {
					$target = dec($opt['url'] ?? '');
					$ssl = ($opt['ssltrust'] ?? '');
					if (!($ssl === 'on' || $ssl === '1')) { $params['insecure_tls'] = true; }
					$params['accept_status'] = '200-399';
					if ($type === 'keyword') { $params['keyword'] = dec($opt['keyword'] ?? ''); }
				}
			}
			// Kanaele: alte Liste "0,12,15" -> neue IDs; leer/0 = Standardkanaele (im neuen System: leer)
			$channels = array();
			foreach (array_filter(array_map('trim', explode(',', (string)$h['integration'])), 'strlen') as $lid) {
				$lid = (int)$lid;
				if (isset($channelByLegacy[$lid])) { $channels[] = $channelByLegacy[$lid]; }
			}
			if ($channels === array($channelByLegacy[0] ?? -1)) { $channels = array(); }   // nur Account-Mail = Standard
			$locations = $hcLocations >= 2 ? implode(',', LOCATIONS) : LOCATIONS[crc32($token) % count(LOCATIONS)];
			$state = STATE_MAP[(int)$h['status']] ?? 'pending';
			$paused = (int)$h['status'] === 2 ? 1 : 0;
			$row = array(
				'token' => $token, 'u' => $uid, 'loc' => $locations, 'slot' => slot($token), 'type' => $type,
				'name' => mb_substr(dec($h['healthname']), 0, 200), 'target' => mb_substr($target, 0, 500), 'params' => json_encode((object)$params, JSON_UNESCAPED_SLASHES),
				'iv' => $interval, 'riv' => $retry, 'retries' => $retries, 'ip' => $ipMode, 'paused' => $paused,
				'nd' => (int)$h['alarm_down'] === 1 ? 1 : 0, 'nu' => (int)$h['alarm_up'] === 1 ? 1 : 0, 'ch' => implode(',', $channels),
				'c' => utc($h['add_time']) ?? $now, 'now' => $now, 'legacy' => $h['id'], 'state' => $state,
				'since' => utc($h['last_update_time']), 'last' => utc($h['last_update_time']), 'next' => utc($h['next_ping']),
				'lstat' => in_array($state, array('up', 'stabilizing'), true) ? 'up' : ($state === 'down' ? 'down' : null),
				'push' => $type === 'push' ? utc($h['last_update_time']) : null,
			);
			if (!$dry) {
				q($hc, "INSERT INTO `$db`.hc2_checks (token, userid, agent_id, execution, locations, policy, notify_degraded, slot, type, name, target, params,
						interval_sec, retry_interval_sec, retries, connect_timeout_ms, total_timeout_ms, invert, stabilize, ip_mode, tags, description, paused,
						parent_token, critical, notify_down, notify_up, channels, repeat_minutes, revision, created_at, updated_at, updated_by, legacy_id,
						state, state_since, last_check_at, next_check_at, last_status, last_push_at)
					VALUES (:token, :u, NULL, 'online', :loc, 'all', 0, :slot, :type, :name, :target, :params,
						:iv, :riv, :retries, 5000, 10000, 0, 3, :ip, '', NULL, :paused,
						NULL, 0, :nd, :nu, :ch, 0, 1, :c, :now, 'migration', :legacy,
						:state, :since, :last, :next, :lstat, :push)
					ON DUPLICATE KEY UPDATE legacy_id = VALUES(legacy_id)", $row);
				// Zustand der Messstelle(n): alter Zustand gilt fuer jeden gewaehlten Standort
				foreach (explode(',', $locations) as $loc) {
					q($hc, "INSERT IGNORE INTO `$db`.hc2_check_states (token, source, state, since, last_check_at, next_check_at, last_status, updated_at)
						VALUES (:t, :s, :st, :since, :last, :next, :ls, :now)",
						array('t' => $token, 's' => 'loc:' . $loc, 'st' => $state === 'pending' ? 'pending' : $state, 'since' => $row['since'], 'last' => $row['last'], 'next' => $row['next'], 'ls' => $row['lstat'], 'now' => $now));
					$stats['states']++;
				}
			}
			$stats['checks']++;

			// 3) Messpunkte der letzten 7 Tage (alt: status 1 = up, 3/4 = down; 0/2/5 ohne Aussage)
			// agent_seq = alte Event-ID: eindeutig, auch bei zwei Ereignissen in derselben Sekunde
			$ev = q($pdo, "SELECT id, event_time, status, text, latency FROM healthcheck_events WHERE userid = :u AND healthtoken = :t AND event_time >= :s ORDER BY id",
				array('u' => $uid, 't' => $token, 's' => $sinceBerlin));
			$batch = array();
			while ($e = $ev->fetch(PDO::FETCH_ASSOC)) {
				$st = (int)$e['status'];
				if ($st !== 1 && $st !== 3 && $st !== 4) { continue; }
				$batch[] = array($token, 'legacy', (int)$e['id'], utc($e['event_time']), $st === 1 ? 1 : 0, (float)$e['latency'], $st === 1 ? '' : 'legacy', mb_substr(dec($e['text']), 0, 500), $now);
				if (count($batch) >= 500) { $stats['measurements'] += insert_measurements($batch, $dry); $batch = array(); }
			}
			if ($batch) { $stats['measurements'] += insert_measurements($batch, $dry); }

			// 4) Aeltere Ereignisse als Tageswerte
			$days = q($pdo, "SELECT DATE(event_time) d, COUNT(*) c, SUM(status = 1) up, MIN(NULLIF(latency,0)) mn, AVG(NULLIF(latency,0)) av, MAX(latency) mx
				FROM healthcheck_events WHERE userid = :u AND healthtoken = :t AND event_time < :s AND status IN (1,3,4) GROUP BY DATE(event_time)",
				array('u' => $uid, 't' => $token, 's' => $sinceBerlin));
			while ($d = $days->fetch(PDO::FETCH_ASSOC)) {
				if (!$dry) {
					q($hc, "INSERT IGNORE INTO `$db`.hc2_daily (token, source, day, count, up_count, min_ms, avg_ms, max_ms) VALUES (:t, 'legacy', :d, :c, :up, :mn, :av, :mx)",
						array('t' => $token, 'd' => $d['d'], 'c' => $d['c'], 'up' => $d['up'], 'mn' => $d['mn'], 'av' => $d['av'], 'mx' => $d['mx']));
				}
				$stats['daily']++;
			}

			// 5) Stoerungen
			foreach (q($pdo, "SELECT * FROM healthcheck_incidents WHERE userid = :u AND healthtoken = :t ORDER BY id", array('u' => $uid, 't' => $token))->fetchAll(PDO::FETCH_ASSOC) as $inc) {
				if (one($hc, "SELECT id FROM `$db`.hc2_incidents WHERE legacy_id = :l", array('l' => $inc['id'])) !== null) { continue; }
				if (!$dry) {
					q($hc, "INSERT INTO `$db`.hc2_incidents (token, userid, started_at, ended_at, reason, message, sources, legacy_id) VALUES (:t, :u, :s, :e, 'legacy', '', 'legacy', :l)",
						array('t' => $token, 'u' => $uid, 's' => utc($inc['created_at']) ?? $now, 'e' => (int)$inc['status'] === 1 ? utc($inc['closed_at']) : null, 'l' => $inc['id']));
				}
				$stats['incidents']++;
			}
		}

		// 6) Revisionen, Log, Flag
		if (!$dry) {
			q($hc, "INSERT INTO `$db`.hc2_revisions (userid, next) VALUES (:u, 2) ON DUPLICATE KEY UPDATE next = GREATEST(next, 2)", array('u' => $uid));
			foreach ($stats as $k => $v) {
				q($hc, "INSERT INTO `$db`.hc2_migration_log (userid, time, step, count, note) VALUES (:u, :t, :s, :c, '')", array('u' => $uid, 't' => $now, 's' => $k, 'c' => $v));
			}
			$hc->commit();
			if ($activate) { q($pdo, "UPDATE users SET hc2 = 1 WHERE id = :u", array('u' => $uid)); }
		}
	} catch (Throwable $e) {
		if (!$dry && $hc->inTransaction()) { $hc->rollBack(); }
		out("  FEHLER: " . $e->getMessage() . " (Account $uid zurueckgerollt)");
		return;
	}
	out(sprintf("  Kanaele %d, Checks %d, Messstellen %d, Messpunkte %d, Tageswerte %d, Stoerungen %d%s",
		$stats['channels'], $stats['checks'], $stats['states'], $stats['measurements'], $stats['daily'], $stats['incidents'],
		$activate && !$dry ? ' -> hc2 = 1' : ''));
}

function insert_measurements(array $rows, bool $dry): int {
	if ($dry) { return count($rows); }
	$sql = "INSERT IGNORE INTO `" . HC2DB . "`.hc2_measurements (token, source, agent_seq, time, status, latency_ms, reason, message, received_at) VALUES ";
	$sql .= implode(',', array_fill(0, count($rows), '(?,?,?,?,?,?,?,?,?)'));
	$flat = array();
	foreach ($rows as $r) { array_push($flat, ...$r); }
	hc2_pdo()->prepare($sql)->execute($flat);
	return count($rows);
}

// ---------------------------------------------------------------- Accounts auswaehlen
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
if ($who === 'all') {
	$sql = "SELECT id, email, user_class FROM users WHERE hc2 = 0"; $p = array();
	if ($class > 0) { $sql .= " AND user_class = :c"; $p['c'] = $class; }
	$sql .= " ORDER BY id";
	if ($limit > 0) { $sql .= " LIMIT " . (int)$limit; }
	$users = q($pdo, $sql, $p)->fetchAll(PDO::FETCH_ASSOC);
} else {
	$u = is_numeric($who) ? one($pdo, "SELECT id, email, user_class FROM users WHERE id = :i", array('i' => (int)$who))
		: one($pdo, "SELECT id, email, user_class FROM users WHERE email = :e", array('e' => $who));
	if ($u === null) { fwrite(STDERR, "Account nicht gefunden: $who\n"); exit(1); }
	$users = array($u);
}
out(count($users) . " Account(s)" . ($dry ? ' (dry-run, es wird nichts geschrieben)' : ''));
if (!$dry && hc2_key() === null) { out("Hinweis: Schluesseldatei " . HC2_KEY_FILE . " fehlt; Accounts mit Integrationen, die Geheimnisse enthalten, schlagen fehl."); }
foreach ($users as $u) { migrate_user($pdo, $u, $dry, $activate); }
out("fertig");
