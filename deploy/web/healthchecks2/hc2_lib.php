<?php
/**
 * Healthchecks 2.0 – gemeinsame Hilfsfunktionen der neuen Portal-Seiten (healthchecks2/*, notifications.php, nodes.php).
 * Voraussetzung: header.php ist eingebunden (Session, $userid, $pdo) und dbconnect.php enthaelt die hc2_*-Grundfunktionen
 * (hc2_pdo, hc2_log_change, hc2_signal, hc2_encrypt, hc2_decrypt). Alle Zeiten in der DB sind UTC.
 * Bewusst ohne Menuelinks: nur wer die URL kennt, findet die Seiten.
 */

defined('HC2_BRIDGE_SECRET_FILE') || define('HC2_BRIDGE_SECRET_FILE', '/var/www/clients/client1/web58/private/hc2_bridge.secret');
defined('HC2_HUBS') || define('HC2_HUBS', 'https://hc-srv01.ipv64.net,https://hc-srv02.ipv64.net');
defined('HC2_BASE') || define('HC2_BASE', '/healthchecks2');

// ---------------------------------------------------------------- Grundlagen

function hc2_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/** Login erzwingen (wie die alten Seiten: Hinweis statt Umleitung) und CSRF-Token bereitstellen. */
function hc2_require_login(): void {
	global $userid;
	if ($userid == '') {
		echo '<div class="container"><div class="alert alert-warning mt-3">Bitte zuerst anmelden.</div></div>';
		include(__DIR__ . '/../footer.php');
		exit;
	}
	if (empty($_SESSION['hc2_csrf'])) { $_SESSION['hc2_csrf'] = bin2hex(random_bytes(16)); }
}
function hc2_csrf_field(): string { return '<input type="hidden" name="_csrf" value="' . hc2_h($_SESSION['hc2_csrf'] ?? '') . '">'; }
function hc2_csrf_ok(): bool {
	$t = (string)($_POST['_csrf'] ?? $_GET['_csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
	return !empty($_SESSION['hc2_csrf']) && hash_equals($_SESSION['hc2_csrf'], $t);
}
function hc2_is_post(): bool { return $_SERVER['REQUEST_METHOD'] === 'POST'; }
function hc2_redirect(string $url): void { header('Location: ' . $url); exit; }
function hc2_flash(string $kind, string $msg): void { $_SESSION['hc2_flash'] = array($kind, $msg); }
function hc2_flash_out(): string {
	if (empty($_SESSION['hc2_flash'])) { return ''; }
	[$k, $m] = $_SESSION['hc2_flash']; unset($_SESSION['hc2_flash']);
	return '<div class="alert alert-' . hc2_h($k) . '" role="alert">' . hc2_h($m) . '</div>';
}
function hc2_json(array $out, int $code = 200): void {
	while (ob_get_level() > 0) { ob_end_clean(); } // HTML aus header.php verwerfen
	http_response_code($code);
	header('Content-Type: application/json; charset=utf-8'); header('Cache-Control: no-store');
	echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	exit;
}

/** UTC-Zeit aus der DB -> Europe/Berlin, formatiert. */
function hc2_dt($utc, string $fmt = 'd.m.Y H:i:s'): string {
	if (!$utc) { return '–'; }
	try { $t = new DateTime($utc, new DateTimeZone('UTC')); $t->setTimezone(new DateTimeZone('Europe/Berlin')); return $t->format($fmt); }
	catch (Throwable $e) { return (string)$utc; }
}
function hc2_ago($utc): string {
	if (!$utc) { return '–'; }
	$s = time() - strtotime($utc . ' UTC');
	if ($s < 0) { $s = 0; }
	if ($s < 60) { return $s . ' s'; }
	if ($s < 3600) { return floor($s / 60) . ' min'; }
	if ($s < 86400) { return floor($s / 3600) . ' h ' . floor(($s % 3600) / 60) . ' min'; }
	return floor($s / 86400) . ' d ' . floor(($s % 86400) / 3600) . ' h';
}
function hc2_dur(int $sec): string {
	if ($sec < 60) { return $sec . ' s'; }
	if ($sec < 3600) { return floor($sec / 60) . ' min ' . ($sec % 60) . ' s'; }
	if ($sec < 86400) { return floor($sec / 3600) . ' h ' . floor(($sec % 3600) / 60) . ' min'; }
	return floor($sec / 86400) . ' d ' . floor(($sec % 86400) / 3600) . ' h';
}
function hc2_token(int $len = 32): string {
	$a = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; $o = '';
	for ($i = 0; $i < $len; $i++) { $o .= $a[random_int(0, strlen($a) - 1)]; }
	return $o;
}
function hc2_slot(string $token): int { return (int)(sprintf('%u', crc32($token)) % 1024); }

// ---------------------------------------------------------------- Account, Nodes, Standorte

/** Account-Klasse und Limits (Sicht ipv64.hc2_users_v, lesbar fuer ipv64_hc). */
function hc2_account(int $userid): array {
	static $cache = array();
	if (isset($cache[$userid])) { return $cache[$userid]; }
	$st = hc2_pdo()->prepare("SELECT id, email, user_class, hc2, healthcheck_limit, hc_locations, sms_limit FROM ipv64.hc2_users_v WHERE id = :u");
	$st->execute(array('u' => $userid));
	$a = $st->fetch(PDO::FETCH_ASSOC) ?: array('id' => $userid, 'email' => '', 'user_class' => 1, 'hc2' => 0, 'healthcheck_limit' => 0, 'hc_locations' => 1, 'sms_limit' => 0);
	$names = array(1 => 'Standard', 2 => 'VIP', 3 => 'Premium', 4 => 'Business', 5 => 'Company', 6 => 'Supporter');
	$a['class_name'] = $names[(int)$a['user_class']] ?? ('Klasse ' . $a['user_class']);
	$a['healthcheck_limit'] = (int)$a['healthcheck_limit']; $a['hc_locations'] = max(1, (int)$a['hc_locations']); $a['sms_limit'] = (int)$a['sms_limit'];
	return $cache[$userid] = $a;
}

/** Belegte Online-Messstellen (Check x Standorte), optional ohne einen Token. */
function hc2_online_used(int $userid, string $except = ''): int {
	$st = hc2_pdo()->prepare("SELECT COALESCE(SUM(LENGTH(locations) - LENGTH(REPLACE(locations, ',', '')) + 1), 0) FROM hc2_checks WHERE userid = :u AND deleted_at IS NULL AND execution IN ('online','both') AND token <> :t");
	$st->execute(array('u' => $userid, 't' => $except));
	return (int)$st->fetchColumn();
}

/** Aktive Nodes des Accounts, Schluessel node_id. */
function hc2_nodes(int $userid, bool $fresh = false): array {
	static $cache = array();
	if (isset($cache[$userid]) && !$fresh) { return $cache[$userid]; }
	$st = hc2_pdo()->prepare("SELECT node_id, name, location, version, remote_mgmt, online, last_seen, last_sync, outbox_size, conflicts, modules, timezone, created_at FROM hc2_nodes WHERE userid = :u AND revoked_at IS NULL ORDER BY name");
	$st->execute(array('u' => $userid));
	$out = array();
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $n) { $out[$n['node_id']] = $n; }
	return $cache[$userid] = $out;
}
function hc2_node_label(array $nodes, ?string $nodeId): string {
	if (!$nodeId) { return ''; }
	if (!isset($nodes[$nodeId])) { return 'Node (getrennt)'; }
	$n = $nodes[$nodeId];
	return $n['name'] . ($n['location'] !== '' ? ' (' . $n['location'] . ')' : '');
}

/** Standorte der hubs (Code => Name). */
function hc2_locations(): array {
	static $l = null;
	if ($l !== null) { return $l; }
	$l = array();
	try {
		foreach (hc2_pdo()->query("SELECT code, name FROM hc2_locations WHERE enabled = 1 ORDER BY code") as $r) { $l[$r['code']] = $r['name']; }
	} catch (Throwable $e) { error_log('hc2_locations: ' . $e->getMessage()); }
	if (!$l) { $l = array('nbg' => 'Nürnberg', 'fsn' => 'Falkenstein'); }
	return $l;
}

// ---------------------------------------------------------------- Checks: Definitionen

function hc2_types(): array {
	return array('http' => 'HTTP(S)', 'keyword' => 'Schlüsselwort', 'icmp' => 'Ping (ICMP)', 'tcp' => 'TCP', 'port' => 'Port', 'cert' => 'Zertifikat', 'push' => 'Push / Heartbeat', 'docker' => 'Docker-Container');
}
function hc2_states(): array {
	return array('up' => array('OK', 'success'), 'down' => array('Gestört', 'danger'), 'degraded' => array('Teilweise gestört', 'warning'), 'flapping' => array('Instabil', 'warning'),
		'paused' => array('Pausiert', 'secondary'), 'pending' => array('Ausstehend', 'info'), 'maintenance' => array('Wartung', 'secondary'), 'unknown' => array('Unbekannt', 'secondary'));
}
function hc2_state_badge(?string $state): string {
	$s = hc2_states(); $x = $s[$state ?? 'pending'] ?? array($state, 'secondary');
	return '<span class="badge badge-' . $x[1] . '">' . hc2_h($x[0]) . '</span>';
}
function hc2_reason_text(?string $r): string {
	$m = array('ok' => 'OK', 'timeout' => 'Zeitüberschreitung', 'dns' => 'DNS-Fehler', 'connection_refused' => 'Verbindung abgelehnt', 'connect_error' => 'Verbindungsfehler', 'tls' => 'TLS-Fehler',
		'http_status' => 'HTTP-Status', 'keyword_missing' => 'Schlüsselwort fehlt', 'keyword_present' => 'Schlüsselwort vorhanden', 'port_closed' => 'Port geschlossen', 'port_open' => 'Port offen',
		'packet_loss' => 'Paketverlust', 'latency' => 'Latenz zu hoch', 'cert_expiring' => 'Zertifikat läuft ab', 'cert_expired' => 'Zertifikat abgelaufen', 'cert_invalid' => 'Zertifikat ungültig',
		'push_missing' => 'Push ausgeblieben', 'push_down' => 'Push meldet Störung', 'invalid_definition' => 'Definition ungültig', 'unreachable' => 'Nicht erreichbar', 'inverted' => 'Invertiert',
		'icmp_not_permitted' => 'ICMP nicht erlaubt', 'family_unreachable' => 'IP-Familie nicht erreichbar');
	return $m[$r ?? ''] ?? (string)$r;
}
function hc2_exec_badge(array $c, array $nodes): string {
	$node = hc2_node_label($nodes, $c['node_id'] ?? null);
	$locs = array(); foreach (explode(',', (string)($c['locations'] ?? '')) as $l) { if ($l !== '') { $locs[] = hc2_locations()[$l] ?? $l; } }
	$online = 'ipv64 (' . implode(', ', $locs) . ')';
	switch ($c['execution'] ?? 'online') {
		case 'local': return '<span class="badge badge-light" title="Wird nur von der Node gemessen"><i class="fa-solid fa-house"></i> ' . hc2_h($node ?: 'Node') . '</span>';
		case 'both': return '<span class="badge badge-light" title="Hybrid: Node und ipv64 messen"><i class="fa-solid fa-house"></i> ' . hc2_h($node ?: 'Node') . ' + <i class="fa-solid fa-cloud"></i> ' . hc2_h($online) . '</span>';
		default: return '<span class="badge badge-light" title="Wird von ipv64.net gemessen"><i class="fa-solid fa-cloud"></i> ' . hc2_h($online) . '</span>';
	}
}
function hc2_source_label(string $src, array $nodes): string {
	if (strncmp($src, 'loc:', 4) === 0) { $c = substr($src, 4); return 'ipv64 ' . (hc2_locations()[$c] ?? $c); }
	if (strncmp($src, 'node:', 5) === 0) { return hc2_node_label($nodes, substr($src, 5)) ?: 'Node'; }
	if ($src === 'push') { return 'Push'; }
	return $src === '' ? 'Gesamt' : $src;
}

/** Ein Check des Accounts oder null. */
function hc2_check(int $userid, string $token): ?array {
	if (!preg_match('/^[A-Za-z0-9]{20,50}$/', $token)) { return null; }
	$st = hc2_pdo()->prepare("SELECT * FROM hc2_checks WHERE token = :t AND userid = :u AND deleted_at IS NULL");
	$st->execute(array('t' => $token, 'u' => $userid));
	$c = $st->fetch(PDO::FETCH_ASSOC);
	return $c ?: null;
}
function hc2_checks(int $userid): array {
	$st = hc2_pdo()->prepare("SELECT * FROM hc2_checks WHERE userid = :u AND deleted_at IS NULL ORDER BY name, token");
	$st->execute(array('u' => $userid));
	return $st->fetchAll(PDO::FETCH_ASSOC);
}
function hc2_check_params(array $c): array { $p = json_decode((string)($c['params'] ?? '{}'), true); return is_array($p) ? $p : array(); }
function hc2_check_channels(array $c): array { $o = array(); foreach (explode(',', (string)($c['channels'] ?? '')) as $x) { if ($x !== '' && is_numeric($x)) { $o[] = (int)$x; } } return $o; }

/** Privates Ziel? (RFC 1918, ULA, Loopback, Link-Local, .local, localhost) – online verboten. */
function hc2_private_target(string $type, string $target): bool {
	$t = trim($target);
	if ($t === '' || $type === 'push') { return false; }
	$host = $t;
	if (in_array($type, array('http', 'keyword'), true)) { $host = (string)parse_url($t, PHP_URL_HOST); }
	elseif (preg_match('/^\[([^\]]+)\](?::\d+)?$/', $t, $m)) { $host = $m[1]; }
	elseif (substr_count($t, ':') === 1) { $host = explode(':', $t)[0]; }
	$host = strtolower(trim($host, '[]'));
	if ($host === '' ) { return false; }
	if ($host === 'localhost' || substr($host, -6) === '.local' || substr($host, -10) === '.localhost' || substr($host, -9) === '.internal') { return true; }
	if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		return !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) || strncmp($host, '169.254.', 8) === 0 || strncmp($host, '100.64.', 7) === 0;
	}
	if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
		return $host === '::1' || preg_match('/^f[cd][0-9a-f]{2}:/', $host) || preg_match('/^fe[89ab][0-9a-f]:/', $host);
	}
	return false;
}

/**
 * Formulareingabe pruefen und in eine hc2_checks-Zeile umsetzen. Regeln wie checks.Validate in der Node.
 * Liefert array('row' => ..., 'errors' => array()).
 */
function hc2_validate_check(array $in, int $userid, ?array $old): array {
	$acc = hc2_account($userid); $nodes = hc2_nodes($userid); $locs = hc2_locations(); $err = array();
	$type = (string)($in['type'] ?? 'http');
	if (!isset(hc2_types()[$type])) { $err[] = 'Unbekannter Check-Typ.'; $type = 'http'; }
	$name = mb_substr(trim((string)($in['name'] ?? '')), 0, 200);
	if ($name === '') { $err[] = 'Name fehlt.'; }
	$target = mb_substr(trim((string)($in['target'] ?? '')), 0, 500);
	$p = array();
	$num = function($k, $def, $min, $max) use ($in) { $v = $in[$k] ?? ''; if ($v === '' || $v === null) { return $def; } $v = (int)$v; return max($min, min($max, $v)); };
	$flag = function($k) use ($in) { return !empty($in[$k]) && $in[$k] !== '0'; };
	switch ($type) {
		case 'http': case 'keyword':
			if (!preg_match('#^https?://[^\s/]+#i', $target) || parse_url($target, PHP_URL_HOST) === null) { $err[] = 'Ziel muss eine http(s)-URL sein.'; }
			$m = strtoupper((string)($in['method'] ?? 'GET')); if (!in_array($m, array('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'), true)) { $m = 'GET'; }
			if ($m !== 'GET') { $p['method'] = $m; }
			$as = trim((string)($in['accept_status'] ?? ''));
			if ($as !== '' && !preg_match('/^\d{3}(-\d{3})?(\s*,\s*\d{3}(-\d{3})?)*$/', $as)) { $err[] = 'Erlaubte Statuscodes: z. B. 200-299,301'; }
			if ($as !== '' && $as !== '200-299') { $p['accept_status'] = $as; }
			if (!$flag('follow_redirects') && isset($in['follow_redirects_present'])) { $p['follow_redirects'] = false; }
			if (($mr = $num('max_redirects', 5, 0, 20)) !== 5) { $p['max_redirects'] = $mr; }
			if ($type === 'keyword') { $kw = trim((string)($in['keyword'] ?? '')); if ($kw === '') { $err[] = 'Schlüsselwort fehlt.'; } $p['keyword'] = $kw; if ($flag('keyword_absent')) { $p['keyword_absent'] = true; } }
			if (($bu = trim((string)($in['basic_user'] ?? ''))) !== '') { $p['basic_user'] = $bu; $p['basic_password'] = (string)($in['basic_password'] ?? ''); }
			$hd = array(); foreach (preg_split('/\r?\n/', (string)($in['headers'] ?? '')) as $line) { if (strpos($line, ':') !== false) { [$k, $v] = explode(':', $line, 2); $k = trim($k); if ($k !== '') { $hd[$k] = trim($v); } } }
			if ($hd) { $p['headers'] = $hd; }
			if (($b = (string)($in['body'] ?? '')) !== '') { $p['body'] = $b; }
			if ($flag('insecure_tls')) { $p['insecure_tls'] = true; }
			if (($cd = $num('cert_min_days', 0, 0, 3650)) > 0) { $p['cert_min_days'] = $cd; }
			break;
		case 'icmp':
			if ($target === '') { $err[] = 'Ziel (Host oder IP) fehlt.'; }
			if (($c = $num('count', 3, 1, 20)) !== 3) { $p['count'] = $c; }
			if (($l = $num('max_loss_percent', 0, 0, 100)) !== 0) { $p['max_loss_percent'] = $l; }
			if (($ml = $num('max_latency_ms', 0, 0, 60000)) !== 0) { $p['max_latency_ms'] = $ml; }
			break;
		case 'tcp': case 'port': case 'cert':
			if ($target === '') { $err[] = 'Ziel (Host oder IP, optional :Port) fehlt.'; }
			$port = $num('port', 0, 0, 65535);
			$hasPort = (bool)preg_match('/^(\[[^\]]+\]|[^:]+):\d+$/', $target);
			if ($type === 'cert' && $port === 0 && !$hasPort) { $port = 443; }
			if ($port > 0) { $p['port'] = $port; } elseif (!$hasPort && $type !== 'cert') { $err[] = 'Port fehlt (im Ziel als host:port oder im Feld Port).'; }
			if ($type === 'tcp') { if (($s = (string)($in['send'] ?? '')) !== '') { $p['send'] = $s; } if (($e = (string)($in['expect'] ?? '')) !== '') { $p['expect'] = $e; } if ($flag('tls')) { $p['tls'] = true; } }
			if ($type === 'port') { $e = (string)($in['expect'] ?? 'open'); if ($e === 'closed') { $p['expect'] = 'closed'; } }
			if ($type === 'cert') { if (($d = $num('min_days', 14, 0, 3650)) !== 14) { $p['min_days'] = $d; } if (($sn = trim((string)($in['server_name'] ?? ''))) !== '') { $p['server_name'] = $sn; } if ($flag('skip_chain')) { $p['skip_chain'] = true; } if ($flag('skip_hostname')) { $p['skip_hostname'] = true; } }
			break;
		case 'docker':
			if (!preg_match('/^\/?[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/', $target)) { $err[] = 'Containername oder -ID fehlt (Buchstaben, Ziffern, _ . -).'; }
			if (($h = trim((string)($in['docker_host'] ?? ''))) !== '') { if (!preg_match('#^(unix|tcp|https?)://#', $h)) { $err[] = 'Docker-Host muss mit unix://, tcp:// oder http(s):// beginnen.'; } else { $p['host'] = $h; } }
			break;
		case 'push':
			$target = '';
			if (($ps = $num('period_seconds', 3600, 20, 31536000)) !== 3600) { $p['period_seconds'] = $ps; }
			if (isset($in['grace_seconds']) && $in['grace_seconds'] !== '') { $g = $num('grace_seconds', 600, 0, 31536000); if ($g !== 600) { $p['grace_seconds'] = $g; } }
			break;
	}
	$interval = $num('interval_sec', 60, 20, 86400);
	$retryInt = $num('retry_interval_sec', 20, 5, 86400);
	$retries = $num('retries', 1, 0, 10);
	$cto = (float)($in['connect_timeout'] ?? 5); $cto = max(0.5, min(60, $cto));
	$tto = (float)($in['total_timeout'] ?? 10); $tto = max(1, min(120, $tto));
	$stab = $num('stabilize', 3, 1, 20);
	$ipMode = (string)($in['ip_mode'] ?? 'auto'); if (!in_array($ipMode, array('auto','ipv4','ipv6','both'), true)) { $ipMode = 'auto'; }
	$tags = array(); foreach (preg_split('/[,\s]+/', (string)($in['tags'] ?? '')) as $t) { $t = trim($t); if ($t !== '' && !in_array($t, $tags, true)) { $tags[] = mb_substr($t, 0, 40); } }
	$tags = implode(',', array_slice($tags, 0, 20)); if (strlen($tags) > 255) { $tags = substr($tags, 0, 255); }
	$group = mb_substr(trim((string)($in['group_name'] ?? '')), 0, 100);
	$desc = mb_substr(trim((string)($in['description'] ?? '')), 0, 5000);
	$parent = trim((string)($in['parent_token'] ?? ''));
	if ($parent !== '') {
		if (($old && $parent === $old['token']) || !hc2_check($userid, $parent)) { $err[] = 'Abhängigkeit ungültig.'; $parent = ''; }
	}
	$channels = array();
	$own = array(); foreach (hc2_channels($userid) as $ch) { $own[(int)$ch['id']] = true; }
	foreach ((array)($in['channels'] ?? array()) as $cid) { $cid = (int)$cid; if (isset($own[$cid]) && !in_array($cid, $channels, true)) { $channels[] = $cid; } }
	$repeat = $num('repeat_minutes', 0, 0, 10080);

	// Messstellen und Bewertung
	$execution = (string)($in['execution'] ?? 'online'); if (!in_array($execution, array('local','online','both'), true)) { $execution = 'online'; }
	$nodeId = (string)($in['node_id'] ?? ($old['node_id'] ?? ''));
	if ($execution !== 'online') {
		if ($nodeId === '' || !isset($nodes[$nodeId])) { $err[] = 'Für lokale oder hybride Messung muss eine verbundene Node gewählt sein.'; }
	}
	$sel = array(); foreach ((array)($in['locations'] ?? array_keys($locs)) as $l) { if (isset($locs[$l]) && !in_array($l, $sel, true)) { $sel[] = $l; } }
	if (!$sel) { $sel = array_keys($locs); }
	if (count($sel) > $acc['hc_locations']) { $sel = array_slice($sel, 0, $acc['hc_locations']); }
	$policy = (string)($in['policy'] ?? 'all'); if (!in_array($policy, array('all','any','majority'), true)) { $policy = 'all'; }
	if ($type === 'docker' && $execution !== 'local') { $err[] = 'Docker-Checks laufen nur lokal auf einer Node und sind nicht umhängbar.'; }
	if ($execution !== 'local' && $type !== 'docker') {
		if (hc2_private_target($type, $target)) { $err[] = 'Online-Checks können keine privaten Ziele prüfen (Heimnetz, localhost, .local). Dafür eine Node nutzen.'; }
		$used = hc2_online_used($userid, $old['token'] ?? '');
		if ($acc['healthcheck_limit'] > 0 && $used + count($sel) > $acc['healthcheck_limit']) {
			$err[] = 'Online-Limit erreicht: ' . $used . ' von ' . $acc['healthcheck_limit'] . ' Messstellen belegt, benötigt werden ' . count($sel) . ' weitere. Standorte reduzieren oder lokal auf einer Node messen.';
		}
	}
	$row = array(
		'type' => $type, 'name' => $name, 'target' => $target, 'params' => json_encode($p ?: new stdClass(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
		'interval_sec' => $interval, 'retry_interval_sec' => $retryInt, 'retries' => $retries, 'connect_timeout_ms' => (int)round($cto * 1000), 'total_timeout_ms' => (int)round($tto * 1000),
		'invert' => $flag('invert') ? 1 : 0, 'stabilize' => $stab, 'ip_mode' => $ipMode, 'tags' => $tags, 'group_name' => $group, 'description' => $desc, 'paused' => $flag('paused') ? 1 : 0,
		'parent_token' => $parent !== '' ? $parent : null, 'critical' => $flag('critical') ? 1 : 0, 'notify_down' => $flag('notify_down') ? 1 : 0, 'notify_up' => $flag('notify_up') ? 1 : 0,
		'channels' => implode(',', $channels), 'repeat_minutes' => $repeat,
		'execution' => $execution, 'node_id' => $execution === 'online' ? ($old['node_id'] ?? null) : $nodeId, 'locations' => implode(',', $sel), 'policy' => $policy, 'notify_degraded' => $flag('notify_degraded') ? 1 : 0,
	);
	if ($execution === 'online' && $row['node_id'] === '') { $row['node_id'] = null; }
	return array('row' => $row, 'errors' => $err);
}

/** Neuen Check anlegen; liefert den Token. */
function hc2_insert_check(int $userid, array $row): string {
	$pdo = hc2_pdo(); $token = hc2_token();
	$cols = array_keys($row);
	$sql = "INSERT INTO hc2_checks (token, userid, slot, revision, created_at, updated_at, updated_by, " . implode(',', $cols) . ") VALUES (:token, :userid, :slot, 1, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3), 'portal', :" . implode(', :', $cols) . ")";
	$row['token'] = $token; $row['userid'] = $userid; $row['slot'] = hc2_slot($token);
	$pdo->prepare($sql)->execute($row);
	hc2_log_change($userid, 'check', $token, 'upsert', 'portal');
	return $token;
}
/** Bestehenden Check speichern. */
function hc2_update_check(int $userid, string $token, array $row): void {
	$pdo = hc2_pdo();
	$set = array(); foreach (array_keys($row) as $k) { $set[] = "$k = :$k"; }
	$row['token'] = $token; $row['userid'] = $userid;
	$pdo->prepare("UPDATE hc2_checks SET " . implode(', ', $set) . ", updated_by = 'portal' WHERE token = :token AND userid = :userid AND deleted_at IS NULL")->execute($row);
	hc2_log_change($userid, 'check', $token, 'upsert', 'portal');
}
function hc2_set_check(int $userid, string $token, array $fields): void {
	$set = array(); foreach (array_keys($fields) as $k) { $set[] = "$k = :$k"; }
	$fields['token'] = $token; $fields['userid'] = $userid;
	hc2_pdo()->prepare("UPDATE hc2_checks SET " . implode(', ', $set) . ", updated_by = 'portal' WHERE token = :token AND userid = :userid AND deleted_at IS NULL")->execute($fields);
	hc2_log_change($userid, 'check', $token, 'upsert', 'portal');
}
function hc2_delete_check(int $userid, string $token): void {
	hc2_log_change($userid, 'check', $token, 'delete', 'portal'); // setzt deleted_at
	hc2_pdo()->prepare("UPDATE hc2_incidents SET ended_at = UTC_TIMESTAMP(3) WHERE userid = :u AND token = :t AND ended_at IS NULL")->execute(array('u' => $userid, 't' => $token));
	hc2_pdo()->prepare("UPDATE hc2_checks SET parent_token = NULL WHERE userid = :u AND parent_token = :t")->execute(array('u' => $userid, 't' => $token));
}

/** Pillen (letzte n Messpunkte, alle Messstellen) im Stil der alten Seite. */
function hc2_pills(string $token, int $n, array $nodes): string {
	$st = hc2_pdo()->prepare("SELECT source, time, status, latency_ms, reason, message FROM hc2_measurements WHERE token = :t ORDER BY time DESC LIMIT " . (int)$n);
	$st->execute(array('t' => $token));
	$out = '';
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $m) {
		$cls = (int)$m['status'] === 1 ? 'little-bar-green' : 'little-bar-danger';
		$tip = hc2_dt($m['time'], 'd.m. H:i:s') . ' · ' . hc2_source_label($m['source'], $nodes) . ' · ' . ((int)$m['status'] === 1 ? 'OK' : hc2_reason_text($m['reason'])) . ((float)$m['latency_ms'] > 0 ? ' · ' . round((float)$m['latency_ms'], 1) . ' ms' : '') . ($m['message'] !== '' ? ' · ' . mb_substr($m['message'], 0, 80) : '');
		$out = '<div class="beat2 gros-bar ' . $cls . '" data-toggle="tooltip" data-placement="top" title="' . hc2_h($tip) . '"></div>' . $out;
	}
	return $out === '' ? '<span class="text-muted small">noch keine Messungen</span>' : $out;
}

/** Verfuegbarkeit in Prozent aus hc2_hourly (24 h), hc2_daily (30 d, 365 d). */
function hc2_availability(string $token): array {
	$pdo = hc2_pdo(); $out = array();
	foreach (array('24h' => array('hc2_hourly', 'hour', 24), '30d' => array('hc2_daily', 'day', 30), '1y' => array('hc2_daily', 'day', 365)) as $k => [$tbl, $col, $span]) {
		try {
			$unit = $tbl === 'hc2_hourly' ? 'HOUR' : 'DAY';
			$st = $pdo->prepare("SELECT SUM(count) c, SUM(up_count) u FROM $tbl WHERE token = :t AND $col >= UTC_TIMESTAMP() - INTERVAL $span $unit");
			$st->execute(array('t' => $token)); $r = $st->fetch(PDO::FETCH_ASSOC);
			$out[$k] = ($r && (int)$r['c'] > 0) ? round(100 * (int)$r['u'] / (int)$r['c'], 3) : null;
		} catch (Throwable $e) { $out[$k] = null; }
	}
	return $out;
}

// ---------------------------------------------------------------- Umhaengen (Testlauf)

/** Wire-Definition eines Checks (wie die Node sie dem hub schickt), optional mit abweichenden Feldern. */
function hc2_wire_def(array $c): array {
	return array('token' => $c['token'] ?? '', 'name' => $c['name'] ?? '', 'type' => $c['type'], 'target' => $c['target'] ?? '', 'params' => json_decode((string)($c['params'] ?? '{}')) ?: new stdClass(),
		'ip_mode' => $c['ip_mode'] ?? 'auto', 'connect_timeout_seconds' => ((int)($c['connect_timeout_ms'] ?? 5000)) / 1000, 'timeout_seconds' => ((int)($c['total_timeout_ms'] ?? 10000)) / 1000,
		'interval_seconds' => (int)($c['interval_sec'] ?? 60));
}

/**
 * Testlauf fuer ein Umhaengen anlegen: online/both -> die hubs messen je Standort; local/both -> Kommando test_check an die Node.
 * Liefert array('id' => ..., 'error' => '') .
 */
function hc2_testrun_create(int $userid, array $c, string $target, ?string $nodeId, array $locations): array {
	$acc = hc2_account($userid); $nodes = hc2_nodes($userid);
	if (!in_array($target, array('local','online','both'), true)) { return array('id' => 0, 'error' => 'Ungültiger Ausführungsort.'); }
	if ($c['type'] === 'docker') { return array('id' => 0, 'error' => 'Docker-Checks laufen nur lokal auf ihrer Node und sind nicht umhängbar.'); }
	if ($target !== 'online') {
		if (!$nodeId || !isset($nodes[$nodeId])) { return array('id' => 0, 'error' => 'Node nicht gefunden oder getrennt.'); }
		if ((int)$nodes[$nodeId]['online'] !== 1) { return array('id' => 0, 'error' => 'Die Node ist offline; der Testlauf braucht eine verbundene Node.'); }
		if ($nodes[$nodeId]['remote_mgmt'] === 'off') { return array('id' => 0, 'error' => 'Die Node nimmt keine Befehle an (Fernverwaltung aus).'); }
	}
	if ($target !== 'local') {
		if (hc2_private_target($c['type'], $c['target'])) { return array('id' => 0, 'error' => 'Online-Checks können keine privaten Ziele prüfen.'); }
		$locations = array_values(array_intersect($locations ?: array_keys(hc2_locations()), array_keys(hc2_locations())));
		if (!$locations) { $locations = array_keys(hc2_locations()); }
		$locations = array_slice($locations, 0, $acc['hc_locations']);
		$used = hc2_online_used($userid, $c['token']);
		if ($acc['healthcheck_limit'] > 0 && $used + count($locations) > $acc['healthcheck_limit']) { return array('id' => 0, 'error' => 'Online-Limit erreicht (' . $used . ' von ' . $acc['healthcheck_limit'] . ' Messstellen).'); }
	} else { $locations = array_keys(hc2_locations()); }
	$def = json_encode(hc2_wire_def($c), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	$pdo = hc2_pdo();
	$pdo->prepare("INSERT INTO hc2_testruns (userid, token, definition, target_execution, node_id, locations, status, created_at) VALUES (:u, :t, :d, :e, :n, :l, 'pending', UTC_TIMESTAMP(3))")
		->execute(array('u' => $userid, 't' => $c['token'], 'd' => $def, 'e' => $target, 'n' => $target === 'online' ? null : $nodeId, 'l' => implode(',', $locations)));
	$id = (int)$pdo->lastInsertId();
	if ($target !== 'online') {
		hc2_command($nodeId, 'test_check', array('definition' => json_decode($def), 'testrun_id' => $id, 'token' => $c['token']));
	}
	return array('id' => $id, 'error' => '');
}

/** Status eines Testlaufs; bei ok wird das Umhaengen genau einmal angewendet (result.applied). */
function hc2_testrun_status(int $userid, int $id): array {
	$pdo = hc2_pdo();
	$st = $pdo->prepare("SELECT * FROM hc2_testruns WHERE id = :i AND userid = :u"); $st->execute(array('i' => $id, 'u' => $userid));
	$t = $st->fetch(PDO::FETCH_ASSOC);
	if (!$t) { return array('status' => 'missing'); }
	$res = json_decode((string)$t['result'], true) ?: array();
	$out = array('id' => $id, 'status' => $t['status'], 'token' => $t['token'], 'target' => $t['target_execution'], 'results' => array(), 'applied' => !empty($res['applied']));
	$nodes = hc2_nodes($userid);
	foreach ($res as $k => $r) {
		if ($k === 'applied' || !is_array($r)) { continue; }
		$label = $k === 'node' ? (hc2_node_label($nodes, $t['node_id']) ?: 'Node') : 'ipv64 ' . (hc2_locations()[$k] ?? $k);
		$msg = $r['error'] ?? '';
		if ($msg === '' && !empty($r['results']) && is_array($r['results'])) { $parts = array(); foreach ($r['results'] as $x) { $parts[] = ($x['family'] ?? '') . ' ' . ($x['status'] ?? '') . (isset($x['latency_ms']) ? ' ' . round((float)$x['latency_ms'], 1) . ' ms' : '') . (!empty($x['message']) ? ' (' . $x['message'] . ')' : ''); } $msg = implode(' | ', $parts); }
		$out['results'][] = array('source' => $label, 'ok' => !empty($r['ok']), 'message' => trim($msg));
	}
	if ($t['status'] === 'ok' && empty($res['applied'])) {
		$c = hc2_check($userid, $t['token']);
		if ($c) {
			$fields = array('execution' => $t['target_execution'], 'locations' => $t['locations']);
			if ($t['target_execution'] !== 'online') { $fields['node_id'] = $t['node_id']; }
			hc2_set_check($userid, $t['token'], $fields);
		}
		$pdo->prepare("UPDATE hc2_testruns SET result = JSON_SET(COALESCE(result,'{}'), '$.applied', true) WHERE id = :i")->execute(array('i' => $id));
		$out['applied'] = true;
	}
	if ($t['status'] === 'expired') { $out['error'] = 'Keine Antwort innerhalb von 60 s (Node offline oder Standort nicht erreichbar).'; }
	return $out;
}

/** Kommando an eine Node (hc2_commands). */
function hc2_command(string $nodeId, string $name, array $args = array()): int {
	$pdo = hc2_pdo();
	$pdo->prepare("INSERT INTO hc2_commands (node_id, name, args, created_at) VALUES (:n, :c, :a, UTC_TIMESTAMP(3))")
		->execute(array('n' => $nodeId, 'c' => $name, 'a' => json_encode($args ?: new stdClass(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)));
	$id = (int)$pdo->lastInsertId();
	hc2_signal('hc2:node:' . $nodeId, 'command');
	return $id;
}

// ---------------------------------------------------------------- Kanaele (Benachrichtigungen)

/** Kanaltypen mit Feldern (wie Fields in der Node). secret => verschluesselt gespeichert. */
function hc2_channel_types(): array {
	return array(
		'ipv64_mail' => array('label' => 'E-Mail (ipv64)', 'icon' => 'fa-envelope', 'verify' => true, 'fields' => array(
			array('key' => 'email', 'label' => 'E-Mail-Adresse', 'required' => true, 'kind' => 'email'))),
		'ipv64_sms' => array('label' => 'SMS (ipv64)', 'icon' => 'fa-mobile-screen', 'verify' => true, 'fields' => array(
			array('key' => 'number', 'label' => 'Mobilnummer (nur Ziffern, mit Ländervorwahl, z. B. 491771234567)', 'required' => true, 'kind' => 'text'))),
		'app' => array('label' => 'IPv64 App (Push)', 'icon' => 'fa-bell', 'fields' => array(
			array('key' => 'device_token', 'label' => 'Geräte-Token aus der App', 'required' => true, 'secret' => true, 'kind' => 'password'))),
		'telegram' => array('label' => 'Telegram', 'icon' => 'fa-paper-plane', 'fields' => array(
			array('key' => 'bot_token', 'label' => 'Bot-Token', 'required' => true, 'secret' => true, 'kind' => 'password'), array('key' => 'chat_id', 'label' => 'Chat-ID', 'required' => true, 'kind' => 'text'),
			array('key' => 'silent', 'label' => 'Lautlos senden', 'kind' => 'bool'))),
		'discord' => array('label' => 'Discord', 'icon' => 'fa-comments', 'fields' => array(
			array('key' => 'webhook_url', 'label' => 'Webhook-URL', 'required' => true, 'secret' => true, 'kind' => 'password'), array('key' => 'username', 'label' => 'Anzeigename (optional)', 'kind' => 'text'))),
		'ntfy' => array('label' => 'ntfy', 'icon' => 'fa-bullhorn', 'fields' => array(
			array('key' => 'server', 'label' => 'Server', 'required' => true, 'kind' => 'url', 'default' => 'https://ntfy.sh'), array('key' => 'topic', 'label' => 'Topic', 'required' => true, 'kind' => 'text'),
			array('key' => 'token', 'label' => 'Zugriffs-Token (optional)', 'secret' => true, 'kind' => 'password'), array('key' => 'user', 'label' => 'Benutzer (optional)', 'kind' => 'text'), array('key' => 'password', 'label' => 'Passwort (optional)', 'secret' => true, 'kind' => 'password'),
			array('key' => 'priority_down', 'label' => 'Priorität bei Störung', 'kind' => 'select', 'options' => array('1','2','3','4','5'), 'default' => '4'), array('key' => 'priority_up', 'label' => 'Priorität bei Entwarnung', 'kind' => 'select', 'options' => array('1','2','3','4','5'), 'default' => '3'))),
		'gotify' => array('label' => 'Gotify', 'icon' => 'fa-bullhorn', 'fields' => array(
			array('key' => 'server', 'label' => 'Server-URL', 'required' => true, 'kind' => 'url'), array('key' => 'app_token', 'label' => 'App-Token', 'required' => true, 'secret' => true, 'kind' => 'password'), array('key' => 'priority', 'label' => 'Priorität', 'kind' => 'number', 'default' => '5'))),
		'pushover' => array('label' => 'Pushover', 'icon' => 'fa-bell', 'fields' => array(
			array('key' => 'user_key', 'label' => 'User-Key', 'required' => true, 'secret' => true, 'kind' => 'password'), array('key' => 'app_token', 'label' => 'App-Token', 'required' => true, 'secret' => true, 'kind' => 'password'), array('key' => 'device', 'label' => 'Gerät (optional)', 'kind' => 'text'),
			array('key' => 'priority_down', 'label' => 'Priorität bei Störung', 'kind' => 'select', 'options' => array('-2','-1','0','1','2'), 'default' => '1'), array('key' => 'priority_up', 'label' => 'Priorität bei Entwarnung', 'kind' => 'select', 'options' => array('-2','-1','0','1','2'), 'default' => '0'))),
		'webhook' => array('label' => 'Webhook', 'icon' => 'fa-link', 'fields' => array(
			array('key' => 'url', 'label' => 'URL', 'required' => true, 'kind' => 'url'), array('key' => 'method', 'label' => 'Methode', 'kind' => 'select', 'options' => array('POST','PUT','GET'), 'default' => 'POST'),
			array('key' => 'headers', 'label' => 'Zusätzliche Header (eine je Zeile: Name: Wert)', 'kind' => 'textarea', 'secret' => true), array('key' => 'body', 'label' => 'Eigener Body (leer = JSON-Standard)', 'kind' => 'textarea'),
			array('key' => 'insecure_tls', 'label' => 'TLS-Fehler ignorieren', 'kind' => 'bool'))),
		'smtp' => array('label' => 'Eigener SMTP-Server', 'icon' => 'fa-envelope-open', 'fields' => array(
			array('key' => 'host', 'label' => 'Host', 'required' => true, 'kind' => 'text'), array('key' => 'port', 'label' => 'Port', 'kind' => 'number', 'default' => '587'),
			array('key' => 'security', 'label' => 'Verschlüsselung', 'kind' => 'select', 'options' => array('starttls','tls','none'), 'default' => 'starttls'),
			array('key' => 'user', 'label' => 'Benutzer', 'kind' => 'text'), array('key' => 'password', 'label' => 'Passwort', 'secret' => true, 'kind' => 'password'),
			array('key' => 'from', 'label' => 'Absender', 'required' => true, 'kind' => 'email'), array('key' => 'to', 'label' => 'Empfänger', 'required' => true, 'kind' => 'email'))),
	);
}

/** Kanaele des Accounts (Konfiguration entschluesselt, Geheimnisse als '' + has_secret-Liste). */
function hc2_channels(int $userid, bool $withSecrets = false): array {
	$st = hc2_pdo()->prepare("SELECT * FROM hc2_channels WHERE userid = :u AND deleted_at IS NULL ORDER BY name, id");
	$st->execute(array('u' => $userid));
	$out = array();
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $ch) {
		$cfg = json_decode((string)$ch['config_enc'], true) ?: array();
		$ch['config'] = array(); $ch['has_secret'] = array();
		foreach ($cfg as $k => $v) {
			if (is_string($v) && strncmp($v, 'enc:v1:', 7) === 0) { $ch['has_secret'][] = $k; $ch['config'][$k] = $withSecrets ? hc2_decrypt($v) : ''; }
			else { $ch['config'][$k] = $v; }
		}
		$ch['execution'] = $ch['node_id'] ? 'node' : 'server';
		$out[] = $ch;
	}
	return $out;
}
function hc2_channel(int $userid, int $id, bool $withSecrets = false): ?array {
	foreach (hc2_channels($userid, $withSecrets) as $ch) { if ((int)$ch['id'] === $id) { return $ch; } }
	return null;
}

/** Formular -> Konfiguration (Geheimnisse verschluesselt); liefert array('config_enc'=>json,'errors'=>[]). */
function hc2_channel_config(string $type, array $in, ?array $old): array {
	$types = hc2_channel_types(); $err = array(); $cfg = array();
	if (!isset($types[$type])) { return array('config_enc' => '{}', 'errors' => array('Unbekannter Kanaltyp.')); }
	foreach ($types[$type]['fields'] as $f) {
		$k = $f['key']; $v = $in['f_' . $k] ?? null;
		if (($f['kind'] ?? '') === 'bool') { if (!empty($v) && $v !== '0') { $cfg[$k] = 'true'; } continue; }
		$v = $v === null ? '' : trim((string)$v);
		if (($f['kind'] ?? '') === 'select' && !in_array($v, $f['options'], true)) { $v = $f['default'] ?? $f['options'][0]; }
		if ($v === '' && !empty($f['secret']) && $old && in_array($k, $old['has_secret'], true)) { $v = (string)($old['config'][$k] ?? ''); } // leer = unveraendert lassen
		if ($v === '' && isset($f['default'])) { $v = $f['default']; }
		if ($v === '' && !empty($f['required'])) { $err[] = $f['label'] . ' fehlt.'; }
		if ($v !== '' && ($f['kind'] ?? '') === 'email' && !filter_var($v, FILTER_VALIDATE_EMAIL)) { $err[] = $f['label'] . ' ist keine gültige E-Mail-Adresse.'; }
		if ($v !== '' && ($f['kind'] ?? '') === 'url' && !preg_match('#^https?://#i', $v)) { $err[] = $f['label'] . ' muss mit http:// oder https:// beginnen.'; }
		if ($type === 'ipv64_sms' && $k === 'number') { $v = preg_replace('/[^0-9]/', '', $v); if (strlen($v) < 6 || strlen($v) > 20) { $err[] = 'Mobilnummer ungültig.'; } }
		if ($v !== '') { $cfg[$k] = !empty($f['secret']) ? hc2_encrypt($v) : $v; }
	}
	return array('config_enc' => json_encode($cfg ?: new stdClass(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 'errors' => $err);
}

/** Signierter Aufruf an den hub (Portal-Endpunkte). Liefert array('ok'=>bool,'error'=>'',...). */
function hc2_hub_call(string $path, array $body): array {
	$secret = is_file(HC2_BRIDGE_SECRET_FILE) ? trim((string)file_get_contents(HC2_BRIDGE_SECRET_FILE)) : '';
	if ($secret === '') { return array('ok' => false, 'error' => 'Portal-Schlüssel fehlt (hc2_bridge.secret).'); }
	$body['ts'] = time();
	$raw = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	$sig = hash_hmac('sha256', $raw, $secret);
	$last = 'kein hub erreichbar';
	foreach (explode(',', HC2_HUBS) as $hub) {
		$ch = curl_init(trim($hub) . $path);
		curl_setopt_array($ch, array(CURLOPT_POST => true, CURLOPT_POSTFIELDS => $raw, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_CONNECTTIMEOUT => 5,
			CURLOPT_HTTPHEADER => array('Content-Type: application/json', 'X-HC2-Signature: ' . $sig, 'User-Agent: ipv64-portal')));
		$res = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $cerr = curl_error($ch); curl_close($ch);
		if ($res === false || $code === 502 || $code === 503 || $code === 504) { $last = $cerr !== '' ? $cerr : ('HTTP ' . $code); continue; }
		$j = json_decode((string)$res, true);
		if (!is_array($j)) { return array('ok' => false, 'error' => 'Unerwartete Antwort (HTTP ' . $code . ')'); }
		if ($code >= 400 && !isset($j['ok'])) { return array('ok' => false, 'error' => (string)($j['error'] ?? ('HTTP ' . $code))); }
		return $j;
	}
	return array('ok' => false, 'error' => $last);
}

/** Einstellungen des Accounts (hc2_settings) lesen/schreiben. */
function hc2_settings(int $userid): array {
	$st = hc2_pdo()->prepare("SELECT `key`, `value` FROM hc2_settings WHERE userid = :u"); $st->execute(array('u' => $userid));
	$o = array(); foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $o[$r['key']] = $r['value']; }
	return $o;
}
function hc2_set_setting(int $userid, string $key, string $value): void {
	hc2_pdo()->prepare("INSERT INTO hc2_settings (userid, `key`, `value`) VALUES (:u, :k, :v) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)")->execute(array('u' => $userid, 'k' => $key, 'v' => mb_substr($value, 0, 500)));
}

/** Kleine Seitenkopf-Navigation der neuen Seiten (kein Eintrag im Hauptmenue). */
function hc2_subnav(string $active): string {
	$items = array('index' => array(HC2_BASE . '/', 'fa-heart-pulse', 'Healthchecks'), 'incidents' => array(HC2_BASE . '/incidents.php', 'fa-triangle-exclamation', 'Störungen'),
		'maintenance' => array(HC2_BASE . '/maintenance.php', 'fa-wrench', 'Wartungsfenster'), 'notifications' => array('/notifications.php', 'fa-bell', 'Benachrichtigungen'), 'nodes' => array('/nodes.php', 'fa-server', 'Nodes'));
	$o = '<ul class="nav nav-pills mb-3">';
	foreach ($items as $k => [$href, $ico, $label]) { $o .= '<li class="nav-item"><a class="nav-link' . ($k === $active ? ' active' : '') . '" href="' . $href . '"><i class="fa-solid ' . $ico . '"></i> ' . $label . '</a></li>'; }
	return $o . '</ul>';
}

/** Pillen fuer viele Checks auf einmal (eine Abfrage, Fensterfunktion). Liefert token => HTML. */
function hc2_pills_many(array $tokens, int $n, array $nodes): array {
	$out = array();
	if (!$tokens) { return $out; }
	$ph = implode(',', array_fill(0, count($tokens), '?'));
	$st = hc2_pdo()->prepare("SELECT token, source, time, status, latency_ms, reason, message FROM (SELECT token, source, time, status, latency_ms, reason, message, ROW_NUMBER() OVER (PARTITION BY token ORDER BY time DESC) rn FROM hc2_measurements WHERE token IN ($ph) AND time > UTC_TIMESTAMP() - INTERVAL 7 DAY) x WHERE rn <= " . (int)$n . " ORDER BY token, time DESC");
	$st->execute(array_values($tokens));
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $m) {
		$cls = (int)$m['status'] === 1 ? 'little-bar-green' : 'little-bar-danger';
		$tip = hc2_dt($m['time'], 'd.m. H:i:s') . ' · ' . hc2_source_label($m['source'], $nodes) . ' · ' . ((int)$m['status'] === 1 ? 'OK' : hc2_reason_text($m['reason'])) . ((float)$m['latency_ms'] > 0 ? ' · ' . round((float)$m['latency_ms'], 1) . ' ms' : '');
		$out[$m['token']] = '<div class="beat2 gros-bar ' . $cls . '" data-toggle="tooltip" data-placement="top" title="' . hc2_h($tip) . '"></div>' . ($out[$m['token']] ?? '');
	}
	return $out;
}

// Ablaufdatum des HTTPS-Zertifikats aus Meldungen ("cert valid until JJJJ-MM-TT"), frühestes gewinnt
function hc2_cert_until($messages) {
	$best = null;
	foreach ((array)$messages as $m) {
		if (preg_match_all('/cert valid until (\d{4}-\d{2}-\d{2})/', (string)$m, $mm)) {
			foreach ($mm[1] as $d) { if ($best === null || $d < $best) { $best = $d; } }
		}
	}
	return $best;
}
function hc2_cert_badge($until) {
	if ($until === null) { return ''; }
	$days = (int)floor((strtotime($until . ' 00:00:00 UTC') - time()) / 86400);
	$cls = $days <= 7 ? 'danger' : ($days <= 21 ? 'warning' : 'success');
	return '<span class="badge badge-' . $cls . '" title="Zertifikat gültig bis ' . hc2_h(date('d.m.Y', strtotime($until))) . '"><i class="fa-solid fa-lock"></i> noch ' . $days . ' Tage</span>';
}
