<?php
// ---------------------------------------------------------------------------
// Healthchecks 2.0 (hc2): Hilfsfunktionen fuer das Portal. Diesen Block ANS ENDE
// von dbconnect.php anhaengen (falls die Datei mit einem schliessenden PHP-Tag endet: davor), nichts anderes
// aendern. Alle Funktionen sind fehlertolerant: scheitert Redis, laeuft alles
// weiter (der hub pollt hc2_config_log alle 2 s).
// ---------------------------------------------------------------------------

defined('HC2_DB')           || define('HC2_DB', 'ipv64_hc');          // neue Datenbank, gleicher MySQL-Server
defined('HC2_DB_HOST')      || define('HC2_DB_HOST', 'localhost');
defined('HC2_DB_USER')      || define('HC2_DB_USER', 'ipv64_hc');
defined('HC2_DB_PASS_FILE') || define('HC2_DB_PASS_FILE', '/var/www/clients/client1/web58/private/hc2_db.pass'); // Passwort von ipv64_hc, eine Zeile
defined('HC2_REDIS_HOST')   || define('HC2_REDIS_HOST', '10.10.0.11');  // Redis auf hc-srv02 (Nuernberg), privates Netz
defined('HC2_REDIS_PORT')   || define('HC2_REDIS_PORT', 6379);
defined('HC2_REDIS_PASS_FILE') || define('HC2_REDIS_PASS_FILE', '/var/www/clients/client1/web58/private/hc2_redis.pass'); // Inhalt von /etc/ipv64-hub/redis.pass
defined('HC2_KEY_FILE')     || define('HC2_KEY_FILE', '/var/www/clients/client1/web58/private/hc2_secret.key');      // 32 Rohbytes, identisch mit secret.key auf den hubs

/**
 * Eigene Verbindung zur hc2-Datenbank mit dem Benutzer ipv64_hc (darf ipv64_hc schreiben und ipv64 lesen).
 * Der Portal-Benutzer braucht so keine zusaetzlichen Rechte. Wird erst beim ersten Aufruf geoeffnet.
 */
function hc2_pdo(): PDO {
	static $hc = null;
	if ($hc === null) {
		$pass = is_file(HC2_DB_PASS_FILE) ? trim((string)file_get_contents(HC2_DB_PASS_FILE)) : '';
		$hc = new PDO('mysql:host=' . HC2_DB_HOST . ';dbname=' . HC2_DB . ';charset=utf8mb4', HC2_DB_USER, $pass,
			array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5));
	}
	return $hc;
}

/** Naechste Revision eines Accounts (streng steigend je Account). */
function hc2_next_revision(int $userid): int {
	$db = HC2_DB; $pdo = hc2_pdo();
	$pdo->prepare("INSERT INTO `$db`.hc2_revisions (userid, next) VALUES (:u, 2) ON DUPLICATE KEY UPDATE next = next + 1")->execute(array('u' => $userid));
	$st = $pdo->prepare("SELECT next - 1 FROM `$db`.hc2_revisions WHERE userid = :u"); $st->execute(array('u' => $userid));
	return (int)$st->fetchColumn();
}

/**
 * Konfigurationsaenderung protokollieren: schreibt die Revision an die Entitaet, eine Zeile ins
 * Config-Log und schickt das Redis-Signal. Aufruf NACH dem eigentlichen UPDATE/INSERT/DELETE
 * (alles ueber hc2_pdo(), eigene Verbindung).
 *   $entity: check | channel | maintenance | node | settings
 *   $op:     upsert | delete
 * Liefert die vergebene Revision.
 */
function hc2_log_change(int $userid, string $entity, string $entityId, string $op = 'upsert', string $origin = 'portal', ?string $agentId = null): int {
	$db = HC2_DB; $pdo = hc2_pdo();
	$rev = hc2_next_revision($userid);
	$tables = array('check' => array('hc2_checks', 'token'), 'channel' => array('hc2_channels', 'id'), 'maintenance' => array('hc2_maintenance', 'id'));
	if (isset($tables[$entity])) {
		[$t, $col] = $tables[$entity];
		$sql = $op === 'delete'
			? "UPDATE `$db`.$t SET revision = :r, deleted_at = UTC_TIMESTAMP(3), updated_at = UTC_TIMESTAMP(3) WHERE $col = :id AND userid = :u"
			: "UPDATE `$db`.$t SET revision = :r, updated_at = UTC_TIMESTAMP(3) WHERE $col = :id AND userid = :u";
		$pdo->prepare($sql)->execute(array('r' => $rev, 'id' => $entityId, 'u' => $userid));
	}
	$pdo->prepare("INSERT INTO `$db`.hc2_config_log (userid, node_id, entity, entity_id, op, revision, origin, time) VALUES (:u, :a, :e, :i, :o, :r, :g, UTC_TIMESTAMP(3))")
		->execute(array('u' => $userid, 'a' => $agentId, 'e' => $entity, 'i' => $entityId, 'o' => $op, 'r' => $rev, 'g' => $origin));
	hc2_signal('hc2:cfg:' . $userid, (string)$rev);
	return $rev;
}

/** Redis-Signal an den hub; Fehler werden nur geloggt. */
function hc2_signal(string $channel, string $message): void {
	static $redis = null, $failed = false;
	if ($failed || !class_exists('Redis')) { return; }
	try {
		if ($redis === null) {
			$pass = is_file(HC2_REDIS_PASS_FILE) ? trim((string)file_get_contents(HC2_REDIS_PASS_FILE)) : '';
			$redis = connectRedis(HC2_REDIS_HOST, HC2_REDIS_PORT, $pass, 0.5);
		}
		$redis->publish($channel, $message);
	} catch (Throwable $e) {
		$failed = true;   // in diesem Request nicht erneut versuchen
		error_log('hc2_signal: ' . $e->getMessage());
	}
}

/**
 * Heartbeat eines Push-Checks der neuen Welt (health.php). Liefert true, wenn der Token zu einem
 * hc2-Check gehoert; dann hat health.php nichts mehr zu tun. Alte Tokens (nicht in hc2_checks) -> false,
 * alte Logik laeuft unveraendert. Unbekannte Tokens werden hier NICHT verraten (false wie "alt").
 */
function hc2_push(string $token, array $get): bool {
	if ($token === '' || !preg_match('/^[A-Za-z0-9]{20,50}$/', $token)) { return false; }
	try {
		$db = HC2_DB; $pdo = hc2_pdo();
		$st = $pdo->prepare("SELECT token, paused FROM `$db`.hc2_checks WHERE token = :t AND type = 'push' AND deleted_at IS NULL");
		$st->execute(array('t' => $token));
		$row = $st->fetch(PDO::FETCH_ASSOC);
		if (!$row) { return false; }
		$down = (isset($get['status']) && strtolower((string)$get['status']) === 'down') || isset($get['fail']);
		$msg = mb_substr((string)($get['msg'] ?? $get['message'] ?? ''), 0, 500);
		$details = json_encode(array('from' => $_SERVER['REMOTE_ADDR'] ?? '', 'via' => 'health.php'));
		$pdo->prepare("INSERT IGNORE INTO `$db`.hc2_measurements (token, source, node_seq, time, status, latency_ms, reason, message, details, received_at)
			VALUES (:t, 'push', 0, UTC_TIMESTAMP(3), :s, 0, :r, :m, :d, UTC_TIMESTAMP(3))")
			->execute(array('t' => $row['token'], 's' => $down ? 0 : 1, 'r' => $down ? 'push_down' : '', 'm' => $msg, 'd' => $details));
		$pdo->prepare("UPDATE `$db`.hc2_checks SET last_push_at = UTC_TIMESTAMP(3) WHERE token = :t")->execute(array('t' => $row['token']));
		hc2_signal('hc2:push', $row['token'] . ($down ? ':down' : ':up'));
		return true;
	} catch (Throwable $e) {
		error_log('hc2_push: ' . $e->getMessage());
		return false;
	}
}

/** Verschluesselung kompatibel zum Node/hub (AES-256-GCM, "enc:v1:" + Base64 ohne Padding). */
/** Schluessel lesen: 64 Hex-Zeichen (Textdatei, kopierbar) oder 32 Rohbytes. */
function hc2_key_bytes(): string {
	$raw = is_file(HC2_KEY_FILE) ? (string)file_get_contents(HC2_KEY_FILE) : '';
	$t = trim($raw);
	if (strlen($t) === 64 && ctype_xdigit($t)) { return (string)hex2bin($t); }
	return $raw;
}
function hc2_encrypt(string $plain): string {
	if ($plain === '') { return ''; }
	$key = hc2_key_bytes();
	if (strlen($key) !== 32) { throw new RuntimeException('hc2: Schluesseldatei fehlt oder ist ungueltig (64 Hex-Zeichen erwartet)'); }
	$nonce = random_bytes(12); $tag = '';
	$ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
	return 'enc:v1:' . rtrim(base64_encode($nonce . $ct . $tag), '=');
}
function hc2_decrypt(string $value): string {
	if (strncmp($value, 'enc:v1:', 7) !== 0) { return $value; }
	$key = hc2_key_bytes();
	$raw = base64_decode(substr($value, 7) . str_repeat('=', (4 - strlen(substr($value, 7)) % 4) % 4));
	if ($raw === false || strlen($raw) < 28 || strlen($key) !== 32) { return ''; }
	$plain = openssl_decrypt(substr($raw, 12, -16), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, -16));
	return $plain === false ? '' : $plain;
}
