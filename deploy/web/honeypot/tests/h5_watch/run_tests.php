<?php
/**
 * Pruefung von H5 Fruehwarnung + Limits in der Testumgebung hp5w-* (run_agentbox.sh): api_v2_threat_watch.php
 * (GET/POST/DELETE /threat/watch, GET /threat/watch/alerts), honeypot/watch.php, bots/honeypot_watch.php,
 * honeypot/hp_limits_lib.php und die Aenderung in api_v2_honeypot.php (Dienst vpn, Sensor-Limit je Klasse).
 * Spricht Seite und API ueber den PHP-Builtin-Server an (mit Sitzungs-Cookies), prueft Tabellen direkt und liest die
 * Mails aus /w/mail.log (Stub von send_mail()).
 *
 *   HP5WTEST=1 php run_tests.php http://127.0.0.1:8080 /w/web
 */
if(php_sapi_name() !== 'cli' OR getenv('HP5WTEST') !== '1') { exit; }

$BASE = rtrim($argv[1] ?? 'http://127.0.0.1:8080', '/');
$WEB = $argv[2] ?? '/w/web';
const K1 = 'TestKeyAccountOne000000000000001';   // users.apikey, Account 1 (Standard)
const K2 = 'TestKeyApiKeysTwo000000000000002';   // api_keys, Account 2 (VIP)
const K3 = 'TestKeyAccountThree0000000000003';   // Account 3, inaktiv
const MAIL_LOG = '/w/mail.log';

$db = new PDO('mysql:host=hp5w-db;dbname=ipv64', 'root', 'hp5wtest', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"));
$pass = 0; $failed = 0;
$JARS = array();

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . (is_string($info) ? substr($info, 0, 700) : substr(json_encode($info, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 0, 700)) . "\n"; }
}

/** HTTP-Anfrage. $o: ip (X-Forwarded-For), key, json (array), form (array), body (roh), ctype, jar (Name der Cookie-Dose) */
function req(string $method, string $path, array $o = array()): array {
	global $BASE, $JARS;
	$h = array('X-Forwarded-For: ' . ($o['ip'] ?? '84.200.9.9'));
	if(isset($o['key'])) { $h[] = 'Authorization: Bearer ' . $o['key']; }
	$jar = $o['jar'] ?? null;
	if($jar !== null AND !empty($JARS[$jar])) { $h[] = 'Cookie: ' . implode('; ', array_map(fn($k, $v) => "$k=$v", array_keys($JARS[$jar]), $JARS[$jar])); }
	$body = '';
	if(isset($o['json'])) { $body = json_encode($o['json'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); $h[] = 'Content-Type: application/json'; }
	if(isset($o['form'])) { $body = http_build_query($o['form']); $h[] = 'Content-Type: application/x-www-form-urlencoded'; }
	if(isset($o['body'])) { $body = $o['body']; $h[] = 'Content-Type: ' . ($o['ctype'] ?? 'application/json'); }
	$ctx = stream_context_create(array('http' => array('method' => $method, 'header' => implode("\r\n", $h), 'content' => $body, 'ignore_errors' => true, 'timeout' => 60)));
	$t = microtime(true);
	$raw = @file_get_contents($BASE . $path, false, $ctx);
	$code = 0; $hdr = array();
	foreach($http_response_header ?? array() as $l) {
		if(preg_match('#^HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
		elseif(stripos($l, 'Set-Cookie:') === 0 AND $jar !== null) { if(preg_match('/^Set-Cookie:\s*([^=]+)=([^;]*)/i', $l, $m)) { $JARS[$jar][$m[1]] = $m[2]; } }
		elseif(str_contains($l, ':')) { [$k, $v] = explode(':', $l, 2); $hdr[strtolower(trim($k))] = trim($v); }
	}
	return array('code' => $code, 'h' => $hdr, 'j' => json_decode((string)$raw, true), 'raw' => (string)$raw, 'ms' => (int)round((microtime(true) - $t) * 1000));
}
function api(string $method, string $path, array $o = array()): array { return req($method, '/api_v2.php' . $path, $o); }
function csrf(string $html): string { return preg_match('/name="csrf" value="([0-9a-f]{32})"/', $html, $m) ? $m[1] : ''; }
function one(string $sql, array $p = array()) { global $db; $st = $db->prepare($sql); $st->execute($p); return $st->fetch(PDO::FETCH_ASSOC); }
function all(string $sql, array $p = array()): array { global $db; $st = $db->prepare($sql); $st->execute($p); return $st->fetchAll(PDO::FETCH_ASSOC); }
function exec_sql(string $sql, array $p = array()): void { global $db; $db->prepare($sql)->execute($p); }
function code(array $r): string { return $r['code'] . ' ' . substr($r['raw'], 0, 400); }
function mails(): array { return is_file(MAIL_LOG) ? array_map(fn($l) => json_decode($l, true), array_values(array_filter(explode("\n", (string)file_get_contents(MAIL_LOG))))) : array(); }
function utc(int $off): string { return gmdate('Y-m-d H:i:s', time() + $off); }
function iso(int $ts): string { return gmdate('Y-m-d\TH:i:s\Z', $ts); }
/** Zeile in hp_scores (Ergebnis der Bewertung) */
function score(string $ip, int $listed, int $score = 60, int $last = -3600, ?int $since = null, string $kinds = 'ssh:bruteforce'): void {
	$b = inet_pton($ip);
	exec_sql("REPLACE INTO hp_scores (ip_bin, ip, family, score, accounts, accounts_eff, strong_eff, sensors, events, kinds, lists, first_seen, last_seen, listed, listed_since, reason, updated_at)
		VALUES (?, ?, ?, ?, 2, 2, 2, 2, 10, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())",
		array($b, inet_ntop($b), strlen($b) === 4 ? 4 : 6, $score, $kinds, $listed ? 'v64,ssh' : '', utc($last - 86400), utc($last), $listed, $listed ? utc($since ?? -86400) : null, $listed ? 'threshold' : ''));
}
function cron(string $args = ''): string { global $WEB; return (string)shell_exec('cd ' . escapeshellarg($WEB . '/bots') . ' && HP5WTEST=1 php honeypot_watch.php ' . $args . ' 2>&1'); }
function alerts(int $u): array { return all("SELECT * FROM hp_watch_alerts WHERE userid = ? ORDER BY id", array($u)); }
function by_ip(array $rows): array { $o = array(); foreach($rows as $r) { $o[$r['ip']][] = $r; } return $o; }
/** Meldung im Format schema 1 (Zeitraum: die letzten 10 Minuten) */
function hp_uuid(): string { $b = random_bytes(16); $b[6] = chr((ord($b[6]) & 0x0f) | 0x40); $b[8] = chr((ord($b[8]) & 0x3f) | 0x80); return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4)); }
function report(string $sid, array $sources = array(), int $end = 0): array {
	$end = $end ?: time() - 5; $start = $end - 600;
	if(!$sources) { $sources = array(array('ip' => '45.8.8.1', 'kind' => 'ssh:bruteforce', 'service' => 'ssh', 'port' => 22, 'count' => 3, 'first' => iso($start + 10), 'last' => iso($start + 20), 'source' => 'honeypot')); }
	return array('schema' => 1, 'report_id' => "$sid-$start", 'sensor' => array('id' => $sid, 'version' => '0.13.0', 'profile' => 'standard', 'mode' => 'headless'),
		'period' => array('start' => iso($start), 'end' => iso($end)), 'sources' => $sources);
}
function post_report(array $r, string $key, string $ip = '84.201.1.1'): array { return api('POST', '/honeypot/reports', array('key' => $key, 'json' => $r, 'ip' => $ip)); }
function sensors(int $u, int $n, int $lastOff): void { for($i = 0; $i < $n; $i++) { exec_sql("INSERT INTO hp_sensors (sensor_id, userid, first_seen, last_seen) VALUES (?, ?, UTC_TIMESTAMP(), ?)", array(hp_uuid(), $u, utc($lastOff))); } }

@unlink(MAIL_LOG);

// ---------------------------------------------------------------- SQL
echo "SQL\n";
$t = array_column(all("SHOW TABLES LIKE 'hp\\_watch%'"), null);
check('Tabellen hp_watch, hp_watch_alerts (zweimal eingespielt)', count($t) === 2, $t);
$idx = array_unique(array_column(all("SHOW INDEX FROM hp_watch_alerts"), 'Key_name'));
check('Indizes hp_watch_alerts', !array_diff(array('PRIMARY', 'user_created', 'user_ip', 'mail', 'created'), $idx), $idx);
$idx = array_unique(array_column(all("SHOW INDEX FROM hp_watch"), 'Key_name'));
check('Indizes hp_watch (user_cidr eindeutig, range)', !array_diff(array('PRIMARY', 'user_cidr', 'range'), $idx), $idx);

// ---------------------------------------------------------------- API /threat/watch
echo "API GET/POST/DELETE /threat/watch\n";
$r = api('GET', '/threat/watch');
check('ohne Key 401', $r['code'] === 401, code($r));
$r = api('GET', '/threat/watch', array('key' => K3));
check('inaktiver Account 401', $r['code'] === 401, code($r));
$r = api('GET', '/threat/watch', array('key' => K1));
$d = $r['j']['data'] ?? array();
check('Standard: 200, Limits 3 / 16 / 32', $r['code'] === 200 AND ($d['limits'] ?? null) === array('max' => 3, 'min_prefix_v4' => 16, 'min_prefix_v6' => 32), code($r));
check('noch keine Netze', ($d['networks'] ?? null) === array(), $d);
check('DynDNS: nur aktive, oeffentliche A/AAAA ohne CDN-Hilfseintrag, nach Domain sortiert, getrimmt',
	($d['dyndns'] ?? null) === array(array('ip' => '45.9.9.9', 'domain' => 'home.ipv64.net'), array('ip' => '2a0b:4d07:1::9', 'domain' => 'nas.home.ipv64.net'), array('ip' => '45.1.1.50', 'domain' => 'office.ipv64.net')), $d['dyndns'] ?? null);
check('RateLimit wie /threat/ip mit Key (120)', ($r['h']['ratelimit-limit'] ?? '') === '120', $r['h']);
$r = api('GET', '/threat/watch', array('key' => K2));
check('VIP: Limit 50', ($r['j']['data']['limits']['max'] ?? 0) === 50, code($r));

$bad = array('abc' => 'invalid_cidr', '45.1.1.0/33' => 'invalid_cidr', '45.1.1.0/x' => 'invalid_cidr', '45.1.1.0/24/1' => 'invalid_cidr', 'fe80::1%eth0/64' => 'invalid_cidr',
	'45.0.0.0/15' => 'prefix_too_large', '0.0.0.0/0' => 'prefix_too_large', '2a0b::/31' => 'prefix_too_large',
	'10.1.0.0/16' => 'not_public', '192.168.1.0/24' => 'not_public', '100.64.5.0/24' => 'not_public', '2001:db8::/48' => 'not_public', '::ffff:45.1.1.0/120' => 'not_public', 'fd00::/48' => 'not_public');
foreach($bad as $in => $want) {
	$r = api('POST', '/threat/watch', array('key' => K1, 'json' => array('cidr' => $in, 'label' => 'x')));
	check("'$in' -> 422 $want", $r['code'] === 422 AND ($r['j']['code'] ?? '') === $want AND ($r['j']['field'] ?? '') === 'cidr', code($r));
}
$r = api('POST', '/threat/watch', array('key' => K1, 'json' => array('label' => 'x')));
check('ohne cidr -> 422 missing_field', $r['code'] === 422 AND ($r['j']['code'] ?? '') === 'missing_field', code($r));
$r = api('POST', '/threat/watch', array('key' => K1, 'json' => array('cidr' => '45.1.1.0/24', 'label' => str_repeat('x', 101))));
check('Bezeichnung > 100 Zeichen -> 422', $r['code'] === 422, code($r));
check('Fehler als problem+json', str_starts_with($r['h']['content-type'] ?? '', 'application/problem+json'), $r['h']);

$r = api('POST', '/threat/watch', array('key' => K1, 'json' => array('cidr' => ' 45.1.1.77/24 ', 'label' => "Büro\x07")));
$n1 = $r['j']['data'] ?? array();
check('201, Host-Bits entfernt, Steuerzeichen weg', $r['code'] === 201 AND ($n1['cidr'] ?? '') === '45.1.1.0/24' AND ($n1['label'] ?? '') === 'Büro' AND ($n1['verified'] ?? null) === false, code($r));
check('Netz: genau die Felder des Vertrags', array_keys($n1) === array('id', 'cidr', 'label', 'verified', 'created_at') AND is_int($n1['id']) AND preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/', $n1['created_at']) === 1, $n1);
$row = one("SELECT HEX(ip_start) s, HEX(ip_end) e, userid FROM hp_watch WHERE id = ?", array($n1['id'] ?? 0));
check('Bereich gespeichert (4 Byte)', ($row['s'] ?? '') === '2D010100' AND $row['e'] === '2D0101FF' AND (int)$row['userid'] === 1, $row);
$r = api('POST', '/threat/watch', array('key' => K1, 'json' => array('cidr' => '45.1.1.0/24')));
check('gleiches Netz -> 409 duplicate', $r['code'] === 409 AND ($r['j']['code'] ?? '') === 'duplicate', code($r));
$r = api('POST', '/threat/watch', array('key' => K1, 'json' => array('cidr' => '2A0B:4D07:0::/48', 'label' => '')));
$n6 = $r['j']['data'] ?? array();
check('IPv6 /48 201, normalisiert', $r['code'] === 201 AND ($n6['cidr'] ?? '') === '2a0b:4d07::/48', code($r));
$row = one("SELECT HEX(ip_start) s, HEX(ip_end) e FROM hp_watch WHERE id = ?", array($n6['id'] ?? 0));
check('IPv6-Bereich (16 Byte)', ($row['s'] ?? '') === '2A0B4D07000000000000000000000000' AND $row['e'] === '2A0B4D070000FFFFFFFFFFFFFFFFFFFF', $row);
$r = api('POST', '/threat/watch', array('key' => K1, 'body' => 'cidr=46.5.5.5&label=Server', 'ctype' => 'application/x-www-form-urlencoded'));
$nS = $r['j']['data'] ?? array();
check('einzelne IP (Formular) -> /32', $r['code'] === 201 AND ($nS['cidr'] ?? '') === '46.5.5.5/32' AND $nS['label'] === 'Server', code($r));
$r = api('POST', '/threat/watch', array('key' => K1, 'json' => array('cidr' => '46.7.0.0/16')));
check('4. Netz bei Standard -> 403 limit_reached', $r['code'] === 403 AND ($r['j']['code'] ?? '') === 'limit_reached' AND ($r['j']['limit'] ?? 0) === 3, code($r));
$r = api('POST', '/threat/watch', array('key' => K1, 'json' => array('cidr' => '46.5.5.5/32')));
check('Doppel geht vor Limit (409)', $r['code'] === 409, code($r));
$r = api('POST', '/threat/watch', array('key' => K2, 'json' => array('cidr' => '46.6.0.0/16', 'label' => 'Rechenzentrum <b>')));
$nV = $r['j']['data'] ?? array();
check('VIP: Netz eingetragen; anderes Konto darf dasselbe Netz', $r['code'] === 201 AND api('POST', '/threat/watch', array('key' => K2, 'json' => array('cidr' => '45.1.1.0/24')))['code'] === 201, code($r));
exec_sql("DELETE FROM hp_watch WHERE userid = 2 AND cidr = '45.1.1.0/24'"); // nur fuer diese Pruefung
$r = api('DELETE', '/threat/watch/' . ($n1['id'] ?? 0), array('key' => K2));
check('fremdes Netz loeschen -> 404', $r['code'] === 404 AND ($r['j']['code'] ?? '') === 'not_found', code($r));
check('DELETE /threat/watch/abc -> 404', api('DELETE', '/threat/watch/abc', array('key' => K1))['code'] === 404);
check('DELETE /threat/watch/alerts -> 404', api('DELETE', '/threat/watch/alerts', array('key' => K1))['code'] === 404);
$r = api('DELETE', '/threat/watch/' . ($nS['id'] ?? 0), array('key' => K1));
check('eigenes Netz loeschen -> 204 ohne Inhalt', $r['code'] === 204 AND $r['raw'] === '', code($r));
check('nochmal -> 404', api('DELETE', '/threat/watch/' . ($nS['id'] ?? 0), array('key' => K1))['code'] === 404);
$d = api('GET', '/threat/watch', array('key' => K1))['j']['data'] ?? array();
check('GET: 2 Netze, aelteste zuerst', array_column($d['networks'] ?? array(), 'cidr') === array('45.1.1.0/24', '2a0b:4d07::/48'), $d['networks'] ?? null);
check('POST /threat/watch/alerts -> 405', api('POST', '/threat/watch/alerts', array('key' => K1, 'json' => array()))['code'] === 405);

// ---------------------------------------------------------------- Cron
echo "Cron bots/honeypot_watch.php\n";
exec_sql("UPDATE hp_watch SET verified = 1 WHERE id = ?", array($nV['id'] ?? 0));                 // Nachweis per SQL (Admin)
exec_sql("INSERT INTO hp_watch (userid, cidr, ip_start, ip_end, label, verified, created_at) VALUES (3, '45.1.1.0/24', UNHEX('2D010100'), UNHEX('2D0101FF'), 'inaktiv', 1, UTC_TIMESTAMP())");
score('45.1.1.1', 1, 80);                      // gelistet im Netz ohne Nachweis -> Treffer
score('45.1.1.2', 0, 30);                      // nur gesehen, Netz ohne Nachweis -> nichts
score('2a0b:4d07::5', 1, 55, -7200, null, 'http:exploit:traversal'); // IPv6 gelistet -> Treffer
score('2d01:101:500::1', 1, 90);               // 16 Byte, liegt bytewise zwischen 2D010100 und 2D0101FF -> nie im IPv4-Netz
score('45.9.9.9', 0, 20);                      // DynDNS (customer_ip, nicht gelistet) -> Treffer
score('2a0b:4d07:1::9', 0, 25);                // DynDNS IPv6 -> Treffer
score('45.9.9.10', 0, 20);                     // Record deaktiviert -> nichts
score('45.9.9.11', 0, 20);                     // CDN-Hilfseintrag -> nichts
score('45.1.1.50', 1, 70);                     // DynDNS und Netz zugleich -> ein Treffer (dyndns)
score('45.1.1.3', 1, 75, -5 * 86400, -5 * 86400); // alt (5 Tage) -> nichts
score('47.7.7.7', 0, 40);                      // DynDNS von 4 Accounts (geteilt) -> nichts
score('45.9.9.20', 0, 20);                     // DynDNS Account 2
for($i = 1; $i <= 106; $i++) { score('46.6.0.' . $i, 0, 10 + $i % 50); } // Netz mit Nachweis (VIP): jede Sichtung
score('46.6.1.1', 1, 95);                      // dito, gelistet -> zuerst
score('46.6.1.2', 0, 30);                      // dito, aber Server von ipv64 (reason infra) -> nie
exec_sql("UPDATE hp_scores SET reason = 'infra' WHERE ip = '46.6.1.2'");
// Rohdaten fuer die Details (warum die IP aufgefallen ist): zwei Sensoren per Honeypot, einer per Log
foreach(array(array('S1', 'honeypot', 'ssh', 22, 'ssh:bruteforce', '', 7), array('S2', 'honeypot', 'ssh', 22, 'ssh:bruteforce', '', 3), array('S3', 'log', 'http', 443, 'http:bruteforce', 'nginx/auth', 4)) as $rs) {
	exec_sql("INSERT INTO hp_report_sources (day, report_ref, userid, sensor_id, ip, ip_bin, kind, service, port, `count`, first_seen, last_seen, source, rule, detail)
		VALUES (UTC_DATE(), 1, 9, ?, '45.1.1.1', UNHEX('2D010101'), ?, ?, ?, ?, ?, ?, ?, ?, 'sni=geheim.example')", array($rs[0], $rs[4], $rs[2], $rs[3], $rs[6], utc(-7200), utc(-3600), $rs[1], $rs[5]));
}

$out = cron('--dry');
check('--dry: Zahlen, nichts geschrieben, keine Mail', str_contains($out, 'DRY RUN') AND (int)one("SELECT COUNT(*) n FROM hp_watch_alerts")['n'] === 0 AND mails() === array(), $out);
$plan = one("EXPLAIN SELECT STRAIGHT_JOIN w.id FROM hp_watch w JOIN hp_scores s ON LENGTH(w.ip_start) = LENGTH(s.ip_bin) AND w.ip_start <= s.ip_bin AND w.ip_end >= s.ip_bin");
echo "        (Plan Netze: " . json_encode(all("EXPLAIN SELECT STRAIGHT_JOIN w.id FROM hp_watch w JOIN hp_scores s ON LENGTH(w.ip_start) = LENGTH(s.ip_bin) AND w.ip_start <= s.ip_bin AND w.ip_end >= s.ip_bin"), JSON_UNESCAPED_SLASHES) . ")\n";
$plan2 = all("EXPLAIN SELECT STRAIGHT_JOIN w.id FROM hp_watch w JOIN hp_scores s ON LENGTH(w.ip_start) = LENGTH(s.ip_bin) AND w.ip_start <= s.ip_bin AND w.ip_end >= s.ip_bin");
check('Plan: hp_scores je Netz ueber den Primaerschluessel (range/Range checked)', isset($plan2[1]) AND $plan2[1]['table'] === 's' AND (str_contains((string)$plan2[1]['Extra'], 'Range checked') OR $plan2[1]['type'] === 'range'), $plan2);

$t0 = time();
$out = cron();
echo preg_replace('/^/m', '        | ', trim($out)) . "\n";
$a1 = by_ip(alerts(1));
check('Account 1: genau 5 Treffer', count(alerts(1)) === 5 AND !array_diff(array_keys($a1), array('45.1.1.1', '2a0b:4d07::5', '45.9.9.9', '2a0b:4d07:1::9', '45.1.1.50')), array_keys($a1));
$x = $a1['45.1.1.1'][0] ?? array();
check('Netz-Treffer: Netz, Bezeichnung, network_id, gelistet, Wert, Arten, Sichtungen', ($x['source'] ?? '') === 'network' AND $x['cidr'] === '45.1.1.0/24' AND $x['label'] === 'Büro'
	AND (int)$x['network_id'] === (int)$n1['id'] AND (int)$x['listed'] === 1 AND (int)$x['score'] === 80 AND $x['kinds'] === 'ssh:bruteforce' AND $x['last_seen'] !== '' AND $x['mailed_at'] !== null, $x);
$x = $a1['45.9.9.9'][0] ?? array();
check('DynDNS-Treffer (nicht gelistet): source dyndns, network_id NULL, Domain, /32', ($x['source'] ?? '') === 'dyndns' AND $x['network_id'] === null AND $x['label'] === 'home.ipv64.net' AND $x['cidr'] === '45.9.9.9/32' AND (int)$x['listed'] === 0, $x);
check('DynDNS IPv6 -> /128', ($a1['2a0b:4d07:1::9'][0]['cidr'] ?? '') === '2a0b:4d07:1::9/128' AND $a1['2a0b:4d07:1::9'][0]['label'] === 'nas.home.ipv64.net');
check('IP in DynDNS und Netz: ein Treffer, DynDNS gewinnt', count($a1['45.1.1.50'] ?? array()) === 1 AND $a1['45.1.1.50'][0]['source'] === 'dyndns' AND $a1['45.1.1.50'][0]['label'] === 'office.ipv64.net');
check('IPv6-Netz-Treffer', ($a1['2a0b:4d07::5'][0]['network_id'] ?? 0) == $n6['id'] AND $a1['2a0b:4d07::5'][0]['kinds'] === 'http:exploit:traversal');
$det = json_decode((string)($a1['45.1.1.1'][0]['details'] ?? ''), true);
check('Details: Anzahlen aus hp_scores, Herkunft/Dienst/Port/Art/Regel aus den Rohdaten, haeufigste zuerst', is_array($det) AND $det['sensors'] === 2 AND $det['accounts'] === 2
	AND $det['lists'] === array('v64', 'ssh') AND count($det['seen']) === 2 AND $det['seen'][0]['origin'] === 'honeypot' AND $det['seen'][0]['count'] === 10 AND $det['seen'][0]['sensors'] === 2
	AND $det['seen'][1]['origin'] === 'log' AND $det['seen'][1]['rule'] === 'nginx/auth' AND $det['seen'][1]['port'] === 443, $det);
check('Details verraten keine Sensoren (keine Kennung, kein Inhalt)', !str_contains((string)$a1['45.1.1.1'][0]['details'], 'S1') AND !str_contains((string)$a1['45.1.1.1'][0]['details'], 'geheim'), $a1['45.1.1.1'][0]['details'] ?? '');
check('Server von ipv64 (reason infra): kein Treffer', (int)one("SELECT COUNT(*) n FROM hp_watch_alerts WHERE ip = '46.6.1.2'")['n'] === 0);
check('nicht: nur gesehen ohne Nachweis, 16-Byte-IP zwischen IPv4-Grenzen, deaktiviert, CDN, alt', !isset($a1['45.1.1.2']) AND !isset($a1['2d01:101:500::1']) AND !isset($a1['45.9.9.10']) AND !isset($a1['45.9.9.11']) AND !isset($a1['45.1.1.3']));
check('geteilte DynDNS-IP (4 Accounts) ohne Nachweis, inaktiver Account nichts', (int)one("SELECT COUNT(*) n FROM hp_watch_alerts WHERE userid IN (3, 5, 6, 7, 8)")['n'] === 0);
$a2 = alerts(2);
check('VIP mit Nachweis: hoechstens 100 je Lauf, gelistete zuerst', count($a2) === 100 AND in_array('46.6.1.1', array_column($a2, 'ip'), true), count($a2));
check('ein Zeitstempel je Lauf', count(array_unique(array_column(all("SELECT created_at FROM hp_watch_alerts"), 'created_at'))) === 1);
$m = mails();
check('2 Mails (je Account eine, gebuendelt)', count($m) === 2, array_column($m, 'to'));
$m1 = array_values(array_filter($m, fn($x) => $x['to'] === 'a@test.invalid'))[0] ?? array();
check('Mail Account 1: Betreff mit Anzahl, alle IPs, Netz/Domain, Link IP-Auskunft und Seite', str_contains($m1['subject'] ?? '', '5 Adressen') AND str_contains($m1['text'], '45.1.1.1') AND str_contains($m1['text'], 'DynDNS home.ipv64.net')
	AND str_contains($m1['text'], '45.1.1.0/24 (Büro)') AND str_contains($m1['text'], 'honeypot/ip.php?ip=45.1.1.1') AND str_contains($m1['text'], 'honeypot/watch.php') AND str_contains($m1['text'], 'gelistet')
	AND str_contains($m1['text'], 'Honeypot ssh/22 ssh:bruteforce ×10 · Log http/443 http:bruteforce (nginx/auth) ×4 – 2 Sensoren, 2 Accounts'), $m1);
$m2 = array_values(array_filter($m, fn($x) => $x['to'] === 'b@test.invalid'))[0] ?? array();
check('Mail Account 2: hoechstens 25 IPs, Rest als Anzahl', str_contains($m2['text'] ?? '', 'und 75 weitere') AND substr_count($m2['text'], 'honeypot/ip.php?ip=') === 25, substr($m2['text'] ?? '', -300));
check('mailed_at gesetzt', (int)one("SELECT COUNT(*) n FROM hp_watch_alerts WHERE mailed_at IS NULL")['n'] === 0);
$T1 = one("SELECT created_at FROM hp_watch_alerts LIMIT 1")['created_at'];

// zweiter Lauf: keine Wiederholung; Rest des VIP-Netzes
exec_sql("UPDATE hp_watch_alerts SET created_at = created_at - INTERVAL 120 SECOND");
$T1 = gmdate('Y-m-d H:i:s', strtotime($T1 . ' UTC') - 120);
$out = cron();
check('2. Lauf: Account 1 nichts Neues (24 h)', count(alerts(1)) === 5, $out);
check('2. Lauf: VIP die restlichen 8', count(alerts(2)) === 108, count(alerts(2)));
check('2. Lauf: nur eine weitere Mail (VIP, 8 Adressen)', count(mails()) === 3 AND str_contains(mails()[2]['subject'], '8 Adressen'), array_column(mails(), 'subject'));
$T2 = one("SELECT MAX(created_at) t FROM hp_watch_alerts")['t'];

// ---------------------------------------------------------------- API /threat/watch/alerts
echo "API GET /threat/watch/alerts\n";
$cur = fn(string $t, $id) => iso(strtotime($t . ' UTC')) . '_' . $id;
$r = api('GET', '/threat/watch/alerts', array('key' => K1));
$d = $r['j']['data'] ?? array();
$ids1 = array_map('intval', array_column(alerts(1), 'id'));
check('200, 5 Treffer, aelteste zuerst (created_at, id)', $r['code'] === 200 AND count($d['alerts'] ?? array()) === 5 AND array_column($d['alerts'], 'id') === $ids1, code($r));
$x = $d['alerts'][0] ?? array();
check('Felder des Vertrags (+ label, details)', array_keys($x) === array('id', 'ip', 'cidr', 'network_id', 'source', 'label', 'listed', 'score', 'kinds', 'first_seen', 'last_seen', 'created_at', 'details'), array_keys($x));
$byIp = array_column($d['alerts'] ?? array(), null, 'ip');
$x = $byIp['45.1.1.1'] ?? array();
check('Netz-Treffer: Typen', is_int($x['id'] ?? null) AND $x['network_id'] === (int)$n1['id'] AND $x['source'] === 'network' AND $x['listed'] === true AND $x['score'] === 80 AND $x['kinds'] === array('ssh:bruteforce')
	AND preg_match('/^\d{4}-\d\d-\d\d$/', (string)$x['first_seen']) === 1 AND preg_match('/^\d{4}-\d\d-\d\d$/', (string)$x['last_seen']) === 1 AND $x['created_at'] === iso(strtotime($T1 . ' UTC')), $x);
$x = $byIp['45.9.9.9'] ?? array();
check('DynDNS-Treffer: network_id null, listed false', array_key_exists('network_id', $x) AND $x['network_id'] === null AND $x['source'] === 'dyndns' AND $x['listed'] === false AND $x['cidr'] === '45.9.9.9/32', $x);
check('next = Cursor <RFC 3339>_<id> des letzten', ($d['next'] ?? '') === $cur($T1, end($ids1)), $d['next'] ?? null);
$r = api('GET', '/threat/watch/alerts?since=' . rawurlencode($d['next'] ?? ''), array('key' => K1));
check('since = next: leer, next = uebergebener Stand', $r['code'] === 200 AND ($r['j']['data']['alerts'] ?? null) === array() AND ($r['j']['data']['next'] ?? '') === ($d['next'] ?? 'x'), code($r));
$r = api('GET', '/threat/watch/alerts?since=' . rawurlencode($cur($T1, $ids1[2])), array('key' => K1));
check('Cursor mitten im Zeitpunkt: nur die 2 danach', array_column($r['j']['data']['alerts'] ?? array(), 'id') === array_slice($ids1, 3), code($r));
$off = (new DateTime($T1 . ' UTC'))->setTimezone(new DateTimeZone('+02:00'))->format('Y-m-d\TH:i:s.123P');
$r = api('GET', '/threat/watch/alerts?since=' . rawurlencode($off), array('key' => K1));
check('reines RFC 3339 (Offset, Bruchteil): created_at danach -> leer, next = since', $r['code'] === 200 AND ($r['j']['data']['alerts'] ?? null) === array() AND ($r['j']['data']['next'] ?? '') === $off, code($r));
$r = api('GET', '/threat/watch/alerts?since=' . rawurlencode(iso(strtotime($T1 . ' UTC') - 1)), array('key' => K1));
check('RFC 3339 eine Sekunde frueher: alle 5', count($r['j']['data']['alerts'] ?? array()) === 5, code($r));
foreach(array('gestern', '2026-13-01T00:00:00Z', '2026-10-20 12:00:00', '2026-10-20T12:00:00Z_', '2026-10-20T12:00:00Z_x1') as $in) {
	$r = api('GET', '/threat/watch/alerts?since=' . rawurlencode($in), array('key' => K1));
	check("since '$in' -> 400 invalid_parameter", $r['code'] === 400 AND ($r['j']['code'] ?? '') === 'invalid_parameter', code($r));
}
$r = api('GET', '/threat/watch/alerts', array('key' => 'TestKeyAccountFour00000000000004'));
$nx = strtotime((string)($r['j']['data']['next'] ?? ''));
check('ohne Treffer und ohne since: next = jetzt minus 5 min (RFC 3339)', $r['code'] === 200 AND ($r['j']['data']['alerts'] ?? null) === array() AND preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/', (string)($r['j']['data']['next'] ?? '')) === 1
	AND abs($nx - (time() - 300)) <= 10, code($r));
// mehr als 100 Treffer mit demselben created_at (1. Lauf: 100 + 5 von Hand) und 3 aeltere davor
$T0 = gmdate('Y-m-d H:i:s', strtotime($T1 . ' UTC') - 60);
foreach(array(array($T0, 3, '46.6.9.'), array($T1, 5, '46.6.8.')) as [$ts, $n, $pre]) {
	for($i = 1; $i <= $n; $i++) {
		exec_sql("INSERT INTO hp_watch_alerts (userid, ip, ip_bin, network_id, source, cidr, label, listed, score, kinds, first_seen, last_seen, created_at, mailed_at)
			VALUES (2, ?, ?, NULL, 'dyndns', '', '', 0, 1, '', ?, ?, ?, ?)", array($pre . $i, inet_pton($pre . $i), $ts, $ts, $ts, $ts));
	}
}
$r = api('GET', '/threat/watch/alerts', array('key' => K2));
$d = $r['j']['data'] ?? array();
check('VIP Seite 1: 100 (3 aeltere + 97 vom gleichen Zeitpunkt), next mit id', count($d['alerts'] ?? array()) === 100 AND str_starts_with((string)($d['next'] ?? ''), iso(strtotime($T1 . ' UTC')) . '_'), array(count($d['alerts'] ?? array()), $d['next'] ?? null));
$seen = array_column($d['alerts'] ?? array(), 'id'); $since = $d['next'] ?? ''; $pages = 1;
for($p = 0; $p < 5; $p++) {
	$d = api('GET', '/threat/watch/alerts?since=' . rawurlencode($since), array('key' => K2))['j']['data'] ?? array();
	if(empty($d['alerts'])) { break; }
	$pages++; $seen = array_merge($seen, array_column($d['alerts'], 'id')); $since = $d['next'];
}
check('alle Seiten: 116 Treffer (105 mit gleichem created_at), jeder genau einmal, 2 Seiten', count($seen) === 116 AND count(array_unique($seen)) === 116 AND $pages === 2, array(count($seen), $pages));
check('am Ende: next bleibt stehen', ($d['next'] ?? '') === $since AND str_starts_with($since, iso(strtotime($T2 . ' UTC')) . '_'), array($d['next'] ?? null, $since));
check('Konten getrennt (Account 1 sieht 5)', count(api('GET', '/threat/watch/alerts', array('key' => K1))['j']['data']['alerts'] ?? array()) === 5);
exec_sql("DELETE FROM hp_watch_alerts WHERE ip LIKE '46.6.9.%' OR ip LIKE '46.6.8.%'");

// ---------------------------------------------------------------- Cron: neu gelistet, Mail-Wiederholung, 24 h, Fristen
echo "Cron: neu gelistet, Mail nachholen, nach 24 h, Fristen\n";
score('45.1.1.2', 1, 65, -600, 0);              // jetzt gelistet (Netz ohne Nachweis) -> erster Treffer
score('45.9.9.9', 1, 66, -600, 0);              // DynDNS jetzt gelistet -> trotz 24 h neuer Treffer
score('45.1.1.1', 1, 81, -600);                 // neue Sichtung, aber innerhalb 24 h und nicht neu gelistet -> nichts
exec_sql("UPDATE users SET email = 'kaputt' WHERE id = 1");
$out = cron();
$a1 = alerts(1);
check('neu gelistet: 2 Treffer (45.1.1.2, 45.9.9.9 gelistet)', count($a1) === 7 AND $a1[5]['ip'] !== $a1[6]['ip'] AND !array_diff(array($a1[5]['ip'], $a1[6]['ip']), array('45.1.1.2', '45.9.9.9')) AND (int)$a1[5]['listed'] === 1 AND (int)$a1[6]['listed'] === 1, array_column($a1, 'ip'));
check('Mail an ungueltige Adresse: nicht gesendet, mailed_at leer', count(mails()) === 3 AND (int)one("SELECT COUNT(*) n FROM hp_watch_alerts WHERE userid = 1 AND mailed_at IS NULL")['n'] === 2, $out);
exec_sql("UPDATE users SET email = 'a@test.invalid' WHERE id = 1");
$out = cron();
check('naechster Lauf holt die Mail nach (2 Adressen, keine neuen Treffer)', count(mails()) === 4 AND str_contains(mails()[3]['subject'], '2 Adressen') AND count(alerts(1)) === 7 AND (int)one("SELECT COUNT(*) n FROM hp_watch_alerts WHERE mailed_at IS NULL")['n'] === 0, $out);
exec_sql("UPDATE hp_watch_alerts SET created_at = created_at - INTERVAL 25 HOUR WHERE userid = 1");
exec_sql("UPDATE hp_scores SET listed_since = listed_since - INTERVAL 25 HOUR WHERE listed_since IS NOT NULL"); // Zeitachse mitschieben
exec_sql("INSERT INTO hp_watch_alerts (userid, ip, ip_bin, source, first_seen, last_seen, created_at, mailed_at) VALUES (1, '45.1.1.98', ?, 'network', ?, ?, ?, ?), (1, '45.1.1.99', ?, 'network', ?, ?, ?, ?)",
	array(inet_pton('45.1.1.98'), utc(-91 * 86400), utc(-91 * 86400), utc(-91 * 86400), utc(-91 * 86400), inet_pton('45.1.1.99'), utc(-89 * 86400), utc(-89 * 86400), utc(-89 * 86400), utc(-89 * 86400)));
$out = cron();
$a1 = alerts(1);
$new = array_slice($a1, 7);
check('nach 24 h: nur die IP mit neuer Sichtung (45.1.1.1)', count($new) === 2 AND $new[1]['ip'] === '45.1.1.1' AND (int)$new[1]['score'] === 81, array_column($new, 'ip'));
check('Fristen: Treffer > 90 Tage geloescht, 89 Tage bleibt', !in_array('45.1.1.98', array_column($a1, 'ip'), true) AND in_array('45.1.1.99', array_column($a1, 'ip'), true) AND str_contains($out, 'geloescht: 1'), $out);
check('Lauf gesperrt, wenn schon einer laeuft (GET_LOCK)', (function() { global $db; $db->query("SELECT GET_LOCK('hp_watch', 0)"); $o = cron(); $db->query("SELECT RELEASE_LOCK('hp_watch')"); return str_contains($o, 'laeuft bereits'); })());

// ---------------------------------------------------------------- Seite honeypot/watch.php
echo "Seite honeypot/watch.php\n";
$r = req('GET', '/honeypot/watch.php', array('jar' => 'anon'));
check('nicht angemeldet: Hinweis', $r['code'] === 200 AND str_contains($r['raw'], 'Bitte zuerst anmelden') AND !str_contains($r['raw'], 'name="cidr"'));
$r = req('GET', '/honeypot/watch.php?as=1', array('jar' => 'u1'));
$tok = csrf($r['raw']);
check('angemeldet: Netze, Zaehler, DynDNS, Treffer, Formular', $r['code'] === 200 AND $tok !== '' AND str_contains($r['raw'], '45.1.1.0/24') AND str_contains($r['raw'], 'Büro') AND str_contains($r['raw'], '2 / 3')
	AND str_contains($r['raw'], 'nas.home.ipv64.net') AND str_contains($r['raw'], 'ip.php?ip=45.1.1.1') AND str_contains($r['raw'], 'name="cidr"') AND str_contains($r['raw'], 'Node64'), substr($r['raw'], 0, 500));
check('DynDNS ohne private/deaktivierte/CDN-Adressen', !str_contains($r['raw'], '192.168.1.5') AND !str_contains($r['raw'], '45.9.9.10') AND !str_contains($r['raw'], '45.9.9.11'));
$r = req('POST', '/honeypot/watch.php?as=1', array('jar' => 'u1', 'form' => array('csrf' => 'falsch', 'action' => 'add', 'cidr' => '45.2.2.0/24')));
check('falsches CSRF-Token: abgelehnt', str_contains($r['raw'], 'Sitzung ist abgelaufen') AND one("SELECT id FROM hp_watch WHERE cidr = '45.2.2.0/24'") === false);
$r = req('POST', '/honeypot/watch.php?as=1', array('jar' => 'u1', 'form' => array('csrf' => $tok, 'action' => 'add', 'cidr' => '45.2.0.0/15', 'label' => '')));
check('zu grosses Netz: Meldung, Eingabe bleibt', str_contains($r['raw'], 'höchstens /16') AND str_contains($r['raw'], 'value="45.2.0.0/15"'));
$r = req('POST', '/honeypot/watch.php?as=1', array('jar' => 'u1', 'form' => array('csrf' => $tok, 'action' => 'add', 'cidr' => '45.2.2.9/24', 'label' => '<script>x</script>')));
check('eintragen: Erfolg, 3 / 3, Formular weg, Bezeichnung maskiert', str_contains($r['raw'], 'Netz <code>45.2.2.0/24</code> eingetragen') AND str_contains($r['raw'], '3 / 3') AND !str_contains($r['raw'], 'name="cidr"')
	AND str_contains($r['raw'], '&lt;script&gt;x&lt;/script&gt;') AND !str_contains($r['raw'], '<script>x'), substr($r['raw'], 0, 300));
$r = req('POST', '/honeypot/watch.php?as=1', array('jar' => 'u1', 'form' => array('csrf' => $tok, 'action' => 'add', 'cidr' => '45.3.3.0/24')));
check('Limit ueber die Seite: Meldung', str_contains($r['raw'], 'höchstens 3 Netze'));
$id = (int)one("SELECT id FROM hp_watch WHERE userid = 1 AND cidr = '45.2.2.0/24'")['id'];
$r = req('POST', '/honeypot/watch.php?as=1', array('jar' => 'u1', 'form' => array('csrf' => $tok, 'action' => 'delete', 'id' => (string)($nV['id'] ?? 0))));
check('fremdes Netz loeschen: nicht gefunden', str_contains($r['raw'], 'Netz nicht gefunden') AND one("SELECT id FROM hp_watch WHERE id = ?", array($nV['id'] ?? 0)) !== false);
$r = req('POST', '/honeypot/watch.php?as=1', array('jar' => 'u1', 'form' => array('csrf' => $tok, 'action' => 'delete', 'id' => (string)$id)));
check('eigenes Netz loeschen', str_contains($r['raw'], 'Netz gelöscht') AND one("SELECT id FROM hp_watch WHERE id = ?", array($id)) === false);
$r = req('GET', '/honeypot/watch.php?as=2&lang=en', array('jar' => 'u2'));
check('Englisch (VIP): Texte, Limit 50, Nachweis-Spalte, Bezeichnung maskiert', str_contains($r['raw'], 'early warning for your networks') AND str_contains($r['raw'], '/ 50') AND str_contains($r['raw'], 'yes – every sighting')
	AND str_contains($r['raw'], 'Rechenzentrum &lt;b&gt;') AND str_contains($r['raw'], 'watch.php?lang=en'), substr($r['raw'], 0, 300));

// ---------------------------------------------------------------- api_v2_honeypot.php: Dienst vpn, Sensor-Limit je Klasse
echo "api_v2_honeypot.php: Dienst vpn, Sensor-Limit je Klasse\n";
$sid = hp_uuid();
$start = time() - 605;
$r = post_report(report($sid, array(array('ip' => '45.8.8.8', 'kind' => 'vpn:bruteforce', 'service' => 'vpn', 'port' => 1194, 'count' => 4, 'first' => iso($start + 30), 'last' => iso($start + 60), 'source' => 'log', 'rule' => 'openvpn/auth@1'))), K1);
check('Dienst vpn angenommen', $r['code'] === 202 AND ($r['j']['data']['accepted'] ?? 0) === 1 AND ($r['j']['data']['rejected'] ?? 1) === 0, code($r));
check('vpn gespeichert', one("SELECT service, kind FROM hp_report_sources WHERE ip = '45.8.8.8'") === array('service' => 'vpn', 'kind' => 'vpn:bruteforce'));
sensors(1, 4, -3600);          // zusammen mit $sid 5 aktive (Standard: 5)
sensors(1, 3, -40 * 86400);    // alt (> 30 Tage): zaehlen nicht
$r = post_report(report(hp_uuid()), K1);
check('Standard: 6. aktiver Sensor -> 403 sensor_limit, limit 5', $r['code'] === 403 AND ($r['j']['code'] ?? '') === 'sensor_limit' AND ($r['j']['limit'] ?? 0) === 5, code($r));
check('abgewiesener Sensor nicht gespeichert', (int)one("SELECT COUNT(*) n FROM hp_sensors WHERE userid = 1")['n'] === 8);
exec_sql("UPDATE hp_sensors SET last_seen = ? WHERE userid = 1 AND sensor_id != ? AND last_seen > ? LIMIT 1", array(utc(-31 * 86400), $sid, utc(-7200)));
$r = post_report(report(hp_uuid()), K1);
check('ein Sensor 31 Tage still -> neuer Sensor 202', $r['code'] === 202, code($r));
exec_sql("UPDATE hp_sensors SET last_seen = ?, last_period_end = ? WHERE sensor_id = ?", array(utc(-300), utc(-1300), $sid));
$r = post_report(report($sid, array(), time() - 1), K1);   // anderer Zeitraum als die vpn-Meldung (sonst duplicate)
check('bekannter Sensor wird immer angenommen (5 aktive)', $r['code'] === 202, code($r));
$old = one("SELECT sensor_id FROM hp_sensors WHERE userid = 1 AND last_seen < ? LIMIT 1", array(utc(-30 * 86400)))['sensor_id'];
exec_sql("UPDATE hp_sensors SET last_seen = ?, last_period_end = ? WHERE sensor_id = ?", array(utc(-35 * 86400), utc(-35 * 86400), $old));
$r = post_report(report($old), K1);
check('alter bekannter Sensor kommt zurueck: angenommen', $r['code'] === 202, code($r));
sensors(2, 24, -3600);
$r = post_report(report(hp_uuid()), K2, '84.201.2.2');
check('VIP: 25. Sensor 202', $r['code'] === 202, code($r));
$r = post_report(report(hp_uuid()), K2, '84.201.2.2');
check('VIP: 26. Sensor -> 403 sensor_limit, limit 25', $r['code'] === 403 AND ($r['j']['code'] ?? '') === 'sensor_limit' AND ($r['j']['limit'] ?? 0) === 25, code($r));

// ---------------------------------------------------------------- OpenAPI
echo "OpenAPI\n";
$raw = (string)file_get_contents($WEB . '/api_v2_openapi.json');
$o = json_decode($raw, true);
check('gueltiges JSON', is_array($o));
check('vier Pfade', isset($o['paths']['/threat/watch']['get'], $o['paths']['/threat/watch']['post'], $o['paths']['/threat/watch/{id}']['delete'], $o['paths']['/threat/watch/alerts']['get']));
check('Schemas', isset($o['components']['schemas']['ThreatWatch'], $o['components']['schemas']['ThreatWatchNetwork'], $o['components']['schemas']['ThreatWatchAlert'], $o['components']['schemas']['ThreatWatchAlerts']));
$refs = array(); array_walk_recursive($o, function($v, $k) use (&$refs) { if($k === '$ref') { $refs[] = $v; } });
$missing = array_filter(array_unique($refs), function($ref) use ($o) { $p = explode('/', substr($ref, 2)); $x = $o; foreach($p as $s) { if(!isset($x[$s])) { return true; } $x = $x[$s]; } return false; });
check('alle $ref aufloesbar', $missing === array(), $missing);
$ops = array(); foreach($o['paths'] as $pp) { foreach($pp as $op) { if(isset($op['operationId'])) { $ops[] = $op['operationId']; } } }
check('operationId eindeutig', count($ops) === count(array_unique($ops)));

echo "\nErgebnis: $pass ok, $failed Fehler\n";
exit($failed > 0 ? 1 : 0);
