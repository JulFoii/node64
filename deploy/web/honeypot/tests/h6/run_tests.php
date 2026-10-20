<?php
/**
 * Pruefung Honeypot64 H6 (Teil ipv64) in der Testumgebung hp6i-* (run_agentbox.sh): Fingerabdruecke in
 * api_v2_honeypot.php, Rangliste (hp_stats_lib.php, GET /threat/stats, stats.php), Passwortpruefung
 * (bots/honeypot_passwords.php, GET /threat/passwords/range/{prefix}, honeypot/password.php), Aenderungs-Feed
 * (bots/blocklist/honeypot_score.php -> hp_list_changes, GET /threat/feed), Einbindung ohne Aenderung an api_v2.php.
 *
 *   HP6ITEST=1 php run_tests.php http://127.0.0.1:8080 /var/www/clients/client1/web58/web
 */
if(php_sapi_name() !== 'cli' OR getenv('HP6ITEST') !== '1') { exit; }

$BASE = rtrim($argv[1] ?? 'http://127.0.0.1:8080', '/');
$WEB = rtrim($argv[2] ?? '/var/www/clients/client1/web58/web', '/');
const K1 = 'TestKeyAccountOne000000000000001';   // Account 1, Standard, meldet
const K2 = 'TestKeyApiKeysTwo000000000000002';   // Account 2, VIP (api_keys), meldet
const K3 = 'TestKeyAccountThree0000000000003';   // Account 3, inaktiv
const K4 = 'TestKeyAccountFour00000000000004';   // Account 4, Standard, meldet
const K8 = 'TestKeyAccountEight0000000000008';   // Account 8, Standard, ohne Sensor
const K9 = 'TestKeyAccountNine00000000000009';   // Account 9, VIP, ohne Sensor

$db = new PDO('mysql:host=hp6i-db;dbname=ipv64', 'root', 'hp6itest', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"));
$pass = 0; $failed = 0;

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . (is_string($info) ? substr($info, 0, 700) : substr(json_encode($info, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 0, 700)) . "\n"; }
}
/** HTTP-Anfrage. $o: ip (X-Forwarded-For), key, json, headers (Liste) */
function req(string $method, string $path, array $o = array()): array {
	global $BASE;
	$h = array('X-Forwarded-For: ' . ($o['ip'] ?? '84.200.9.9'));
	if(isset($o['key'])) { $h[] = 'Authorization: Bearer ' . $o['key']; }
	foreach($o['headers'] ?? array() as $x) { $h[] = $x; }
	$body = '';
	if(isset($o['json'])) { $body = json_encode($o['json'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); $h[] = 'Content-Type: application/json'; }
	$ctx = stream_context_create(array('http' => array('method' => $method, 'header' => implode("\r\n", $h), 'content' => $body, 'ignore_errors' => true, 'timeout' => 120)));
	$raw = @file_get_contents($BASE . $path, false, $ctx);
	$code = 0; $hdr = array();
	foreach($http_response_header ?? array() as $l) {
		if(preg_match('#^HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
		elseif(str_contains($l, ':')) { [$k, $v] = explode(':', $l, 2); $hdr[strtolower(trim($k))] = trim($v); }
	}
	return array('code' => $code, 'h' => $hdr, 'j' => json_decode((string)$raw, true), 'raw' => (string)$raw);
}
function api(string $method, string $path, array $o = array()): array { return req($method, '/api_v2.php' . $path, $o); }
function x(string $sql, array $p = array()) { global $db; $st = $db->prepare($sql); $st->execute($p); return $st; }
function one(string $sql, array $p = array()) { $r = x($sql, $p)->fetch(PDO::FETCH_ASSOC); return $r === false ? null : $r; }
function all(string $sql, array $p = array()): array { return x($sql, $p)->fetchAll(PDO::FETCH_ASSOC); }
function code(array $r): string { return $r['code'] . ' ' . substr($r['raw'], 0, 400); }
function iso(int $ts): string { return gmdate('Y-m-d\TH:i:s\Z', $ts); }
function dt(float $daysAgo): string { return gmdate('Y-m-d H:i:s', (int)(time() - $daysAgo * 86400)); }
function cli(string $cmd): string { global $WEB; return (string)shell_exec("cd " . escapeshellarg($WEB) . " && HP6ITEST=1 $cmd 2>&1"); }
function scorer(string $a = ''): string { global $WEB; return cli("php $WEB/bots/blocklist/honeypot_score.php $a"); }
function pwcron(string $a = ''): string { global $WEB; return cli("php $WEB/bots/honeypot_passwords.php $a"); }
function clean_out(string $o): bool { return !preg_match('/Fatal|Warning|Notice|Deprecated|Fehler/i', $o); }
function hp_uuid(): string { $b = random_bytes(16); $b[6] = chr((ord($b[6]) & 0x0f) | 0x40); $b[8] = chr((ord($b[8]) & 0x3f) | 0x80); return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4)); }
/** Meldung schema 1 (letzte 10 Minuten) mit Proben */
function report(int $u, array $samples): array {
	$sid = hp_uuid(); $end = time() - 5; $start = $end - 600;
	return array('schema' => 1, 'report_id' => "$sid-$start", 'sensor' => array('id' => $sid, 'version' => '0.14.0', 'profile' => 'standard', 'mode' => 'headless'),
		'period' => array('start' => iso($start), 'end' => iso($end)), 'samples' => $samples,
		'sources' => array(array('ip' => "45.9.$u.1", 'kind' => 'ssh:bruteforce', 'service' => 'ssh', 'port' => 22, 'count' => 2, 'first' => iso($start + 10), 'last' => iso($start + 20), 'source' => 'honeypot')));
}
function post(array $r, string $key, int $u): array { return api('POST', '/honeypot/reports', array('key' => $key, 'json' => $r, 'ip' => "84.201.$u.1")); }
function cred(string $user, string $pw, int $n): array { return array('service' => 'ssh', 'user' => $user, 'pass' => $pw, 'count' => $n); }
/** Cursor wie api_v2_threat_feed.php */
function cur(int $ts, int $id): string { return rtrim(strtr(base64_encode(pack('JJ', $ts, $id)), '+/', '-_'), '='); }
/** Bewertungsdaten direkt (wie H3-Test): Account $u meldet $ip */
$repNo = 0;
function src(int $u, string $ip, string $kind): void {
	global $repNo;
	$sid = sprintf('00000000-0000-4000-8000-%012d', $u); $sip = "84.210.$u.10"; $seen = dt(0.05); $day = substr($seen, 0, 10);
	x("INSERT INTO hp_sensors (sensor_id, userid, version, profile, mode, first_seen, last_seen, last_ip) VALUES (?, ?, '0.14.0', 'standard', 'headless', ?, ?, ?)
		ON DUPLICATE KEY UPDATE last_seen = VALUES(last_seen)", array($sid, $u, dt(30), dt(0.01), $sip));
	$repNo++;
	x("INSERT INTO hp_reports (day, report_id, sensor_id, userid, period_start, period_end, received_at, sources, ip) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
		array($day, "$sid-$repNo", $sid, $u, $seen, $seen, $seen, $sip));
	$ref = (int)x("SELECT LAST_INSERT_ID()")->fetchColumn();
	x("INSERT INTO hp_report_sources (day, report_ref, userid, sensor_id, ip, ip_bin, kind, service, port, `count`, first_seen, last_seen, source) VALUES (?, ?, ?, ?, ?, INET6_ATON(?), ?, 'ssh', 22, 3, ?, ?, 'honeypot')",
		array($day, $ref, $u, $sid, $ip, $ip, $kind, $seen, $seen));
}

// ---------------------------------------------------------------- SQL und Einbindung
echo "SQL und Einbindung\n";
$t = array_column(all("SHOW TABLES"), 'Tables_in_ipv64');
check('Tabellen hp_pw_range, hp_list_changes, hp_samples_fps (datenbank.sql zweimal eingespielt)', !array_diff(array('hp_pw_range', 'hp_list_changes', 'hp_samples_fps'), $t), $t);
$col = one("SHOW COLUMNS FROM hp_pw_range WHERE Field = 'sha1'");
check('hp_pw_range.sha1 binary(20) PK', ($col['Type'] ?? '') === 'binary(20)' AND ($col['Key'] ?? '') === 'PRI', $col);
$api = (string)file_get_contents("$WEB/api_v2.php");
check('api_v2.php: nur die vier live vorhandenen require-Zeilen, keine H6-Datei', substr_count($api, "require __DIR__ . '/api_v2_") === 4 AND !str_contains($api, 'threat_feed') AND !str_contains($api, 'threat_passwords'));
$r = api('GET', '/threat/ip/45.1.2.3');
check('GET /threat/ip weiter erreichbar (Reihenfolge der Einbindung)', $r['code'] === 200 AND ($r['j']['data']['listed'] ?? null) === false, code($r));
$r = api('GET', '/threat/watch', array('key' => K1));
check('GET /threat/watch weiter erreichbar', $r['code'] === 200, code($r));
rename("$WEB/api_v2_threat_feed.php", "$WEB/api_v2_threat_feed.php.off");
$r = api('GET', '/threat/feed', array('key' => K9));
$r2 = api('GET', '/threat/stats');
rename("$WEB/api_v2_threat_feed.php.off", "$WEB/api_v2_threat_feed.php");
check('ohne api_v2_threat_feed.php: 404, Rest laeuft', $r['code'] === 404 AND $r2['code'] === 200, code($r) . ' | ' . code($r2));
$o = cli("php $WEB/bots/honeypot_cron.php --list");
check('Cron-Job pwrange in HPC_JOBS', str_contains($o, 'pwrange') AND str_contains($o, 'honeypot_passwords.php'), $o);

// ---------------------------------------------------------------- Fingerabdruecke
echo "Fingerabdruecke (samples.fingerprints)\n";
$JA4 = 'ja4:t13d1516h2_8daaf6152771_02713d6af862'; $HASSH = 'hassh:ec7378c1a92f5a8dde7e8b7a1ddf33d1';
$bad = array(array('key' => 'JA4:T13D', 'count' => 1), array('key' => 'ja4:', 'count' => 1), array('key' => 'foo:bar', 'count' => 1),
	array('key' => 'hassh:' . str_repeat('a', 31), 'count' => 1), array('key' => "ja4:t13d\n", 'count' => 1), array('key' => 123, 'count' => 1),
	array('key' => 'ja4:' . str_repeat('a', 65), 'count' => 1));
$r = post(report(1, array('fingerprints' => array_merge(array(array('key' => $JA4, 'count' => 4), array('key' => $HASSH, 'count' => 2), array('key' => $JA4, 'count' => 1)), $bad),
	'credentials' => array(cred('root', 'hunter2', 5), cred('admin', 'solo-pass', 3), cred('root', '', 2)))), K1, 1);
check('Meldung mit Fingerabdruecken 202, 7 ungueltige verworfen und gezaehlt', $r['code'] === 202 AND ($r['j']['data']['rejected_reasons']['invalid_fingerprint'] ?? 0) === 7, code($r));
$r = post(report(2, array('fingerprints' => array(array('key' => $JA4, 'count' => 1)), 'credentials' => array(cred('admin', 'hunter2', 7), cred('root', '', 1)))), K2, 2);
check('zweiter Account 202', $r['code'] === 202 AND ($r['j']['data']['rejected'] ?? -1) === 0, code($r));
$r = post(report(4, array('credentials' => array(cred('pi', '', 4)))), K4, 4);
check('Meldung ohne fingerprints (aeltere Sensoren) 202', $r['code'] === 202, code($r));
$f = array_map(fn($x) => array('fp' => $x['fp'], 'c' => (int)$x['c']), all("SELECT fp, `count` c FROM hp_samples_fps ORDER BY fp"));
check('hp_samples_fps: ja4 6 (zusammengefasst, 2 Accounts), hassh 2, keine ungueltigen', $f === array(array('fp' => $HASSH, 'c' => 2), array('fp' => $JA4, 'c' => 6)), $f);
$h = one("SELECT HEX(key_hash) h FROM hp_samples_fps WHERE fp = ?", array($JA4));
check('key_hash = SHA-256 ueber den Key', ($h['h'] ?? '') === strtoupper(hash('sha256', $JA4)), $h);
$c = array_map(fn($x) => array((int)$x['userid'], (int)$x['cnt']), all("SELECT userid, cnt FROM hp_sample_contrib WHERE kind = 'fp' AND key_hash = UNHEX(?) ORDER BY userid", array(hash('sha256', $JA4))));
check('Beitrag je Account (kind fp): Account 1 = 5, Account 2 = 1', $c === array(array(1, 5), array(2, 1)), $c);
$r = post(report(1, array('fingerprints' => array(array('key' => $JA4, 'count' => 0)))), K1, 1);
check('count 0 -> 422 mit Feld', $r['code'] === 422 AND ($r['j']['field'] ?? '') === 'samples.fingerprints[0].count', code($r));
$r = post(report(1, array('fingerprints' => array('a' => array('key' => $JA4, 'count' => 1)))), K1, 1);
check('fingerprints als Objekt -> 422', $r['code'] === 422 AND ($r['j']['field'] ?? '') === 'samples.fingerprints', code($r));
$r = post(report(1, array('fingerprints' => array_fill(0, 501, array('key' => $JA4, 'count' => 1)))), K1, 1);
check('501 Fingerabdruecke -> 413', $r['code'] === 413 AND ($r['j']['code'] ?? '') === 'too_many_samples', code($r));
x("DELETE FROM hp_stats_cache");
$r = api('GET', '/threat/stats');
$top = $r['j']['data']['top']['fingerprints'] ?? null;
check('GET /threat/stats: top.fingerprints nur ab 2 Accounts (ja4 ja, hassh nein)', $r['code'] === 200 AND $top === array(array('value' => $JA4, 'events' => 6, 'accounts' => 2)), code($r));
check('andere Ranglisten unveraendert vorhanden', isset($r['j']['data']['top']['passwords'], $r['j']['data']['top']['usernames'], $r['j']['data']['top']['paths'], $r['j']['data']['top']['user_agents']), array_keys($r['j']['data']['top'] ?? array()));
$r = req('GET', '/honeypot/stats.php');
check('stats.php: Karte Fingerabdruecke mit Eintrag, ohne PHP-Fehler', $r['code'] === 200 AND str_contains($r['raw'], 'Fingerabdrücke (JA4/HASSH)') AND str_contains($r['raw'], $JA4) AND !str_contains($r['raw'], $HASSH)
	AND !preg_match('/Warning|Notice|Deprecated|Fatal error/', $r['raw']), substr($r['raw'], 0, 300));
$r = req('GET', '/honeypot/stats.php?as=2&k=fp&q=t13d');
check('stats.php (volle Seite): Suche in fp', $r['code'] === 200 AND substr_count($r['raw'], $JA4) >= 2 AND !preg_match('/Warning|Notice|Fatal error/', $r['raw']), substr($r['raw'], 0, 300));
$r = req('GET', '/honeypot/stats.php?as=2&export=fp');
check('stats.php: CSV-Export fp', $r['code'] === 200 AND str_contains($r['raw'], $JA4) AND str_starts_with($r['h']['content-type'] ?? '', 'text/csv'), code($r));

// ---------------------------------------------------------------- Passwortpruefung: Cron
echo "Passwortpruefung: bots/honeypot_passwords.php\n";
$sha = fn($p) => strtoupper(sha1($p));
// Altbestand: oldpass (Schwelle vor 100 Tagen erfuellt), ancient (vor 400 Tagen), nosamples, outside (Proben nur vor 400 Tagen)
foreach(array(array('oldpass', 100, 9), array('ancient', 100, 4), array('outside', 400, 6)) as [$pw, $ago, $n]) {
	x("INSERT INTO hp_samples_creds (day, key_hash, service, username, password, pass_sha1, `count`, last_seen) VALUES (?, UNHEX(?), 'ssh', 'root', ?, ?, ?, ?)",
		array(substr(dt($ago), 0, 10), hash('sha256', "ssh\0root\0$pw"), $pw, sha1($pw), $n, dt($ago)));
}
foreach(array(array('oldpass', 100), array('ancient', 400), array('nosamples', 10), array('outside', 10)) as [$pw, $ago]) {
	x("INSERT INTO hp_pw_range (sha1, cnt, updated) VALUES (UNHEX(?), 1, ?)", array(sha1($pw), dt($ago)));
}
$o = pwcron('--dry');
check('--dry: rechnet, schreibt nichts', str_contains($o, 'DRY RUN') AND (int)one("SELECT COUNT(*) n FROM hp_pw_range")['n'] === 4, $o);
$o = pwcron();
echo preg_replace('/^/m', '        ', trim($o)) . "\n";
check('Lauf ohne Fehler', str_contains($o, 'Fertig') AND clean_out($o), $o);
$rows = array(); foreach(all("SELECT HEX(sha1) h, cnt, updated FROM hp_pw_range") as $x) { $rows[$x['h']] = $x; }
check('hunter2 (2 Accounts) aufgenommen, cnt 12, updated jetzt', (int)($rows[$sha('hunter2')]['cnt'] ?? 0) === 12 AND strtotime($rows[$sha('hunter2')]['updated'] . ' UTC') >= time() - 120, $rows[$sha('hunter2')] ?? null);
check('solo-pass (1 Account) nicht aufgenommen', !isset($rows[$sha('solo-pass')]));
check('leeres Passwort (3 Accounts) nie aufgenommen', !isset($rows[$sha('')]));
check('oldpass: bleibt (Frist 365 Tage), cnt neu 9, updated unveraendert', (int)($rows[$sha('oldpass')]['cnt'] ?? 0) === 9 AND substr($rows[$sha('oldpass')]['updated'] ?? '', 0, 10) === substr(dt(100), 0, 10), $rows[$sha('oldpass')] ?? null);
check('ancient (Schwelle vor 400 Tagen) entfernt', !isset($rows[$sha('ancient')]));
check('nosamples und outside (keine Proben in 365 Tagen) entfernt', !isset($rows[$sha('nosamples')]) AND !isset($rows[$sha('outside')]));
check('genau 2 Eintraege', count($rows) === 2, array_keys($rows));
$o = pwcron();
check('zweiter Lauf gleiches Ergebnis', clean_out($o) AND (int)one("SELECT COUNT(*) n FROM hp_pw_range")['n'] === 2 AND (int)one("SELECT cnt FROM hp_pw_range WHERE sha1 = UNHEX(?)", array(sha1('hunter2')))['cnt'] === 12, $o);

// ---------------------------------------------------------------- Passwortpruefung: API
echo "Passwortpruefung: GET /threat/passwords/range/{prefix}\n";
$hx = $sha('hunter2'); $pre = substr($hx, 0, 5); $suf = substr($hx, 5);
$r = api('GET', "/threat/passwords/range/$pre", array('ip' => '84.202.0.1'));
$lines = explode("\r\n", rtrim($r['raw'], "\r\n"));
check('200 text/plain, CRLF', $r['code'] === 200 AND str_starts_with($r['h']['content-type'] ?? '', 'text/plain') AND str_contains($r['raw'], "\r\n"), code($r));
check('Cache-Control public, max-age=3600', ($r['h']['cache-control'] ?? '') === 'public, max-age=3600', $r['h']);
check('mindestens 64 Zeilen, alle "<35 Hex>:<Zahl>"', count($lines) >= 64 AND count(preg_grep('/^[0-9A-F]{35}:\d+$/D', $lines)) === count($lines), array_slice($lines, 0, 3));
check('Treffer enthalten (Anzahl 12)', in_array("$suf:12", $lines, true), $lines);
check('Rest sind Fuellzeilen mit Anzahl 0', count(preg_grep('/:0$/', $lines)) === count($lines) - 1);
$sorted = $lines; sort($sorted, SORT_STRING);
check('sortiert', $sorted === $lines);
check('keine doppelten Endungen', count(array_unique(array_map(fn($l) => explode(':', $l)[0], $lines))) === count($lines));
$r2 = api('GET', '/threat/passwords/range/' . strtolower($pre), array('ip' => '84.202.0.1'));
check('Praefix klein geschrieben geht auch', $r2['code'] === 200 AND str_contains($r2['raw'], "$suf:12"), code($r2));
$e1 = api('GET', '/threat/passwords/range/00000', array('ip' => '84.202.0.1')); $e2 = api('GET', '/threat/passwords/range/00000', array('ip' => '84.202.0.1'));
check('ohne Treffer: gleiche Zeilenzahl (64), nur Anzahl 0, Fuellung zufaellig', substr_count($e1['raw'], "\r\n") === 64 AND !preg_match('/:[1-9]/', $e1['raw']) AND $e1['raw'] !== $e2['raw'], code($e1));
check('Groesse verraet nichts: Antwort mit Treffer gleich lang wie ohne (+-Ziffern)', abs(strlen($r['raw']) - strlen($e1['raw'])) <= 4, array(strlen($r['raw']), strlen($e1['raw'])));
$o = one("SELECT HEX(sha1) h FROM hp_pw_range WHERE sha1 = UNHEX(?)", array(sha1('oldpass')));
$r = api('GET', '/threat/passwords/range/' . substr($sha('oldpass'), 0, 5), array('ip' => '84.202.0.1'));
check('oldpass ueber seinen Praefix gefunden (Anzahl 9)', str_contains($r['raw'], substr($sha('oldpass'), 5) . ':9'), code($r));
foreach(array('XYZ12', '1234', '123456', 'g0000') as $bp) {
	$r = api('GET', "/threat/passwords/range/$bp", array('ip' => '84.202.0.2'));
	check("Praefix '$bp' -> 422 invalid_prefix", $r['code'] === 422 AND ($r['j']['code'] ?? '') === 'invalid_prefix' AND ($r['j']['field'] ?? '') === 'prefix', code($r));
}
$r = api('GET', "/threat/passwords/range/$pre", array('ip' => '84.202.0.3'));
check('ohne Key: Limit je IP (RateLimit-Limit 10)', ($r['h']['ratelimit-limit'] ?? '') === '10', $r['h']);
for($i = 0; $i < 9; $i++) { api('GET', "/threat/passwords/range/$pre", array('ip' => '84.202.0.3')); }
$r = api('GET', "/threat/passwords/range/$pre", array('ip' => '84.202.0.3'));
check('11. Abfrage ohne Key -> 429 mit Retry-After', $r['code'] === 429 AND isset($r['h']['retry-after']), code($r));
$r = api('GET', "/threat/passwords/range/$pre", array('ip' => '84.202.0.4'));
check('andere IP nicht betroffen', $r['code'] === 200, code($r));
$r = api('GET', "/threat/passwords/range/$pre", array('ip' => '84.202.0.3', 'key' => K8));
check('mit Key: Limit je Account (120), gleiche IP wieder frei', $r['code'] === 200 AND ($r['h']['ratelimit-limit'] ?? '') === '120', code($r));
$r = api('GET', "/threat/passwords/range/$pre", array('key' => 'Invalid000000000000000000000000x'));
check('ungueltiger Key -> 401', $r['code'] === 401, code($r));
$r = api('GET', "/threat/passwords/range/$pre", array('key' => K3));
check('inaktiver Account -> 401', $r['code'] === 401, code($r));

// ---------------------------------------------------------------- Seite password.php
echo "Seite honeypot/password.php\n";
foreach(array('' => 'verlässt nie deinen Browser', '?lang=en' => 'never leaves your browser', '?as=2' => 'verlässt nie deinen Browser', '?as=1&lang=en' => 'never leaves your browser') as $q => $want) {
	$r = req('GET', "/honeypot/password.php$q");
	check("password.php$q rendert ohne PHP-Fehler", $r['code'] === 200 AND str_contains($r['raw'], $want) AND str_contains($r['raw'], '</html>') AND !preg_match('/Warning|Notice|Deprecated|Fatal error|Parse error/', $r['raw']), substr($r['raw'], 0, 400));
}
$r = req('GET', '/honeypot/password.php');
check('nur Praefix per JavaScript (SubtleCrypto SHA-1, Range-API)', str_contains($r['raw'], "crypto.subtle.digest('SHA-1'") AND str_contains($r['raw'], "'/api/v2/threat/passwords/range/'") AND str_contains($r['raw'], 'hex.slice(0, 5)'));
check('Passwortfeld ohne name (wird nie mit einem Formular gesendet), Formular ohne action', preg_match('/<input id="hpwPw"[^>]*>/', $r['raw'], $m) === 1 AND !str_contains($m[0], 'name=') AND !preg_match('/<form[^>]*action=/', $r['raw']), $m[0] ?? '');

// ---------------------------------------------------------------- Aenderungs-Feed
echo "Aenderungs-Feed: honeypot_score.php -> hp_list_changes, GET /threat/feed\n";
$r = api('GET', '/threat/feed');
check('ohne Key -> 401', $r['code'] === 401, code($r));
$r = api('GET', '/threat/feed', array('key' => K3));
check('inaktiver Account -> 401', $r['code'] === 401, code($r));
$r = api('GET', '/threat/feed', array('key' => K8));
check('Standard ohne Sensor -> 403 feed_not_available mit Erklaerung', $r['code'] === 403 AND ($r['j']['code'] ?? '') === 'feed_not_available' AND str_contains($r['j']['detail'] ?? '', 'contributors'), code($r));
$r = api('GET', '/threat/feed', array('key' => K1));
check('Standard als Beitragender (Meldung in 7 Tagen) -> 200', $r['code'] === 200, code($r));
x("UPDATE hp_sensors SET disabled = 1 WHERE userid = 4");
$r = api('GET', '/threat/feed', array('key' => K4));
check('Standard mit gesperrtem Sensor -> 403', $r['code'] === 403, code($r));
x("UPDATE hp_sensors SET disabled = 0 WHERE userid = 4");
$r = api('GET', '/threat/feed', array('key' => K9));
$c0 = $r['j']['data']['next'] ?? '';
check('VIP ohne Sensor -> 200, ohne since: keine Eintraege, Cursor', $r['code'] === 200 AND ($r['j']['data']['changes'] ?? null) === array() AND ($r['j']['data']['more'] ?? null) === false AND preg_match('/^[A-Za-z0-9_-]{22}$/', $c0) === 1, code($r));
check('RateLimit je Account (120)', ($r['h']['ratelimit-limit'] ?? '') === '120', $r['h']);

src(5, '45.2.0.1', 'ssh:bruteforce'); src(6, '45.2.0.1', 'ssh:bruteforce');            // A: gelistet ssh
src(5, '45.2.0.2', 'ssh:bruteforce'); src(6, '45.2.0.2', 'ssh:bruteforce');            // B: gelistet ssh, spaeter auch web
src(5, '45.2.0.3', 'scanner:research'); src(6, '45.2.0.3', 'scanner:research'); src(7, '45.2.0.3', 'scanner:research'); // C: research
src(5, '45.2.0.4', 'generic:portscan');                                                 // D: nicht gelistet
$o = scorer();
echo preg_replace('/^/m', '        ', trim($o)) . "\n";
check('Bewertung ohne Fehler, Protokoll 3 neu', clean_out($o) AND str_contains($o, 'hp_list_changes: 3 neu, 0 entfernt, 0 geaendert'), $o);
$r = api('GET', '/threat/feed?since=' . $c0, array('key' => K9));
$ch = $r['j']['data']['changes'] ?? array(); $c1 = $r['j']['data']['next'] ?? ''; $e1 = $r['h']['etag'] ?? '';
$by = array(); foreach($ch as $x) { $by[$x['ip']] = $x; }
check('since=c0: 3 Aenderungen add', $r['code'] === 200 AND count($ch) === 3 AND count(array_filter($ch, fn($x) => $x['action'] === 'add')) === 3, code($r));
check('A: lists v64,ssh, previous_lists leer, at ISO', ($by['45.2.0.1']['lists'] ?? null) === array('v64', 'ssh') AND $by['45.2.0.1']['previous_lists'] === array() AND preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/', $by['45.2.0.1']['at']) === 1, $by['45.2.0.1'] ?? null);
check('C: nur research', ($by['45.2.0.3']['lists'] ?? null) === array('research'), $by['45.2.0.3'] ?? null);
check('genau die Felder ip, action, lists, previous_lists, at', array_keys($ch[0] ?? array()) === array('ip', 'action', 'lists', 'previous_lists', 'at'), $ch[0] ?? null);
check('next neu, more false, ETag gesetzt', $c1 !== $c0 AND ($r['j']['data']['more'] ?? null) === false AND preg_match('/^"[0-9a-f]{32}"$/', $e1) === 1, $r['h']);
$r = api('GET', '/threat/feed?since=' . $c1, array('key' => K9));
$e2 = $r['h']['etag'] ?? '';
check('since=c1: keine Aenderungen, next bleibt c1', $r['code'] === 200 AND ($r['j']['data']['changes'] ?? null) === array() AND ($r['j']['data']['next'] ?? '') === $c1, code($r));
$r = api('GET', '/threat/feed?since=' . $c1, array('key' => K9, 'headers' => array('If-None-Match: ' . $e2)));
check('If-None-Match passend -> 304 ohne Inhalt, ETag', $r['code'] === 304 AND $r['raw'] === '' AND ($r['h']['etag'] ?? '') === $e2, code($r));
$r = api('GET', '/threat/feed?since=' . $c0, array('key' => K9, 'headers' => array('If-None-Match: ' . $e2)));
check('If-None-Match fuer anderen Stand -> 200', $r['code'] === 200 AND count($r['j']['data']['changes'] ?? array()) === 3 AND ($r['h']['etag'] ?? '') === $e1, code($r));
$r = api('GET', '/threat/feed', array('key' => K9));
check('ohne since jetzt: Cursor = letzte Aenderung', ($r['j']['data']['next'] ?? '') === $c1, code($r));

x("INSERT INTO hp_allowlist (cidr, ip_start, ip_end, reason, source, created_at) VALUES ('45.2.0.1/32', INET6_ATON('45.2.0.1'), INET6_ATON('45.2.0.1'), 'Test', 'manual', UTC_TIMESTAMP())");
src(5, '45.2.0.2', 'http:exploit:sqli'); src(6, '45.2.0.2', 'http:exploit:sqli');
$o = scorer();
check('zweiter Lauf: 0 neu, 1 entfernt, 1 geaendert', clean_out($o) AND str_contains($o, 'hp_list_changes: 0 neu, 1 entfernt, 1 geaendert'), $o);
$r = api('GET', '/threat/feed?since=' . $c1, array('key' => K1));
$ch = $r['j']['data']['changes'] ?? array(); $c2 = $r['j']['data']['next'] ?? '';
$by = array(); foreach($ch as $x) { $by[$x['ip']] = $x; }
check('remove A: lists leer, previous_lists v64,ssh', ($by['45.2.0.1']['action'] ?? '') === 'remove' AND $by['45.2.0.1']['lists'] === array() AND $by['45.2.0.1']['previous_lists'] === array('v64', 'ssh'), $ch);
$bl = $by['45.2.0.2']['lists'] ?? array(); sort($bl);
check('update B: lists mit web, previous_lists v64,ssh', ($by['45.2.0.2']['action'] ?? '') === 'update' AND $bl === array('ssh', 'v64', 'web') AND $by['45.2.0.2']['previous_lists'] === array('v64', 'ssh'), $ch);
check('aelteste zuerst (nach ID)', count($ch) === 2 AND $c2 !== $c1);
$o = scorer();
check('dritter Lauf ohne Aenderung: nichts protokolliert', str_contains($o, 'hp_list_changes: 0 neu, 0 entfernt, 0 geaendert'), $o);
$n0 = (int)one("SELECT COUNT(*) n FROM hp_list_changes")['n'];
$o = scorer('--dry');
check('--dry protokolliert nichts', str_contains($o, 'DRY RUN') AND (int)one("SELECT COUNT(*) n FROM hp_list_changes")['n'] === $n0, $o);

foreach(array('abc', cur(time() + 3 * 86400, 1), str_repeat('A', 23), 'AAAAAAAAAAAAAAAAAAAAA=') as $bs) {
	$r = api('GET', '/threat/feed?since=' . rawurlencode($bs), array('key' => K9));
	check("since '$bs' -> 400 invalid_parameter", $r['code'] === 400 AND ($r['j']['code'] ?? '') === 'invalid_parameter', code($r));
}
// Seiten: 10 005 Aenderungen
x("INSERT INTO hp_list_changes (created_at, action, ip, lists, prev_lists) SELECT UTC_TIMESTAMP(), 'add', CONCAT('46.0.', seq DIV 256, '.', seq MOD 256), 'v64', '' FROM seq_1_to_10005");
$r = api('GET', '/threat/feed?since=' . $c2, array('key' => K9));
$p1 = $r['j']['data'] ?? array();
check('10 005 Aenderungen: erste Seite 10 000, more true', $r['code'] === 200 AND count($p1['changes'] ?? array()) === 10000 AND ($p1['more'] ?? null) === true AND ($p1['changes'][0]['ip'] ?? '') === '46.0.0.1', code($r));
$r = api('GET', '/threat/feed?since=' . ($p1['next'] ?? ''), array('key' => K9));
$p2 = $r['j']['data'] ?? array();
check('zweite Seite 5, more false, lueckenlos', count($p2['changes'] ?? array()) === 5 AND ($p2['more'] ?? null) === false AND ($p2['changes'][4]['ip'] ?? '') === '46.0.39.21', $p2['changes'] ?? null);
// Frist und abgelaufene Cursor
x("INSERT INTO hp_list_changes (created_at, action, ip, lists, prev_lists) VALUES (?, 'add', '46.1.1.1', 'v64', '')", array(dt(31)));
$o = scorer();
check('Bewertung loescht Aenderungen aelter als 30 Tage', str_contains($o, 'hp_list_changes: 1 alte Eintraege geloescht') AND one("SELECT id FROM hp_list_changes WHERE ip = '46.1.1.1'") === null, $o);
$r = api('GET', '/threat/feed?since=' . cur(time() - 40 * 86400, 1), array('key' => K9));
check('alter Cursor ohne Luecke (MIN(id) = id+1) -> 200', $r['code'] === 200, code($r));
x("DELETE FROM hp_list_changes WHERE id = 1");
$r = api('GET', '/threat/feed?since=' . cur(time() - 40 * 86400, 0), array('key' => K9));
check('alter Cursor mit geloeschten Aenderungen -> 410 cursor_expired', $r['code'] === 410 AND ($r['j']['code'] ?? '') === 'cursor_expired', code($r));
$r = api('GET', '/threat/feed?since=' . cur(time() - 86400, 0), array('key' => K9));
check('junger Cursor -> 200', $r['code'] === 200, code($r));
// fehlende Tabelle: Bewertung laeuft weiter, Feed 503
x("RENAME TABLE hp_list_changes TO hp_list_changes_off");
src(5, '45.2.0.9', 'ssh:bruteforce'); src(6, '45.2.0.9', 'ssh:bruteforce');
$o = scorer();
$s = one("SELECT listed FROM hp_scores WHERE ip = '45.2.0.9'");
check('ohne hp_list_changes: Bewertung schreibt trotzdem (Warnung)', str_contains($o, 'Warnung: hp_list_changes nicht geschrieben') AND (int)($s['listed'] ?? 0) === 1 AND str_contains($o, 'hp_scores:'), $o);
$r = api('GET', '/threat/feed?since=' . $c2, array('key' => K9));
check('ohne Tabelle: Feed 503', $r['code'] === 503 AND ($r['j']['code'] ?? '') === 'unavailable', code($r));
x("RENAME TABLE hp_list_changes_off TO hp_list_changes");

// ---------------------------------------------------------------- openapi
echo "openapi\n";
$raw = (string)file_get_contents("$WEB/api_v2_openapi.json");
$oa = json_decode($raw, true);
check('openapi: neue Pfade und Schemas', isset($oa['paths']['/threat/feed']['get'], $oa['paths']['/threat/passwords/range/{prefix}']['get'], $oa['components']['schemas']['ThreatFeed'],
	$oa['components']['schemas']['HoneypotReportSamples']['properties']['fingerprints'], $oa['components']['schemas']['ThreatStats']['properties']['top']['properties']['fingerprints']));

echo "\n$pass ok, $failed Fehler\n";
exit($failed === 0 ? 0 : 1);
