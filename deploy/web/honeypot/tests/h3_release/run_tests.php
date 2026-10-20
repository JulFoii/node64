<?php
/**
 * Pruefung von H3 IP-Auskunft + Freigaben in der Testumgebung hp3b-* (run_agentbox.sh): api_v2_threat.php,
 * honeypot/ip.php, honeypot/admin.php, bots/honeypot_release.php. Spricht Seite und API ueber den PHP-Builtin-Server an
 * (mit Sitzungs-Cookies), prueft Tabellen direkt und liest die Mails aus /w/mail.log (Stub von send_mail()).
 *
 *   HP3BTEST=1 php run_tests.php http://127.0.0.1:8080 /w/web
 */
if(php_sapi_name() !== 'cli' OR getenv('HP3BTEST') !== '1') { exit; }

$BASE = rtrim($argv[1] ?? 'http://127.0.0.1:8080', '/');
$WEB = $argv[2] ?? '/w/web';
const K1 = 'TestKeyAccountOne000000000000001';   // users.apikey, Account 1
const MAIL_LOG = '/w/mail.log';

$db = new PDO('mysql:host=hp3b-db;dbname=ipv64', 'root', 'hp3btest', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"));
$pass = 0; $failed = 0;
$JARS = array();

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . (is_string($info) ? substr($info, 0, 600) : json_encode($info, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . "\n"; }
}

/** HTTP-Anfrage. $o: ip (X-Forwarded-For), key, form (array), jar (Name der Cookie-Dose) */
function req(string $method, string $path, array $o = array()): array {
	global $BASE, $JARS;
	$h = array('X-Forwarded-For: ' . ($o['ip'] ?? '84.200.9.9'));
	if(isset($o['key'])) { $h[] = 'Authorization: Bearer ' . $o['key']; }
	$jar = $o['jar'] ?? null;
	if($jar !== null AND !empty($JARS[$jar])) { $h[] = 'Cookie: ' . implode('; ', array_map(fn($k, $v) => "$k=$v", array_keys($JARS[$jar]), $JARS[$jar])); }
	$body = '';
	if(isset($o['form'])) { $body = http_build_query($o['form']); $h[] = 'Content-Type: application/x-www-form-urlencoded'; }
	$ctx = stream_context_create(array('http' => array('method' => $method, 'header' => implode("\r\n", $h), 'content' => $body, 'ignore_errors' => true, 'timeout' => 60)));
	$raw = @file_get_contents($BASE . $path, false, $ctx);
	$code = 0; $hdr = array();
	foreach($http_response_header ?? array() as $l) {
		if(preg_match('#^HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
		elseif(stripos($l, 'Set-Cookie:') === 0 AND $jar !== null) { if(preg_match('/^Set-Cookie:\s*([^=]+)=([^;]*)/i', $l, $m)) { $JARS[$jar][$m[1]] = $m[2]; } }
		elseif(str_contains($l, ':')) { [$k, $v] = explode(':', $l, 2); $hdr[strtolower(trim($k))] = trim($v); }
	}
	return array('code' => $code, 'h' => $hdr, 'j' => json_decode((string)$raw, true), 'raw' => (string)$raw);
}
function api(string $ip, array $o = array()): array { return req('GET', '/api_v2.php/threat/ip/' . $ip, $o); }
function csrf(string $html): string { return preg_match('/name="csrf" value="([0-9a-f]{32})"/', $html, $m) ? $m[1] : ''; }
function one(string $sql, array $p = array()) { global $db; $st = $db->prepare($sql); $st->execute($p); return $st->fetch(PDO::FETCH_ASSOC); }
function all(string $sql, array $p = array()): array { global $db; $st = $db->prepare($sql); $st->execute($p); return $st->fetchAll(PDO::FETCH_ASSOC); }
function exec_sql(string $sql, array $p = array()): void { global $db; $db->prepare($sql)->execute($p); }
function code(array $r): string { return $r['code'] . ' ' . substr($r['raw'], 0, 400); }
function mails(): array { return is_file(MAIL_LOG) ? array_map(fn($l) => json_decode($l, true), array_filter(explode("\n", (string)file_get_contents(MAIL_LOG)))) : array(); }
function last_mail(): array { $m = mails(); return $m ? $m[count($m) - 1] : array(); }
function utc(int $off): string { return gmdate('Y-m-d H:i:s', time() + $off); }
function score(string $ip, int $listed, int $score = 80, int $acc = 3, string $kinds = 'ssh:bruteforce,generic:portscan', string $lists = 'ssh'): void {
	exec_sql("REPLACE INTO hp_scores (ip_bin, ip, family, score, accounts, sensors, events, kinds, lists, first_seen, last_seen, listed, listed_since, reason, updated_at)
		VALUES (?, ?, ?, ?, ?, 5, 120, ?, ?, ?, ?, ?, ?, 'threshold', UTC_TIMESTAMP())",
		array(inet_pton($ip), $ip, strlen(inet_pton($ip)) === 4 ? 4 : 6, $score, $acc, $kinds, $lists, utc(-3 * 86400), utc(-3600), $listed, $listed ? utc(-86400) : null));
}
/** Meldung (H2-Tabelle) von Account $u fuer $ip */
function touch_ip(string $ip, int $u, int $port, string $last, string $svc = 'ssh'): void {
	exec_sql("INSERT INTO hp_report_sources (day, report_ref, userid, sensor_id, ip, ip_bin, kind, service, port, `count`, first_seen, last_seen)
		VALUES (UTC_DATE(), 1, ?, 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', ?, ?, 'ssh:bruteforce', ?, ?, 3, ?, ?)", array($u, $ip, inet_pton($ip), $svc, $port, $last, $last));
}
function cron(string $args = ''): string { global $WEB; return (string)shell_exec('cd ' . escapeshellarg($WEB . '/bots') . ' && php honeypot_release.php ' . $args . ' 2>&1'); }

// ---------------------------------------------------------------- Testdaten
const L1 = '45.1.1.1';     // gelistet
const N1 = '45.1.1.2';     // gesehen, nicht gelistet
const U1 = '45.1.1.3';     // unbekannt
const R1 = '45.1.1.4';     // gelistet, aber freigegeben (Antrag)
const L6 = '2a0b:4d07::5'; // gelistet, IPv6
score(L1, 1); score(N1, 0, 30, 1, 'generic:probe', ''); score(R1, 1); score(L6, 1, 55, 2, 'http:exploit:traversal', 'web');
touch_ip(L1, 1, 22, utc(-7200)); touch_ip(L1, 3, 22, utc(-7000)); touch_ip(L1, 1, 2323, utc(-6000), 'telnet');   // 22 von 2 Accounts, 2323 nur von einem
touch_ip(N1, 1, 8443, utc(-6000), 'https');
exec_sql("INSERT INTO hp_allowlist (cidr, ip_start, ip_end, reason, source, `until`, created_at) VALUES (?, ?, ?, 'Antrag #0', 'request', ?, UTC_TIMESTAMP())",
	array(R1 . '/32', inet_pton(R1), inet_pton(R1), utc(10 * 86400)));
@unlink(MAIL_LOG);

// ---------------------------------------------------------------- SQL
echo "SQL\n";
$infra = all("SELECT cidr, source, LENGTH(ip_start) l, HEX(ip_start) s, HEX(ip_end) e FROM hp_allowlist WHERE source = 'infra' ORDER BY id");
check('Startwerte infra: 8 Eintraege, zweimal eingespielt ohne Doppel', count($infra) === 8, $infra);
check('IPv6 /64 als Bereich', $infra[1]['cidr'] === '2a01:4f8:1c18:5887::/64' AND $infra[1]['l'] == 16 AND $infra[1]['s'] === '2A0104F81C1858870000000000000000' AND $infra[1]['e'] === '2A0104F81C185887FFFFFFFFFFFFFFFF', $infra[1]);

// ---------------------------------------------------------------- API
echo "API GET /threat/ip/{ip}\n";
$r = api(L1, array('ip' => '84.200.10.1'));
$d = $r['j']['data'] ?? array();
check('gelistet 200', $r['code'] === 200 AND ($d['listed'] ?? null) === true AND ($d['status'] ?? '') === 'listed', code($r));
check('Score, Accounts, Arten, Listen', ($d['score'] ?? 0) === 80 AND ($d['accounts'] ?? 0) === 3 AND ($d['kinds'] ?? null) === array('ssh:bruteforce', 'generic:portscan') AND ($d['lists'] ?? null) === array('ssh'), $d);
check('Ports nur ab 2 Accounts (22 ja, 2323 nein)', ($d['ports'] ?? null) === array(array('service' => 'ssh', 'port' => 22)), $d['ports'] ?? null);
check('Sichtungen nur als Tag', preg_match('/^\d{4}-\d\d-\d\d$/', (string)($d['first_seen'] ?? '')) === 1 AND preg_match('/^\d{4}-\d\d-\d\d$/', (string)($d['last_seen'] ?? '')) === 1, $d);
check('Land/ASN null (nicht vorhanden)', array_key_exists('country', $d) AND $d['country'] === null AND array_key_exists('asn', $d) AND $d['asn'] === null, $d);
check('keine Sensor-IDs, Accounts, Zugangsdaten', !preg_match('/aaaaaaaa-bbbb|sensor|userid|"user"|pass|a@test/i', $r['raw']), $r['raw']);
check('Freigabe-Status none', ($d['release'] ?? null) === array('status' => 'none', 'protected_until' => null), $d['release'] ?? null);
check('RateLimit-Kopfzeilen', ($r['h']['ratelimit-limit'] ?? '') === '10', $r['h']);
$rn = api(N1, array('ip' => '84.200.10.1')); $ru = api(U1, array('ip' => '84.200.10.1'));
$dn = $rn['j']['data'] ?? array(); $du = $ru['j']['data'] ?? array();
check('nicht gelistet (mit Sichtungen): keine Details', $rn['code'] === 200 AND $dn['listed'] === false AND $dn['status'] === 'not_listed' AND $dn['score'] === null AND $dn['kinds'] === array() AND $dn['ports'] === array() AND $dn['accounts'] === null, $dn);
unset($dn['ip'], $dn['details'], $du['ip'], $du['details']);
check('gesehen und ungesehen nicht unterscheidbar', $dn === $du, array($dn, $du));
$d = api(R1, array('ip' => '84.200.10.1'))['j']['data'] ?? array();
check('freigegeben: released, nicht gelistet, geschuetzt bis', ($d['status'] ?? '') === 'released' AND $d['listed'] === false AND ($d['release']['status'] ?? '') === 'released' AND preg_match('/Z$/', (string)$d['release']['protected_until']) === 1 AND $d['score'] === null, $d);
$d = api('91.99.98.96', array('ip' => '84.200.10.1'))['j']['data'] ?? array();
check('Infrastruktur: allowlisted, dauerhaft', ($d['status'] ?? '') === 'allowlisted' AND $d['release']['protected_until'] === null, $d);
$d = api('2a01:4f8:c015:bca8::1234', array('ip' => '84.200.10.2'))['j']['data'] ?? array();
check('IPv6 im infra-/64: allowlisted', ($d['status'] ?? '') === 'allowlisted', $d);
$r = api('2A0B:4D07:0:0::5', array('ip' => '84.200.10.2'));
check('IPv6 gelistet, normalisiert', ($r['j']['data']['ip'] ?? '') === L6 AND $r['j']['data']['family'] === 6 AND $r['j']['data']['listed'] === true AND $r['j']['data']['lists'] === array('web'), code($r));
foreach(array('abc' => 422, '1.2.3' => 422, '45.1.1.1%2F24' => array(404, 422), '10.0.0.1' => 422, '192.0.2.1' => 422, '::ffff:45.1.1.1' => 422, 'fe80::1%25eth0' => 422, '::1' => 422) as $in => $want) {
	$r = api($in, array('ip' => '84.200.10.3'));
	check("Eingabe '$in' -> " . (is_array($want) ? implode('/', $want) : $want), in_array($r['code'], (array)$want, true), code($r));
}
check('nicht oeffentlich: Fehlercode not_public_ip', (api('10.0.0.1', array('ip' => '84.200.10.4'))['j']['code'] ?? '') === 'not_public_ip');
check('Netz: Fehlercode invalid_ip (?r=)', in_array(req('GET', '/api_v2.php?r=' . rawurlencode('/threat/ip/45.1.1.0/24'), array('ip' => '84.200.10.4'))['code'], array(404, 422), true));

echo "API Rate-Limit\n";
$codes = array();
for($i = 0; $i < 11; $i++) { $codes[] = api(U1, array('ip' => '84.200.20.1'))['code']; }
check('ohne Key: 10 erlaubt, 11. -> 429', count(array_filter(array_slice($codes, 0, 10), fn($c) => $c === 200)) === 10 AND $codes[10] === 429, $codes);
$r = api(U1, array('ip' => '84.200.20.1'));
check('429 mit Retry-After und rate_limited', $r['code'] === 429 AND (int)($r['h']['retry-after'] ?? 0) > 0 AND ($r['j']['code'] ?? '') === 'rate_limited', code($r));
check('andere Client-IP nicht betroffen', api(U1, array('ip' => '84.200.20.2'))['code'] === 200);
$codes = array();
for($i = 0; $i < 40; $i++) { $codes[] = api(U1, array('ip' => '84.200.20.1', 'key' => K1))['code']; }
check('mit Key von derselben IP: 40 erlaubt (eigener Topf je Account)', count(array_filter($codes, fn($c) => $c === 200)) === 40, array_count_values($codes));
$r = api(L1, array('ip' => '84.200.20.1', 'key' => K1));
check('mit Key: gleiche Auskunft', $r['code'] === 200 AND ($r['j']['data']['score'] ?? 0) === 80, code($r));
check('mit Key: RateLimit 120', ($r['h']['ratelimit-limit'] ?? '') === '120', $r['h']);
$r = api(L1, array('ip' => '84.200.20.3', 'key' => 'FalscherKey00000000000000000000x'));
check('ungueltiger Key -> 401', $r['code'] === 401, code($r));
for($i = 0; $i < 10; $i++) { req('GET', '/honeypot/ip.php?ip=' . U1, array('ip' => '84.200.20.4')); }
check('Seite und API teilen den Topf ohne Key', api(U1, array('ip' => '84.200.20.4'))['code'] === 429);

// ---------------------------------------------------------------- Seite
echo "Seite honeypot/ip.php\n";
$r = req('GET', '/honeypot/ip.php?ip=' . L1, array('ip' => '84.200.30.1', 'jar' => 'anon'));
check('gelistet: Status, Vertrauenswert, Laientext, Formular', $r['code'] === 200 AND str_contains($r['raw'], 'Gelistet') AND str_contains($r['raw'], '80 / 100')
	AND str_contains($r['raw'], 'Passwort-Raten per SSH') AND str_contains($r['raw'], 'Freigabe beantragen') AND csrf($r['raw']) !== '', substr($r['raw'], 0, 400));
check('Seite: Ports 22, nicht 2323; keine Sensor-ID', str_contains($r['raw'], '22 <small') AND !str_contains($r['raw'], '2323') AND !str_contains($r['raw'], 'aaaaaaaa'));
check('Seite: Hinweis auf Fehlalarme', str_contains($r['raw'], 'Fehlalarm'));
$r = req('GET', '/honeypot/ip.php?ip=' . L1 . '&lang=en', array('ip' => '84.200.30.1', 'jar' => 'anon'));
check('englisch', str_contains($r['raw'], 'Listed') AND str_contains($r['raw'], 'Request a release') AND str_contains($r['raw'], 'False positive'));
$r = req('GET', '/honeypot/ip.php?ip=' . N1, array('ip' => '84.200.30.1'));
check('nicht gelistet: kein Formular, keine Details', str_contains($r['raw'], 'Nicht gelistet') AND !str_contains($r['raw'], 'name="reason"') AND !str_contains($r['raw'], '8443') AND !str_contains($r['raw'], 'generic:probe'));
$r = req('GET', '/honeypot/ip.php?ip=' . R1, array('ip' => '84.200.30.1'));
check('freigegeben: geschuetzt bis', str_contains($r['raw'], 'Freigegeben') AND str_contains($r['raw'], 'geschützt bis') AND !str_contains($r['raw'], 'name="reason"'));
$r = req('GET', '/honeypot/ip.php?ip=' . rawurlencode('45.1.1.0/24'), array('ip' => '84.200.30.1'));
check('Netz abgelehnt', str_contains($r['raw'], 'keine Netze'));
$r = req('GET', '/honeypot/ip.php?ip=' . rawurlencode('<script>alert(1)</script>'), array('ip' => '84.200.30.1'));
check('Eingabe escaped', !str_contains($r['raw'], '<script>alert(1)') AND str_contains($r['raw'], '&lt;script&gt;'));

echo "Antrag anonym mit Bestaetigung\n";
$page = req('GET', '/honeypot/ip.php?ip=' . L1, array('ip' => '84.200.31.1', 'jar' => 'a1'));
$tok = csrf($page['raw']);
$form = array('action' => 'request', 'ip' => L1, 'reason' => 'Unser Buero-Anschluss, Kamera entfernt.', 'email' => 'anon1@test.invalid');
$r = req('POST', '/honeypot/ip.php?ip=' . L1, array('ip' => '84.200.31.1', 'jar' => 'a1', 'form' => $form + array('csrf' => 'falsch')));
check('ohne gueltiges CSRF-Token abgelehnt', str_contains($r['raw'], 'Sitzung ist abgelaufen') AND one("SELECT COUNT(*) c FROM hp_release_requests")['c'] == 0, substr($r['raw'], 0, 300));
$r = req('POST', '/honeypot/ip.php?ip=' . L1, array('ip' => '84.200.31.1', 'jar' => 'a1', 'form' => $form + array('csrf' => $tok, 'website' => 'http://spam')));
check('Bot-Feld ausgefuellt -> abgelehnt', one("SELECT COUNT(*) c FROM hp_release_requests")['c'] == 0);
$r = req('POST', '/honeypot/ip.php?ip=' . L1, array('ip' => '84.200.31.1', 'jar' => 'a1', 'form' => array_merge($form, array('csrf' => $tok, 'reason' => 'kurz'))));
check('Begruendung zu kurz -> abgelehnt', str_contains($r['raw'], '10 bis 2000') AND one("SELECT COUNT(*) c FROM hp_release_requests")['c'] == 0);
$r = req('POST', '/honeypot/ip.php?ip=' . L1, array('ip' => '84.200.31.1', 'jar' => 'a1', 'form' => array_merge($form, array('csrf' => $tok, 'email' => 'keine-mail'))));
check('ungueltige E-Mail -> abgelehnt', str_contains($r['raw'], 'gültige E-Mail') AND one("SELECT COUNT(*) c FROM hp_release_requests")['c'] == 0);
$r = req('POST', '/honeypot/ip.php?ip=' . N1, array('ip' => '84.200.31.1', 'jar' => 'a1', 'form' => array_merge($form, array('csrf' => $tok, 'ip' => N1))));
check('nicht gelistete IP -> kein Antrag', str_contains($r['raw'], 'nicht gelistet') AND one("SELECT COUNT(*) c FROM hp_release_requests")['c'] == 0);
$r = req('POST', '/honeypot/ip.php?ip=' . L1, array('ip' => '84.200.31.1', 'jar' => 'a1', 'form' => $form + array('csrf' => $tok)));
$row = one("SELECT * FROM hp_release_requests WHERE ip = ?", array(L1));
check('Antrag angelegt, unbestaetigt', $row AND $row['status'] === 'open' AND $row['confirmed_at'] === null AND $row['userid'] === null AND $row['email'] === 'anon1@test.invalid'
	AND strlen($row['confirm_hash']) === 64 AND strlen($row['client_hash']) === 64 AND $row['ip_bin'] === inet_pton(L1), $row);
check('Seite: Hinweis auf Mail', str_contains($r['raw'], 'E-Mail geschickt'));
check('keine Absender-IP im Klartext gespeichert', !str_contains(json_encode(array_map('strval', array_values($row ?: array())), JSON_INVALID_UTF8_SUBSTITUTE), '84.200.31.1'));
$m = mails();
$link = (count($m) === 1 AND preg_match('#https://ipv64\.net/honeypot/ip\.php\?request=([A-Za-z0-9]{32})&confirm=([A-Za-z0-9]{32})#', $m[0]['text'], $mm)) ? $mm : null;
check('Bestaetigungs-Mail mit Link', $link !== null AND $m[0]['to'] === 'anon1@test.invalid' AND $link[1] === $row['token'], $m);
$d = api(L1, array('ip' => '84.200.31.2'))['j']['data'] ?? array();
check('unbestaetigt: Auskunft noch ohne Antrag', ($d['release']['status'] ?? '') === 'none', $d['release'] ?? null);
$r = req('GET', '/honeypot/ip.php?request=' . $link[1] . '&confirm=' . $link[2], array('ip' => '84.200.31.3', 'jar' => 'a2'));
check('Link zeigt Knopf (GET bestaetigt nicht)', str_contains($r['raw'], 'Antrag jetzt bestätigen') AND one("SELECT confirmed_at FROM hp_release_requests WHERE id = ?", array($row['id']))['confirmed_at'] === null);
$t2 = csrf($r['raw']);
$r = req('POST', '/honeypot/ip.php?request=' . $link[1], array('ip' => '84.200.31.3', 'jar' => 'a2', 'form' => array('action' => 'confirm', 'csrf' => $t2, 'request' => $link[1], 'confirm' => str_repeat('x', 32))));
check('falsches Bestaetigungs-Token -> abgelehnt', str_contains($r['raw'], 'ungültig oder abgelaufen') AND one("SELECT confirmed_at FROM hp_release_requests WHERE id = ?", array($row['id']))['confirmed_at'] === null);
$r = req('POST', '/honeypot/ip.php?request=' . $link[1], array('ip' => '84.200.31.3', 'jar' => 'a2', 'form' => array('action' => 'confirm', 'csrf' => $t2, 'request' => $link[1], 'confirm' => $link[2])));
$row = one("SELECT * FROM hp_release_requests WHERE id = ?", array($row['id']));
check('bestaetigt', $row['confirmed_at'] !== null AND $row['confirm_hash'] === '' AND str_contains($r['raw'], 'bestätigt'), $row);
check('Statusseite: offen, automatisch', str_contains($r['raw'], 'Wird automatisch geprüft') AND str_contains($r['raw'], L1));
$d = api(L1, array('ip' => '84.200.31.2'))['j']['data'] ?? array();
check('Auskunft: in_review', ($d['release']['status'] ?? '') === 'in_review' AND $d['listed'] === true, $d['release'] ?? null);
$r = req('GET', '/honeypot/ip.php?ip=' . L1, array('ip' => '84.200.31.4', 'jar' => 'a3'));
check('Seite: laufender Antrag, kein zweites Formular', str_contains($r['raw'], 'Antrag läuft bereits') AND !str_contains($r['raw'], 'name="reason"'));
$r = req('GET', '/honeypot/ip.php?request=' . str_repeat('Z', 32), array('ip' => '84.200.31.4'));
check('unbekannter Statuslink', str_contains($r['raw'], 'Antrag nicht gefunden'));

echo "Antrag eingeloggt\n";
score('45.1.2.1', 1);
$page = req('GET', '/honeypot/ip.php?ip=45.1.2.1&as=1', array('ip' => '84.200.32.1', 'jar' => 'u1'));
check('eingeloggt: kein E-Mail-Feld', !str_contains($page['raw'], 'name="email"') AND str_contains($page['raw'], 'Du bist angemeldet'));
$r = req('POST', '/honeypot/ip.php?ip=45.1.2.1&as=1', array('ip' => '84.200.32.1', 'jar' => 'u1', 'form' => array('action' => 'request', 'csrf' => csrf($page['raw']), 'ip' => '45.1.2.1', 'reason' => 'Mein DynDNS-Anschluss zu Hause.')));
$row = one("SELECT * FROM hp_release_requests WHERE ip = '45.1.2.1'");
check('eingeloggt: sofort bestaetigt, ohne E-Mail, ohne Mail', $row AND (int)$row['userid'] === 1 AND $row['email'] === '' AND $row['confirmed_at'] !== null AND $row['confirm_hash'] === '' AND count(mails()) === 1, $row);
check('eingeloggt: Statuslink auf der Seite', str_contains($r['raw'], 'request=' . $row['token']));

echo "Drossel\n";
foreach(array('45.1.2.2', '45.1.2.3', '45.1.2.4', '45.1.2.5', '45.1.2.6', '45.1.2.7', '45.1.2.8') as $x) { score($x, 1); }
$jarN = 0;
$ask = function(string $ip, string $client, string $email) use (&$jarN) {
	$j = 'd' . (++$jarN);
	$p = req('GET', '/honeypot/ip.php?ip=' . $ip, array('ip' => $client, 'jar' => $j));
	return req('POST', '/honeypot/ip.php?ip=' . $ip, array('ip' => $client, 'jar' => $j, 'form' => array('action' => 'request', 'csrf' => csrf($p['raw']), 'ip' => $ip, 'reason' => 'Bitte freigeben, Fehlalarm.', 'email' => $email)));
};
$ask('45.1.2.2', '84.200.33.1', 'x1@test.invalid'); $ask('45.1.2.3', '84.200.33.1', 'x2@test.invalid'); $ask('45.1.2.4', '84.200.33.1', 'x3@test.invalid');
$r = $ask('45.1.2.5', '84.200.33.1', 'x4@test.invalid');
check('je Absender-IP: 4. Antrag am Tag abgelehnt', str_contains($r['raw'], 'höchstens 3 Anträge') AND one("SELECT id FROM hp_release_requests WHERE ip = '45.1.2.5'") === false, substr($r['raw'], 0, 200));
$ask('45.1.2.5', '84.200.34.1', 'y@test.invalid'); $ask('45.1.2.6', '84.200.34.2', 'y@test.invalid'); $ask('45.1.2.7', '84.200.34.3', 'y@test.invalid');
$r = $ask('45.1.2.8', '84.200.34.4', 'y@test.invalid');
check('je E-Mail: 4. Antrag am Tag abgelehnt (andere Absender-IPs)', str_contains($r['raw'], 'höchstens 3 Anträge') AND one("SELECT id FROM hp_release_requests WHERE ip = '45.1.2.8'") === false);
exec_sql("UPDATE hp_release_requests SET created_at = created_at - INTERVAL 25 HOUR WHERE email = 'y@test.invalid'");
$r = $ask('45.1.2.8', '84.200.34.4', 'y@test.invalid');
check('nach 24 h wieder moeglich', one("SELECT id FROM hp_release_requests WHERE ip = '45.1.2.8'") !== false, substr($r['raw'], 0, 200));
// Drossel-Antraege nicht in die Cron-Pruefung mitnehmen
exec_sql("DELETE FROM hp_release_requests WHERE ip LIKE '45.1.2.%' AND ip != '45.1.2.1'");

// ---------------------------------------------------------------- Cron
echo "Cron bots/honeypot_release.php\n";
/** bestaetigten Antrag direkt anlegen */
function make_req(string $ip, string $confirmed, ?int $u = null, string $email = '', string $status = 'open', ?string $decided = null): int {
	global $db;
	if($email === '') { $email = 'r' . bin2hex(random_bytes(4)) . '@test.invalid'; } // je Antrag eigener Absender
	exec_sql("INSERT INTO hp_release_requests (ip, ip_bin, userid, email, reason, status, created_at, confirmed_at, decided_at, token) VALUES (?, ?, ?, ?, 'Test', ?, ?, ?, ?, ?)",
		array($ip, inet_pton($ip), $u, $u ? '' : $email, $status, $confirmed, $confirmed, $decided, bin2hex(random_bytes(16))));
	return (int)$db->lastInsertId();
}
foreach(array('45.1.3.1', '45.1.3.2', '45.1.3.3', '52.95.1.1', '45.1.3.5', '2600:1f00::7') as $x) { score($x, 1); }
$A = (int)one("SELECT id FROM hp_release_requests WHERE ip = '45.1.2.1'")['id'];       // eingeloggt (Account 1), ruhig
exec_sql("UPDATE hp_release_requests SET confirmed_at = ?, created_at = ? WHERE id = ?", array(utc(-25 * 3600), utc(-25 * 3600), $A));
$B = make_req('45.1.3.2', utc(-25 * 3600), null, 'b1@test.invalid'); touch_ip('45.1.3.2', 3, 22, utc(-3600));     // greift weiter an
make_req('45.1.3.3', utc(-40 * 86400), null, 'old@test.invalid', 'rejected', utc(-39 * 86400));
$C = make_req('45.1.3.3', utc(-25 * 3600));                                                // mehrere Antraege
$D = make_req('52.95.1.1', utc(-25 * 3600));                                               // Provider-Netz (Cloud-Liste)
$D6 = make_req('2600:1f00::7', utc(-25 * 3600));                                           // Provider-Netz IPv6
$E = make_req('45.1.3.5', utc(-2 * 3600));                                                 // erst 2 h
$F = make_req('45.1.3.1', utc(-30 * 3600)); touch_ip('45.1.3.1', 1, 22, utc(-31 * 3600));  // Beruehrung nur VOR der Bestaetigung -> frei
$Sx = array(); foreach(array('45.1.4.1', '45.1.4.2', '45.1.4.3', '45.1.4.4') as $x) { $Sx[] = make_req($x, utc(-20 * 86400), null, 'many@test.invalid', 'released', utc(-19 * 86400)); }
$S = make_req('45.1.4.5', utc(-25 * 3600), null, 'many@test.invalid');                   // Absender mit 5 IPs in 30 Tagen
exec_sql("INSERT INTO hp_release_requests (ip, ip_bin, email, reason, created_at, token, confirm_hash) VALUES ('45.1.5.1', ?, 'u@test.invalid', 'x', ?, ?, ?)",
	array(inet_pton('45.1.5.1'), utc(-49 * 3600), bin2hex(random_bytes(16)), str_repeat('a', 64)));   // unbestaetigt, 49 h alt
exec_sql("UPDATE hp_release_requests SET client_hash = ? WHERE id = ?", array(str_repeat('b', 64), $E));
exec_sql("UPDATE hp_release_requests SET created_at = ? WHERE id = ?", array(utc(-3 * 86400), $E));
exec_sql("INSERT INTO hp_allowlist (cidr, ip_start, ip_end, reason, source, `until`, created_at) VALUES ('45.1.9.9/32', ?, ?, 'alt', 'request', ?, UTC_TIMESTAMP())",
	array(inet_pton('45.1.9.9'), inet_pton('45.1.9.9'), utc(-8 * 86400)));
$mails0 = count(mails());
$before = all("SELECT id, status FROM hp_release_requests ORDER BY id");
$out = cron('--dry');
echo preg_replace('/^/m', '        ', trim($out)), "\n";
check('--dry: nichts geaendert, keine Mail', all("SELECT id, status FROM hp_release_requests ORDER BY id") === $before AND count(mails()) === $mails0 AND str_contains($out, 'NUR ANZEIGEN'));
$out = cron();
echo preg_replace('/^/m', '        ', trim($out)), "\n";
$st = fn(int $id) => one("SELECT * FROM hp_release_requests WHERE id = ?", array($id));
$a = $st($A);
check('24 h ruhig -> released, protected_until +30 Tage', $a['status'] === 'released' AND $a['decided_at'] !== null AND $a['decided_by'] === null
	AND abs(strtotime($a['protected_until'] . ' UTC') - (time() + 30 * 86400)) < 300, $a);
$al = one("SELECT cidr, source, `until`, HEX(ip_start) s, HEX(ip_end) e FROM hp_allowlist WHERE cidr = '45.1.2.1/32'");
check('hp_allowlist: source request, until = protected_until', $al AND $al['source'] === 'request' AND $al['until'] === $a['protected_until'] AND $al['s'] === '2D010201' AND $al['e'] === '2D010201', $al);
$f = $st($F);
check('Beruehrung vor der Bestaetigung zaehlt nicht -> released', $f['status'] === 'released', $f);
$d = api('45.1.2.1', array('ip' => '84.200.40.1'))['j']['data'] ?? array();
check('Auskunft sofort: freigegeben, geschuetzt bis', ($d['status'] ?? '') === 'released' AND $d['listed'] === false AND ($d['release']['protected_until'] ?? '') === gmdate('Y-m-d\TH:i:s\Z', strtotime($a['protected_until'] . ' UTC')), $d);
$m = array_values(array_filter(mails(), fn($x) => $x['to'] === 'a@test.invalid'));
check('Bescheid an den eingeloggten Antragsteller (Mail aus users)', count($m) === 1 AND str_contains($m[0]['subject'], 'freigegeben'), $m);
$b = $st($B);
check('greift weiter an -> escalated, Grund in note', $b['status'] === 'escalated' AND str_contains($b['note'], 'greift weiter an') AND $b['decided_at'] === null, $b);
$adm = array_values(array_filter(mails(), fn($x) => $x['to'] === 'admin@test.invalid'));
check('Mail-Stub an Admin aufgerufen (je eskaliertem Antrag)', count($adm) === 5 AND str_contains(implode(' ', array_column($adm, 'text')), '45.1.3.2') AND str_contains($adm[0]['text'], 'admin.php'), array_column($adm, 'subject'));
check('mehrere Antraege -> escalated', $st($C)['status'] === 'escalated' AND str_contains($st($C)['note'], 'mehrere Antraege'), $st($C));
check('Provider-Netz (IPv4) -> escalated', $st($D)['status'] === 'escalated' AND str_contains($st($D)['note'], 'Provider-Netz: Amazon AWS'), $st($D));
check('Provider-Netz (IPv6) -> escalated', $st($D6)['status'] === 'escalated', $st($D6));
check('viele IPs vom selben Absender -> escalated', $st($S)['status'] === 'escalated' AND str_contains($st($S)['note'], '5 verschiedene IPs'), $st($S));
check('erst 2 h -> bleibt open', $st($E)['status'] === 'open' AND $st($E)['decided_at'] === null);
check('keine Freigabe fuer eskalierte', one("SELECT COUNT(*) c FROM hp_allowlist WHERE cidr IN ('45.1.3.2/32', '45.1.3.3/32', '52.95.1.1/32')")['c'] == 0);
check('unbestaetigt > 48 h geloescht', one("SELECT id FROM hp_release_requests WHERE ip = '45.1.5.1'") === false);
check('client_hash nach 2 Tagen geleert', $st($E)['client_hash'] === '');
check('abgelaufene request-Freigabe geloescht, infra bleibt', one("SELECT id FROM hp_allowlist WHERE cidr = '45.1.9.9/32'") === false AND one("SELECT COUNT(*) c FROM hp_allowlist WHERE source = 'infra'")['c'] == 8);
$mails1 = count(mails());
$out2 = cron();
check('zweiter Lauf: keine neuen Mails, nichts geaendert', count(mails()) === $mails1 AND str_contains($out2, '0 freigegeben, 0 eskaliert'), $out2);

// ---------------------------------------------------------------- Admin
echo "Admin honeypot/admin.php\n";
$r = req('GET', '/honeypot/admin.php', array('ip' => '84.200.50.1', 'jar' => 'n0'));
check('nicht angemeldet: kein Zugriff', str_contains($r['raw'], 'Kein Zugriff') AND !str_contains($r['raw'], '45.1.3.2') AND csrf($r['raw']) === '');
$r = req('GET', '/honeypot/admin.php?as=1', array('ip' => '84.200.50.1', 'jar' => 'n1'));
check('kein Admin: kein Zugriff', str_contains($r['raw'], 'Kein Zugriff') AND !str_contains($r['raw'], '45.1.3.2'));
$r = req('GET', '/honeypot/admin.php?as=2', array('ip' => '84.200.50.1', 'jar' => 'adm'));
$ta = csrf($r['raw']);
check('Admin: eskalierte Antraege mit Pruefangaben', str_contains($r['raw'], '45.1.3.2') AND str_contains($r['raw'], 'eskaliert') AND str_contains($r['raw'], 'Amazon AWS') AND $ta !== '', substr($r['raw'], 0, 300));
// Nicht-Admin mit gueltigem Token aus eigener Sitzung darf nichts aendern
$p1 = req('GET', '/honeypot/ip.php?ip=' . L1 . '&as=1', array('ip' => '84.200.50.2', 'jar' => 'n1'));
req('POST', '/honeypot/admin.php?as=1', array('ip' => '84.200.50.2', 'jar' => 'n1', 'form' => array('action' => 'release', 'csrf' => csrf($p1['raw']), 'id' => $B, 'days' => 30)));
check('Nicht-Admin kann nicht freigeben', $st($B)['status'] === 'escalated');
req('POST', '/honeypot/admin.php?as=2', array('ip' => '84.200.50.1', 'jar' => 'adm', 'form' => array('action' => 'release', 'csrf' => 'falsch', 'id' => $B, 'days' => 30)));
check('Admin ohne CSRF-Token: nichts geaendert', $st($B)['status'] === 'escalated');
$mails2 = count(mails());
$r = req('POST', '/honeypot/admin.php?as=2', array('ip' => '84.200.50.1', 'jar' => 'adm', 'form' => array('action' => 'release', 'csrf' => $ta, 'id' => $B, 'days' => 30, 'note' => 'geprueft')));
$b = $st($B);
check('Admin gibt frei: released, decided_by, allowlist', $b['status'] === 'released' AND (int)$b['decided_by'] === 2 AND str_contains($b['note'], 'Freigabe von Hand (30 Tage): geprueft')
	AND one("SELECT source FROM hp_allowlist WHERE cidr = '45.1.3.2/32'")['source'] === 'request', $b);
check('Bescheid-Mail an anonymen Antragsteller', count(mails()) === $mails2 + 1 AND last_mail()['to'] === 'b1@test.invalid');
$r = req('POST', '/honeypot/admin.php?as=2', array('ip' => '84.200.50.1', 'jar' => 'adm', 'form' => array('action' => 'release', 'csrf' => $ta, 'id' => $D, 'days' => 0)));
check('dauerhaft freigeben -> manual ohne until', $st($D)['protected_until'] === null AND one("SELECT source, `until` FROM hp_allowlist WHERE cidr = '52.95.1.1/32'") === array('source' => 'manual', 'until' => null));
check('Auskunft dauerhaft: allowlisted', (api('52.95.1.1', array('ip' => '84.200.50.3'))['j']['data']['status'] ?? '') === 'allowlisted');
$r = req('POST', '/honeypot/admin.php?as=2', array('ip' => '84.200.50.1', 'jar' => 'adm', 'form' => array('action' => 'reject', 'csrf' => $ta, 'id' => $C, 'note' => 'weiter aktiv')));
check('Admin lehnt ab: rejected', $st($C)['status'] === 'rejected' AND (int)$st($C)['decided_by'] === 2 AND str_contains(last_mail()['subject'] ?? '', 'abgelehnt'), $st($C));
$d = api('45.1.3.3', array('ip' => '84.200.50.3'))['j']['data'] ?? array();
check('Auskunft nach Ablehnung: gelistet, release rejected', $d['listed'] === true AND $d['release']['status'] === 'rejected', $d);
$r = req('POST', '/honeypot/admin.php?as=2', array('ip' => '84.200.50.1', 'jar' => 'adm', 'form' => array('action' => 'release', 'csrf' => $ta, 'id' => $C, 'days' => 30)));
check('schon entschieden -> keine zweite Entscheidung', $st($C)['status'] === 'rejected' AND str_contains($r['raw'], 'schon entschieden'));
$r = req('POST', '/honeypot/admin.php?as=2', array('ip' => '84.200.50.1', 'jar' => 'adm', 'form' => array('action' => 'allow_add', 'csrf' => $ta, 'cidr' => '45.2.77.9/16', 'reason' => 'Partner Test', 'source' => 'manual', 'days' => 0)));
$al = one("SELECT id, cidr, HEX(ip_start) s, HEX(ip_end) e, `until`, created_by FROM hp_allowlist WHERE reason = 'Partner Test'");
check('Freigabe anlegen: Netz normalisiert, Bereich', $al AND $al['cidr'] === '45.2.0.0/16' AND $al['s'] === '2D020000' AND $al['e'] === '2D02FFFF' AND $al['until'] === null AND (int)$al['created_by'] === 2, $al);
check('Auskunft im Netz: allowlisted', (api('45.2.3.4', array('ip' => '84.200.50.3'))['j']['data']['status'] ?? '') === 'allowlisted');
req('POST', '/honeypot/admin.php?as=2', array('ip' => '84.200.50.1', 'jar' => 'adm', 'form' => array('action' => 'allow_add', 'csrf' => $ta, 'cidr' => '2001:db8:aa::1/48', 'reason' => 'v6 Test', 'source' => 'cdn', 'days' => 10)));
$al6 = one("SELECT cidr, HEX(ip_start) s, HEX(ip_end) e, `until` FROM hp_allowlist WHERE reason = 'v6 Test'");
check('IPv6-Netz mit Frist', $al6 AND $al6['cidr'] === '2001:db8:aa::/48' AND $al6['s'] === '20010DB800AA00000000000000000000' AND $al6['e'] === '20010DB800AAFFFFFFFFFFFFFFFFFFFF' AND $al6['until'] !== null, $al6);
foreach(array('0.0.0.0/0' => 'zu groß', 'kein-netz' => 'Ungültiges Netz', '45.3.0.0/16|request' => 'Ungültige Quelle') as $in => $want) {
	[$c, $src] = array_pad(explode('|', $in), 2, 'manual');
	$r = req('POST', '/honeypot/admin.php?as=2', array('ip' => '84.200.50.1', 'jar' => 'adm', 'form' => array('action' => 'allow_add', 'csrf' => $ta, 'cidr' => $c, 'reason' => 'x', 'source' => $src, 'days' => 0)));
	check("Freigabe '$c' ($src) abgelehnt", str_contains($r['raw'], $want) AND one("SELECT COUNT(*) c FROM hp_allowlist WHERE reason = 'x'")['c'] == 0);
}
$r = req('POST', '/honeypot/admin.php?as=2', array('ip' => '84.200.50.1', 'jar' => 'adm', 'form' => array('action' => 'allow_del', 'csrf' => $ta, 'id' => $al['id'])));
check('Freigabe loeschen', one("SELECT id FROM hp_allowlist WHERE id = ?", array($al['id'])) === false AND str_contains($r['raw'], 'gelöscht'));
check('Auskunft danach: nicht gelistet', (api('45.2.3.4', array('ip' => '84.200.50.3'))['j']['data']['status'] ?? '') === 'not_listed');

echo "\n$pass ok, $failed Fehler\n";
exit($failed > 0 ? 1 : 0);
