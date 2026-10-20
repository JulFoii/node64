<?php
/**
 * Honeypot64 H4 (DNSBL): Abgleich gegen einen echten, lokalen PowerDNS (nur Testnetz, Test-Key aus der Umgebung).
 * zone_update_test() macht dasselbe wie zone_update() aus dbconnect.php (PATCH auf die Zone, Erfolg nur bei 204).
 *   php pdns_test.php <honeypot_dnsbl.php> create|sync1|sync2
 * Die Abfragen per sdig prueft run_agentbox.sh.
 */
define('HPD_TEST', true);
require $argv[1];
$step = $argv[2] ?? '';
$api = getenv('PDNS_URL') . '/api/v1/servers/localhost/zones';
$key = (string)getenv('PDNS_KEY');

function pdns(string $method, string $url, string $body, string $key): array {
	$ch = curl_init($url);
	curl_setopt_array($ch, array(CURLOPT_CUSTOMREQUEST => $method, CURLOPT_POSTFIELDS => $body, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 15,
		CURLOPT_HTTPHEADER => array('X-API-Key: ' . $key, 'Content-Type: application/json')));
	$r = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
	return array($code, (string)$r);
}

function zone_update_test($post, $zone) {
	global $api, $key;
	[$code, $r] = pdns('PATCH', "$api/$zone", $post, $key);
	if($code != 204) { echo "PowerDNS-Fehler $code bei $zone: $r\n"; return false; }
	return true;
}

$db = new PDO('sqlite:/w/state.sqlite', null, null, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
$db->exec("CREATE TABLE IF NOT EXISTS hp_dnsbl (name TEXT PRIMARY KEY, ip TEXT NOT NULL, a TEXT NOT NULL, txt TEXT NOT NULL, synced_at TEXT NOT NULL)");
$dir = '/w/src';
@mkdir($dir);
function src(string $dir, array $lists): void {
	foreach(glob("$dir/*") as $f) { unlink($f); }
	foreach($lists as $l => $lines) { $f = "$dir/ipv64_blocklist_" . ($l === 'v64' ? 'v64' : "v64_$l") . '.txt'; file_put_contents($f, implode("\n", $lines) . "\n"); touch($f, time() - 3600); }
}

if($step === 'create') {
	// Zone wie mit --create-zone, aber Native (kein NOTIFY an echte Nameserver aus dem Testnetz)
	$z = json_decode(hpd_zone_setup()[0][1], true);
	$z['kind'] = 'Native';
	[$code, $r] = pdns('POST', $api, json_encode($z), $key);
	echo "Zone anlegen: HTTP $code\n";
	exit($code == 201 ? 0 : 1);
}

$big = array(); for($i = 0; $i < 1200; $i++) { $big[] = '11.0.' . intdiv($i, 250) . '.' . ($i % 250 + 1) . '/32'; }
if($step === 'sync1') {
	src($dir, array('v64' => array_merge(array('1.2.3.4/32', '5.6.7.8/32', '2a01:4f8::1/128'), $big), 'ssh' => array('1.2.3.4/32'), 'mail' => array('1.2.3.4/32'),
		'web' => array('2a01:4f8::1/128'), 'rdp' => array(), 'scanner' => array('5.6.7.8/32'), 'research' => array('9.9.9.9/32')));
} elseif($step === 'sync2') {
	src($dir, array('v64' => array_merge(array('1.2.3.4/32', '2a01:4f8::1/128', '4.4.4.4/32'), $big), 'ssh' => array('1.2.3.4/32'), 'mail' => array(),
		'web' => array('1.2.3.4/32', '2a01:4f8::1/128'), 'rdp' => array(), 'scanner' => array()));
} else { exit(2); }
$res = hpd_run($db, $dir, array(), 'zone_update_test', time());
echo hpd_log($res, array());
exit($res['ok'] ? 0 : 1);
