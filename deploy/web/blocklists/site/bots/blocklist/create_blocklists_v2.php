<?php
// IPv64.net Blocklisten-Generator v2 (Ersatz fuer create_blocklists.php)
//
// Liest die importierten Quelltabellen (blocklisten.db_name) und bl_countries_ips
// und schreibt alle Dateien unter blocklists/ neu. Dateinamen bleiben identisch,
// bestehende Links funktionieren weiter.
//
// Was gegenueber v1 anders ist:
//   - jede Zeile wird in ein sauberes Netz normalisiert (Hostbits weg, /32 bzw. /128 fuer Einzeladressen)
//   - Duplikate und enthaltene Netze werden in JEDER Datei entfernt (auch v6, auch "all")
//   - nicht routbare Bereiche (privat, CGNAT, Loopback, Link-Local, Multicast, Dokumentation) fliegen raus
//   - numerisch sortiert, damit Diffs und Vergleiche stabil sind
//   - MikroTik: IPv6 bekommt "/ipv6 firewall address-list", und am Anfang steht ein remove,
//     damit ein erneuter Import keine Duplikate erzeugt
//   - Dateien werden erst in eine Temp-Datei geschrieben und dann umbenannt (kein halber Download)
//   - last_updated wird nur gesetzt, wenn wirklich Dateien geschrieben wurden
//
// Aufruf:  php create_blocklists_v2.php              -> schreibt nach ../../blocklists/
//          php create_blocklists_v2.php --out=/tmp/x  -> schreibt zum Vergleichen nach /tmp/x (keine DB-Updates)
//          php create_blocklists_v2.php --dry         -> nur Statistik, schreibt nichts
//          php create_blocklists_v2.php --only=v64    -> nur die v64 Blocklist (Honeypot64, nach honeypot_score.php alle 30 min)
//          php create_blocklists_v2.php --v64-daily   -> Tagesstand der v64 Blocklist jetzt neu schreiben
include("/var/www/clients/client1/web58/web/dbconnect.php");
set_time_limit(900);
ini_set('memory_limit', '1024M');

$OUT = realpath(__DIR__."/../../blocklists");
// Live-Stand der v64 Blocklist: nicht oeffentlich (ISPConfig-Ordner private/ neben web/), ausgeliefert ueber blocklists/live.php
$LIVE = dirname(__DIR__, 3)."/private/blocklists_live";
$dry = false; $extern = false; $only_v64 = false; $v64_daily = false;
foreach($argv as $a) {
	if($a === '--dry') { $dry = true; }
	if($a === '--only=v64') { $only_v64 = true; }
	if($a === '--v64-daily') { $v64_daily = true; }
	if(str_starts_with($a, '--out=')) { $OUT = rtrim(substr($a, 6), '/'); $LIVE = $OUT."/live"; $extern = true; @mkdir($OUT, 0755, true); @mkdir($OUT."/countries", 0755, true); @mkdir($OUT."/user", 0755, true); }
}
if($OUT === false OR !is_dir($OUT)) { die("Ausgabeverzeichnis nicht gefunden\n"); }
echo ($dry ? "*** DRY RUN ***\n" : "Ausgabe: $OUT\n");

// ---------------------------------------------------------------
// Netz-Helfer (ohne externe Bibliothek, IPv4 und IPv6 ueber Binaerstrings)
// ---------------------------------------------------------------

/** "1.2.3.4", "1.2.3.0/24", "2001:db8::1", "2001:db8::/32" -> ['v'=>4|6,'bin'=>Netzadresse binaer,'len'=>Praefix] oder null */
function net_parse(string $s): ?array
{
	$s = trim($s);
	if($s === '') { return null; }
	$len = null;
	if(str_contains($s, '/')) { [$s, $l] = explode('/', $s, 2); if(!ctype_digit($l)) { return null; } $len = (int)$l; }
	$s = trim($s, " \t[]");
	if(filter_var($s, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { $v = 4; $bits = 32; }
	elseif(filter_var($s, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) { $v = 6; $bits = 128; }
	else { return null; }
	if($len === null) { $len = $bits; }
	if($len < 0 OR $len > $bits) { return null; }
	$bin = inet_pton($s);
	if($bin === false) { return null; }
	// Hostbits loeschen
	$bin = $bin & net_mask($len, strlen($bin));
	return ['v' => $v, 'bin' => $bin, 'len' => $len];
}

/** Maske als Binaerstring */
function net_mask(int $len, int $bytes): string
{
	$m = '';
	for($i = 0; $i < $bytes; $i++) {
		$b = max(0, min(8, $len - $i * 8));
		$m .= chr($b === 0 ? 0 : (0xFF << (8 - $b)) & 0xFF);
	}
	return $m;
}

/** Liegt $b innerhalb von $a (oder ist gleich)? */
function net_contains(array $a, array $b): bool
{
	if($a['v'] !== $b['v'] OR $b['len'] < $a['len']) { return false; }
	$m = net_mask($a['len'], strlen($a['bin']));
	return ($b['bin'] & $m) === $a['bin'];
}

function net_str(array $n): string
{
	return inet_ntop($n['bin']).'/'.$n['len'];
}

/** Sortieren (Version, Adresse, Praefix), Duplikate und enthaltene Netze entfernen */
function net_merge(array $nets): array
{
	usort($nets, function($a, $b) {
		return ($a['v'] <=> $b['v']) ?: (strcmp($a['bin'], $b['bin']) ?: ($a['len'] <=> $b['len']));
	});
	$out = []; $cur = null;
	foreach($nets as $n) {
		if($cur !== null AND net_contains($cur, $n)) { continue; }   // Duplikat oder enthalten
		$out[] = $n; $cur = $n;
	}
	return $out;
}

/** Nicht routbare Bereiche: Eintraege, die darin liegen oder sie umfassen, werden verworfen */
$BOGONS = array_map('net_parse', [
	'0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12',
	'192.0.0.0/24','192.0.2.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24',
	'224.0.0.0/4','240.0.0.0/4',
	'::/128','::1/128','::ffff:0:0/96','64:ff9b::/96','100::/64','2001:db8::/32','fc00::/7','fe80::/10','ff00::/8',
]);
function net_is_bogon(array $n): bool
{
	global $BOGONS;
	foreach($BOGONS as $b) { if(net_contains($b, $n) OR net_contains($n, $b)) { return true; } }
	return false;
}

/** Liste von Strings -> bereinigte, sortierte Netze. Gibt [nets, verworfen, bogons] zurueck. */
function net_clean(array $lines): array
{
	$nets = []; $bad = 0; $bog = 0;
	foreach($lines as $l) {
		$n = net_parse((string)$l);
		if($n === null) { $bad++; continue; }
		if(net_is_bogon($n)) { $bog++; continue; }
		$nets[] = $n;
	}
	return [net_merge($nets), $bad, $bog];
}

// ---------------------------------------------------------------
// Dateien schreiben (atomar)
// ---------------------------------------------------------------
function write_atomic(string $path, string $content): void
{
	global $dry;
	if($dry) { return; }
	$tmp = $path.".tmp";
	file_put_contents($tmp, $content);
	chmod($tmp, 0644);
	rename($tmp, $path);
}

function write_raw(string $path, array $nets): void
{
	$s = '';
	foreach($nets as $n) { $s .= net_str($n)."\n"; }
	write_atomic($path, $s);
}

function write_mikrotik(string $path, array $nets, int $v, string $listname = "IPv64-Blocklist"): void
{
	$pfad = ($v === 6) ? "/ipv6 firewall address-list" : "/ip firewall address-list";
	$s  = "# IPv64.net Blocklist - ".date("Y-m-d H:i")." UTC - https://ipv64.net/v64_blocklists\n";
	$s .= "$pfad\n";
	$s .= "remove [find list=$listname comment=\"IPv64 Blocklist\"]\n";
	foreach($nets as $n) { $s .= "add list=$listname address=".net_str($n)." comment=\"IPv64 Blocklist\"\n"; }
	write_atomic($path, $s);
}

function split46(array $nets): array
{
	$v4 = []; $v6 = [];
	foreach($nets as $n) { if($n['v'] === 4) { $v4[] = $n; } else { $v6[] = $n; } }
	return [$v4, $v6];
}

// ---------------------------------------------------------------
// index.json: alle Listen mit Anzahl, Stand, Quelle und Lizenz (fuer Node64 und andere Werkzeuge)
// ---------------------------------------------------------------
/** Dateinamen relativ zu base; $p = "" (Hauptlisten) oder "countries/" */
function index_files(string $p, string $f, bool $mikrotik): array
{
	$files = ['all' => $p."ipv64_blocklist_$f.txt", 'v4' => $p."ipv64_blocklist_v4_$f.txt", 'v6' => $p."ipv64_blocklist_v6_$f.txt"];
	if($mikrotik) { $files['mikrotik_v4'] = "v64_mikrotik_v4_$f.rsc"; $files['mikrotik_v6'] = "v64_mikrotik_v6_$f.rsc"; }
	return $files;
}

/** Eintrag fuer eine Quellliste; $v4/$v6 null = Liste diesmal nicht neu geschrieben, Zahlen aus der DB */
function index_list(array $bl, string $kat, bool $in_all, ?array $v4, ?array $v6): array
{
	$e = ['id' => $bl["file_name"], 'name' => $bl["name"], 'category' => $kat, 'in_all' => $in_all,
		'description' => $bl["description"] ?? '', 'source' => $bl["source"] ?? '', 'license' => $bl["license"] ?? ''];
	if($v4 === null) { $e['count'] = (int)$bl["ips"]; }
	else { $e['count'] = count($v4) + count($v6); $e['count_v4'] = count($v4); $e['count_v6'] = count($v6); }
	$t = strtotime((string)$bl["last_updated"]);
	$e['updated'] = $t ? date('c', $t) : null;
	$e['files'] = index_files('', $bl["file_name"], true);
	return $e;
}

function index_entry(string $id, string $name, string $p, array $v4, array $v6, bool $mikrotik): array
{
	return ['id' => $id, 'name' => $name, 'count' => count($v4) + count($v6), 'count_v4' => count($v4), 'count_v6' => count($v6),
		'updated' => date('c'), 'files' => index_files($p, $id, $mikrotik)];
}

// ---------------------------------------------------------------
// 0. v64 Blocklist (Honeypot64) aus hp_scores (bots/blocklist/honeypot_score.php), Hauptliste und Teillisten.
//    Live-Stand bei jedem Lauf nach $LIVE (nicht oeffentlich, Abruf mit Listen-Token ueber blocklists/live.php),
//    Tagesstand beim ersten Lauf eines UTC-Tages nach blocklists/ (frei fuer alle). Nicht in "all"/"all_notor".
// ---------------------------------------------------------------
const V64_LISTS = [
	'v64'          => ['v64 Blocklist (Honeypot64)', 'Attackers confirmed by several independent Honeypot64 sensors (logins, exploits, scans); research scanners not included'],
	'v64_ssh'      => ['v64 SSH/Telnet', 'Honeypot64: SSH and Telnet brute force'],
	'v64_web'      => ['v64 Web', 'Honeypot64: web attacks (login pages, exploits, scans)'],
	'v64_mail'     => ['v64 Mail', 'Honeypot64: mail login brute force'],
	'v64_rdp'      => ['v64 RDP', 'Honeypot64: RDP brute force'],
	'v64_scanner'  => ['v64 Scanner', 'Honeypot64: port scanners, probes and scanner user agents'],
	'v64_research' => ['v64 Research Scanner', 'Honeypot64: research scanners (Shodan, Censys and others), not part of the v64 Blocklist'],
];

/** index.json-Eintraege der v64-Listen aus den oeffentlichen Dateien (Tagesstand) */
function v64_index(string $OUT): array
{
	$e = [];
	foreach(V64_LISTS as $id => [$name, $desc]) {
		$p = "$OUT/ipv64_blocklist_$id.txt";
		if(!is_file($p)) { continue; }
		$c4 = is_file("$OUT/ipv64_blocklist_v4_$id.txt") ? count(file("$OUT/ipv64_blocklist_v4_$id.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) : 0;
		$c6 = is_file("$OUT/ipv64_blocklist_v6_$id.txt") ? count(file("$OUT/ipv64_blocklist_v6_$id.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) : 0;
		$e[] = ['id' => $id, 'name' => $name, 'category' => 'honeypot', 'in_all' => false, 'description' => $desc,
			'source' => 'https://ipv64.net/honeypot/', 'license' => 'CC BY 4.0 (IPv64.net Honeypot64), provided as is without warranty',
			'count' => $c4 + $c6, 'count_v4' => $c4, 'count_v6' => $c6, 'updated' => date('c', filemtime($p)),
			'files' => index_files('', $id, true), 'live' => true];
	}
	return $e;
}

$v64_index = [];
try {
	$v64 = array_fill_keys(array_keys(V64_LISTS), []);
	foreach($pdo->query("SELECT ip, lists FROM hp_scores WHERE listed = 1")->fetchAll(PDO::FETCH_ASSOC) as $r) {
		foreach(explode(',', (string)$r["lists"]) as $l) { $id = ($l === 'v64') ? 'v64' : "v64_$l"; if(isset($v64[$id])) { $v64[$id][] = $r["ip"]; } }
	}
	$daily = $v64_daily || !is_file("$OUT/ipv64_blocklist_v64.txt") || gmdate('Y-m-d', filemtime("$OUT/ipv64_blocklist_v64.txt")) !== gmdate('Y-m-d');
	if(!$dry AND !is_dir($LIVE)) { mkdir($LIVE, 0755, true); }
	foreach($v64 as $f => $ips) {
		[$nets, $bad, $bog] = net_clean($ips);
		[$v4, $v6] = split46($nets);
		foreach(($daily ? [$LIVE, $OUT] : [$LIVE]) as $dir) {
			write_raw("$dir/ipv64_blocklist_$f.txt", $nets);
			write_raw("$dir/ipv64_blocklist_v4_$f.txt", $v4);
			write_raw("$dir/ipv64_blocklist_v6_$f.txt", $v6);
			write_mikrotik("$dir/v64_mikrotik_v4_$f.rsc", $v4, 4, "IPv64-$f");
			write_mikrotik("$dir/v64_mikrotik_v6_$f.rsc", $v6, 6, "IPv64-$f");
		}
		printf("%-22s %6d Netze (v4 %6d, v6 %4d) live%s\n", $f, count($nets), count($v4), count($v6), $daily ? " + Tagesstand" : "");
	}
} catch(Throwable $e) {
	echo "v64 Blocklist: nicht geschrieben (".$e->getMessage().")\n";
}
$v64_index = v64_index($OUT);
$v64_live = ['base' => 'https://ipv64.net/blocklists/live/{token}/', 'categories' => ['honeypot'], 'token' => 'https://ipv64.net/honeypot/token.php',
	'info' => 'Live list for contributors and all plans except Standard; otherwise the daily list (header X-IPv64-List: live|daily)'];
if($only_v64) {
	// nur die honeypot-Eintraege in der vorhandenen index.json ersetzen
	$idx = is_file("$OUT/index.json") ? json_decode((string)file_get_contents("$OUT/index.json"), true) : null;
	if(is_array($idx) AND isset($idx['lists']) AND is_array($idx['lists'])) {
		$idx['lists'] = array_values(array_filter($idx['lists'], fn($e) => ($e['category'] ?? '') !== 'honeypot'));
		$idx['lists'] = array_merge($idx['lists'], $v64_index);
		$idx['live'] = $v64_live;
		write_atomic("$OUT/index.json", json_encode($idx, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n");
		echo "index.json: ".count($v64_index)." v64-Listen eingetragen\n";
	} else {
		echo "index.json fehlt oder ist ungueltig: v64-Listen kommen mit dem naechsten vollen Lauf hinein\n";
	}
	echo "Fertig (nur v64)".($dry ? " (nichts geschrieben)" : "")."\n";
	exit(0);
}

// ---------------------------------------------------------------
// 1. Einzelne Quelllisten
// ---------------------------------------------------------------
$alle = []; $alle_notor = []; // Gesamtliste mit und ohne Tor
$index = ['version' => 1, 'generated' => date('c'), 'info' => 'https://ipv64.net/v64_blocklists', 'base' => 'https://ipv64.net/blocklists/', 'lists' => [], 'combined' => [], 'countries' => [], 'regions' => []];
$statement = $pdo->prepare("SELECT * FROM blocklisten WHERE disabled = 0");
$statement->execute();
foreach($statement->fetchAll(PDO::FETCH_ASSOC) as $bl)
{
	if(!preg_match('/^[a-z0-9_]+$/', $bl["db_name"]) OR !preg_match('/^[a-z0-9_]+$/', $bl["file_name"])) { echo "SKIP ".$bl["name"].": unsauberer Tabellen-/Dateiname\n"; continue; }
	// Spalten aus blocklists_neue_listen.sql; fehlen sie noch, gilt das alte Verhalten (alles in "all", tor_* ohne notor)
	$kat = $bl["category"] ?? (str_starts_with($bl["file_name"], "tor_") ? "tor" : "attack");
	$in_all = (!isset($bl["in_all"]) || (int)$bl["in_all"] === 1);
	$rows = $pdo->query("SELECT ip FROM `".$bl["db_name"]."`")->fetchAll(PDO::FETCH_COLUMN);
	if(count($rows) === 0) {
		echo "SKIP ".$bl["name"].": Quelltabelle leer, Dateien bleiben wie sie sind\n";
		if(is_file("$OUT/ipv64_blocklist_".$bl["file_name"].".txt")) { $index['lists'][] = index_list($bl, $kat, $in_all, null, null); }
		continue;
	}
	[$nets, $bad, $bog] = net_clean($rows);
	[$v4, $v6] = split46($nets);
	if($in_all) { foreach($nets as $n) { $alle[] = $n; } }
	if($in_all AND $kat !== "tor") { foreach($nets as $n) { $alle_notor[] = $n; } }
	$index['lists'][] = index_list($bl, $kat, $in_all, $v4, $v6);
	printf("%-22s Quelle %6d -> %6d Netze (v4 %6d, v6 %4d) | ungueltig %d, nicht routbar %d\n", $bl["name"], count($rows), count($nets), count($v4), count($v6), $bad, $bog);

	$f = $bl["file_name"];
	write_raw("$OUT/ipv64_blocklist_$f.txt", $nets);
	write_raw("$OUT/ipv64_blocklist_v4_$f.txt", $v4);
	write_raw("$OUT/ipv64_blocklist_v6_$f.txt", $v6);
	write_mikrotik("$OUT/v64_mikrotik_v4_$f.rsc", $v4, 4, "IPv64-$f");
	write_mikrotik("$OUT/v64_mikrotik_v6_$f.rsc", $v6, 6, "IPv64-$f");
	if(!$dry AND !$extern) {
		$st = $pdo->prepare("UPDATE blocklisten set ips = :ips WHERE id = :id");
		$st->execute(['ips' => count($nets), 'id' => $bl["id"]]);
	}
}

// ---------------------------------------------------------------
// 2. Gesamtliste
// ---------------------------------------------------------------
$alle = net_merge($alle);
[$v4, $v6] = split46($alle);
printf("%-22s %6d Netze (v4 %6d, v6 %4d)\n", "ALL", count($alle), count($v4), count($v6));
write_raw("$OUT/ipv64_blocklist_all.txt", $alle);
write_raw("$OUT/ipv64_blocklist_v4_all.txt", $v4);
write_raw("$OUT/ipv64_blocklist_v6_all.txt", $v6);
write_mikrotik("$OUT/v64_mikrotik_v4_all.rsc", $v4, 4, "IPv64-all");
write_mikrotik("$OUT/v64_mikrotik_v6_all.rsc", $v6, 6, "IPv64-all");
$index['combined'][] = index_entry("all", "All lists (incl. Tor)", "", $v4, $v6, true);

// Gesamtliste ohne Tor (wer nur Angreifer sperren will, nicht alle Tor-Nutzer)
$alle_notor = net_merge($alle_notor);
[$v4, $v6] = split46($alle_notor);
printf("%-22s %6d Netze (v4 %6d, v6 %4d)\n", "ALL ohne Tor", count($alle_notor), count($v4), count($v6));
write_raw("$OUT/ipv64_blocklist_all_notor.txt", $alle_notor);
write_raw("$OUT/ipv64_blocklist_v4_all_notor.txt", $v4);
write_raw("$OUT/ipv64_blocklist_v6_all_notor.txt", $v6);
write_mikrotik("$OUT/v64_mikrotik_v4_all_notor.rsc", $v4, 4, "IPv64-all_notor");
write_mikrotik("$OUT/v64_mikrotik_v6_all_notor.rsc", $v6, 6, "IPv64-all_notor");
$index['combined'][] = index_entry("all_notor", "All lists without Tor", "", $v4, $v6, true);

// ---------------------------------------------------------------
// 3. Laender und Regionen
// ---------------------------------------------------------------
$regionen = [
	"europe"        => ['AL','AD','AT','BY','BE','BA','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IS','IE','IT','LV','LI','LT','LU','MK','MT','MD','MC','ME','NL','NO','PL','PT','RO','RU','SM','RS','SK','SI','ES','SE','CH','UA','GB','VA'],
	"africa"        => ['DZ','AO','BJ','BW','BF','BI','CM','CV','CF','TD','KM','CG','CD','DJ','EG','GQ','ER','ET','GA','GM','GH','GN','GW','CI','KE','LS','LR','LY','MG','MW','ML','MR','MU','MA','MZ','NA','NE','NG','RW','ST','SN','SC','SL','SO','ZA','SS','SD','SZ','TZ','TG','TN','UG','ZM','ZW'],
	"asia"          => ['AF','AM','AZ','BH','BD','BT','BN','KH','CN','GE','IN','ID','IR','IQ','IL','JP','JO','KZ','KW','KG','LA','LB','MY','MV','MN','MM','NP','KP','OM','PK','PS','PH','QA','SA','SG','KR','LK','SY','TW','TJ','TH','TL','TR','TM','AE','UZ','VN','YE','HK','MO'],
	"north_america" => ['AG','BS','BB','BZ','CA','CR','CU','DM','DO','SV','GD','GT','HT','HN','JM','MX','NI','PA','KN','LC','VC','TT','US'],
	"south_america" => ['AR','BO','BR','CL','CO','EC','GY','PY','PE','SR','UY','VE','GF','FK'],
	"oceania"       => ['AU','FJ','KI','MH','FM','NR','NZ','PW','PG','WS','SB','TO','TV','VU','NC','PF','GU','AS','MP','CK','NU','TK','WF'],
];
$region_nets = array_fill_keys(array_keys($regionen), []);

$st = $pdo->prepare("SELECT ip FROM bl_countries_ips WHERE country = :c");
$laender = $pdo->query("SELECT id, country, country_name, file_name FROM blocklisten_countries ORDER BY country")->fetchAll(PDO::FETCH_ASSOC);
$geschrieben = 0;
foreach($laender as $land)
{
	if(!preg_match('/^[A-Za-z0-9_]+$/', $land["file_name"])) { continue; }
	$st->execute(['c' => $land["country"]]);
	$rows = $st->fetchAll(PDO::FETCH_COLUMN);
	if(count($rows) === 0) { continue; }
	[$nets, $bad, $bog] = net_clean($rows);
	[$v4, $v6] = split46($nets);
	$f = $land["file_name"];
	write_raw("$OUT/countries/ipv64_blocklist_$f.txt", $nets);
	write_raw("$OUT/countries/ipv64_blocklist_v4_$f.txt", $v4);
	write_raw("$OUT/countries/ipv64_blocklist_v6_$f.txt", $v6);
	$index['countries'][] = ['country' => strtoupper($land["country"])] + index_entry($f, $land["country_name"], "countries/", $v4, $v6, false);
	$geschrieben++;
	foreach($regionen as $r => $cc) { if(in_array(strtoupper($land["country"]), $cc, true)) { foreach($nets as $n) { $region_nets[$r][] = $n; } } }
	if(!$dry AND !$extern) {
		$up = $pdo->prepare("UPDATE blocklisten_countries set ips = :ips, last_updated = NOW() WHERE id = :id");
		$up->execute(['ips' => count($nets), 'id' => $land["id"]]);
	}
}
echo "Laender: $geschrieben Dateisaetze geschrieben\n";

foreach($region_nets as $r => $nets)
{
	$nets = net_merge($nets);
	[$v4, $v6] = split46($nets);
	printf("%-22s %6d Netze (v4 %6d, v6 %4d)\n", "Region $r", count($nets), count($v4), count($v6));
	write_raw("$OUT/countries/ipv64_blocklist_$r.txt", $nets);
	write_raw("$OUT/countries/ipv64_blocklist_v4_$r.txt", $v4);
	write_raw("$OUT/countries/ipv64_blocklist_v6_$r.txt", $v6);
	$index['regions'][] = ['countries' => $regionen[$r]] + index_entry($r, ucwords(str_replace("_", " ", $r)), "countries/", $v4, $v6, false);
}

$index['lists'] = array_merge($index['lists'], $v64_index); // v64 Blocklist (Abschnitt 0), nicht in "all"
$index['live'] = $v64_live;
// Honeypot64 Text-Listen (bots/honeypot_lists.php) unter "data", nicht unter "lists" (dort waeren es IP-Listen)
if(is_file(__DIR__."/../honeypot_lists_index.php")) { require_once __DIR__."/../honeypot_lists_index.php"; $index['data'] = hpl_index_entries($OUT); }
write_atomic("$OUT/index.json", json_encode($index, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n");
echo "index.json: ".count($index['lists'])." Listen, ".count($index['countries'])." Laender\n";

echo "Fertig".($dry ? " (nichts geschrieben)" : "")."\n";
?>
